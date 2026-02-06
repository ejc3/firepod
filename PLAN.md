# Phase 3 Review Fixes — Implementation Plan

## Overview

Fix remaining high-severity issues from REVIEW.md that weren't addressed in Wave 1 (PR #268, 8 fixes) or Wave 2 (PR #268, 10 fixes). This wave focuses on the 6 remaining high-severity items plus 2 critical medium-severity items.

## Commit 1: Add Forget/BatchForget to fuse-pipe protocol

**Issue #1 — No FUSE forget() forwarding, unbounded inode/fd leak**

The FUSE kernel sends `forget` and `batch_forget` to decrement inode reference counts (nlookup). Without forwarding these, fuse-backend-rs `PassthroughFs` accumulates inode references that are never freed — each tracked inode holds a `/proc/self/fd/N` reference. For long-running VMs with filesystem churn, this leaks memory and file descriptors without bound.

### Changes

1. **`fuse-pipe/src/protocol/request.rs`** — Add two new VolumeRequest variants:
   ```rust
   Forget { ino: u64, nlookup: u64 },
   BatchForget { inodes: Vec<(u64, u64)> },  // Vec of (ino, nlookup)
   ```
   Update `op_name()` and `is_read_op()` (forget is not a read, but it's not a write either — it's lifecycle management, so leave it out of is_read_op).

2. **`fuse-pipe/src/client/fuse.rs`** — Implement `forget()` and `batch_forget()` on FuseClient:
   - `forget()`: Send `VolumeRequest::Forget` as fire-and-forget (no response expected — the FUSE kernel doesn't wait for a reply to forget).
   - `batch_forget()`: Send `VolumeRequest::BatchForget` as fire-and-forget.
   - These are the only FUSE operations where no reply is sent. Need a `send_request_no_reply()` method on FuseMultiplexer.

3. **`fuse-pipe/src/client/multiplexer.rs`** — Add `send_request_no_reply()`:
   - Serialize and send the request but don't register a response channel.
   - The server must NOT send a response for forget operations.

4. **`fuse-pipe/src/server/handler.rs`** — Add `forget()` and `batch_forget()` to FilesystemHandler trait:
   - Default implementations are no-ops (return nothing — these don't produce responses).
   - Dispatch from `handle_request()`.

5. **`fuse-pipe/src/server/pipelined.rs`** — Handle forget specially:
   - After dispatching forget/batch_forget, do NOT send a response back through the pipe.

6. **`fuse-pipe/src/server/passthrough.rs`** — Forward to fuse-backend-rs:
   - `forget()`: Call `self.inner.forget(ctx, ino, nlookup)`
   - `batch_forget()`: Call `self.inner.batch_forget(ctx, inodes)`

## Commit 2: Fix multiplexer hang on deserialization failure

**Issue #2 — Multiplexer hangs forever on single-request deserialization failure**

Two places where deserialization failures cause permanent hangs:

### Changes

1. **`fuse-pipe/src/server/pipelined.rs:373`** — When server-side deserialization fails:
   - Currently: `continue` (silently drops request, no response sent).
   - Fix: Try to extract the `unique` ID from the raw bytes (already done for logging). Send an EIO error response using that unique ID so the client unblocks. If unique ID can't be extracted, log error and continue (best-effort).

2. **`fuse-pipe/src/client/multiplexer.rs:356`** — When client-side response deserialization fails:
   - Currently: silent `if let Ok(...)` — failed responses are dropped.
   - Fix: Log the deserialization error. Try to extract `unique` from raw bytes and send EIO to the waiting channel.

## Commit 3: Forward RENAME flags through the protocol

**Issue #3 — RENAME_NOREPLACE / RENAME_EXCHANGE silently dropped**

### Changes

1. **`fuse-pipe/src/protocol/request.rs`** — Add `flags: u32` field to `VolumeRequest::Rename`.

2. **`fuse-pipe/src/client/fuse.rs:700`** — Pass `flags.bits()` instead of discarding `_flags`.

3. **`fuse-pipe/src/server/handler.rs`** — Add `flags: u32` parameter to `rename()` method. Update dispatch.

4. **`fuse-pipe/src/server/passthrough.rs`** — Pass flags through to `self.inner.rename()`. The fuse-backend-rs passthrough already supports rename flags via `libc::renameat2()`.

## Commit 4: Use bytes instead of String for filenames in protocol

**Issue #4 — Non-UTF-8 filenames silently corrupted**

`name.to_string_lossy().to_string()` replaces non-UTF-8 bytes with U+FFFD. POSIX allows any byte sequence except NUL and `/`.

### Changes

1. **`fuse-pipe/src/protocol/request.rs`** — Change all `name: String` fields to `name: Vec<u8>` in:
   - Lookup, Mkdir, Mknod, Rmdir, Create, Unlink, Rename (name + newname), Symlink (name + target), Link (newname), Setxattr (name), Getxattr (name), Removexattr (name)

2. **`fuse-pipe/src/client/fuse.rs`** — Convert `OsStr` to `Vec<u8>` using `name.as_bytes()` (on Unix, OsStr is just bytes). Replace all `name.to_string_lossy().to_string()` calls.

3. **`fuse-pipe/src/server/handler.rs`** — Change all `_name: &str` parameters to `_name: &[u8]` in trait methods.

4. **`fuse-pipe/src/server/passthrough.rs`** — Convert `&[u8]` to `CStr`/`CString` for fuse-backend-rs calls. The passthrough fs already uses CStr internally.

**Note:** This is a wire-format breaking change. Since there's no protocol versioning (#25), any running VMs would need restart. This is acceptable per the project's NO LEGACY policy.

## Commit 5: Make seccomp configurable (default enabled)

**Issue #5 — --no-seccomp unconditionally disables Firecracker sandboxing**

### Changes

1. **`src/firecracker/vm.rs:197`** — Remove the hardcoded `--no-seccomp`. Only add it if an explicit `FCVM_NO_SECCOMP=1` env var is set or a CLI flag is passed:
   ```rust
   if std::env::var("FCVM_NO_SECCOMP").map_or(false, |v| v == "1") {
       cmd.arg("--no-seccomp");
   }
   ```

2. **Test compatibility**: Verify existing tests pass with seccomp enabled. Firecracker's default seccomp filter allows all operations fcvm uses. If tests fail, the seccomp filter needs extending (add to env in test setup), not disabling globally.

## Commit 6: Add RAII wrapper for VsockListener in fc-agent

**Issue #6 — fc-agent raw fd management without RAII, fd leaks on error paths**

### Changes

1. **`fc-agent/src/main.rs`** — Add `Drop` impl for `VsockListener`:
   ```rust
   impl Drop for VsockListener {
       fn drop(&mut self) {
           unsafe { libc::close(self.fd); }
       }
   }
   ```

2. Remove all manual `libc::close(listener_fd)` calls in error paths of `run_exec_server_with_ready_signal()` — the Drop impl handles cleanup.

3. When transferring ownership to `AsyncFd`, use `std::mem::forget()` on the VsockListener to prevent double-close (AsyncFd takes ownership of the fd via `AsRawFd`). Or better: implement `IntoRawFd` and have AsyncFd consume it.

## Commit 7: Fix multiplexer client-side deserialization logging

**Issue #2 addendum** — The client reader loop at multiplexer.rs:356 silently drops failed deserializations with no logging.

This is folded into Commit 2 above.

## Commit 8 (bonus, medium severity): Fix e2fsck exit code handling

**Issue #30** — Already partially addressed in Wave 1, but verify the current state.

## Order of implementation

1. Commit 2 (multiplexer hang fix) — smallest, most impactful for reliability
2. Commit 3 (rename flags) — small, self-contained
3. Commit 5 (seccomp) — small, security improvement
4. Commit 6 (VsockListener RAII) — small, prevents fd leaks
5. Commit 1 (forget forwarding) — larger but critical for long-running VMs
6. Commit 4 (bytes for filenames) — largest change, touches many files
