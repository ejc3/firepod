//! Multi-reader FUSE mount helpers.
//!
//! Note: Multi-reader support via FUSE_DEV_IOC_CLONE requires a custom fuser fork.
//! When using standard fuser from crates.io, multi-reader requests will fall back
//! to single reader mode.

use super::{FuseClient, Multiplexer};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

#[cfg(target_os = "linux")]
use crate::transport::VsockTransport;

/// Mount a FUSE filesystem using a Unix socket connection.
///
/// This connects to a server at `socket_path` and mounts a FUSE filesystem
/// at `mount_point`. The function blocks until the filesystem is unmounted.
pub fn mount<P: AsRef<Path>>(socket_path: &str, mount_point: P) -> anyhow::Result<()> {
    mount_with_options(socket_path, mount_point, 1, 0)
}

/// Mount a FUSE filesystem with multiple reader threads.
///
/// This creates multiple FUSE reader threads using FUSE_DEV_IOC_CLONE,
/// allowing parallel processing of FUSE requests.
pub fn mount_with_readers<P: AsRef<Path>>(
    socket_path: &str,
    mount_point: P,
    num_readers: usize,
) -> anyhow::Result<()> {
    mount_with_options(socket_path, mount_point, num_readers, 0)
}

/// Mount a FUSE filesystem with full configuration.
///
/// # Arguments
///
/// * `socket_path` - Path to the Unix socket where the server is listening
/// * `mount_point` - Directory where the FUSE filesystem will be mounted
/// * `num_readers` - Number of FUSE reader threads (1-8 recommended)
///   Note: Multi-reader support requires custom fuser fork. Standard fuser uses single reader.
/// * `trace_rate` - Trace every Nth request (0 = disabled)
pub fn mount_with_options<P: AsRef<Path>>(
    socket_path: &str,
    mount_point: P,
    num_readers: usize,
    trace_rate: u64,
) -> anyhow::Result<()> {
    info!(target: "fuse-pipe::client", socket_path, num_readers, "connecting");

    // Multi-reader requires custom fuser fork with FUSE_DEV_IOC_CLONE support
    // Standard fuser only supports single reader
    if num_readers > 1 {
        warn!(target: "fuse-pipe::client",
              requested = num_readers,
              "multi-reader requires custom fuser fork, falling back to single reader");
    }

    // Create socket connection
    let socket = UnixStream::connect(socket_path)?;
    socket.set_read_timeout(Some(Duration::from_secs(30)))?;
    socket.set_write_timeout(Some(Duration::from_secs(30)))?;
    debug!(target: "fuse-pipe::client", "connected to server");

    // Create multiplexer for request/response handling
    // Use single reader since standard fuser doesn't support multi-reader
    let mux = Multiplexer::with_trace_rate(socket, 1, trace_rate);
    debug!(target: "fuse-pipe::client", "multiplexer started (single reader)");

    // Mount options:
    // - AllowOther: Allow non-root users to access the mount (requires user_allow_other in /etc/fuse.conf or running as root)
    // Note: We do NOT use DefaultPermissions because we implement our own permission checks
    // in the passthrough handler to properly enforce POSIX ownership rules (chmod/chown/utimes)
    let options = vec![
        fuser::MountOption::FSName("fuse-pipe".to_string()),
        fuser::MountOption::AllowOther,
    ];

    let fs = FuseClient::new(Arc::clone(&mux), 0);
    let mut session = fuser::Session::new(fs, mount_point.as_ref(), &options)?;
    info!(target: "fuse-pipe::client", mount_point = ?mount_point.as_ref(), "mounted");

    if let Err(e) = session.run() {
        error!(target: "fuse-pipe::client", reader_id = 0, error = %e, "reader error");
    }
    debug!(target: "fuse-pipe::client", "FUSE session exited");
    Ok(())
}

/// Mount a FUSE filesystem using a vsock connection.
///
/// This connects to a server via vsock (CID + port) and mounts a FUSE filesystem
/// at `mount_point`. The function blocks until the filesystem is unmounted.
///
/// # Arguments
///
/// * `cid` - The context ID (use `HOST_CID` to connect to host from guest)
/// * `port` - The vsock port number
/// * `mount_point` - Directory where the FUSE filesystem will be mounted
///
/// # Example
///
/// ```rust,ignore
/// use fuse_pipe::client::mount_vsock;
/// use fuse_pipe::transport::HOST_CID;
///
/// // Connect from guest to host on port 5000
/// mount_vsock(HOST_CID, 5000, "/mnt/volume")?;
/// ```
#[cfg(target_os = "linux")]
pub fn mount_vsock<P: AsRef<Path>>(cid: u32, port: u32, mount_point: P) -> anyhow::Result<()> {
    mount_vsock_with_options(cid, port, mount_point, 1, 0)
}

/// Mount a FUSE filesystem via vsock with multiple reader threads.
#[cfg(target_os = "linux")]
pub fn mount_vsock_with_readers<P: AsRef<Path>>(
    cid: u32,
    port: u32,
    mount_point: P,
    num_readers: usize,
) -> anyhow::Result<()> {
    mount_vsock_with_options(cid, port, mount_point, num_readers, 0)
}

/// Mount a FUSE filesystem via vsock with full configuration.
///
/// # Arguments
///
/// * `cid` - The context ID (use `HOST_CID` to connect to host from guest)
/// * `port` - The vsock port number
/// * `mount_point` - Directory where the FUSE filesystem will be mounted
/// * `num_readers` - Number of FUSE reader threads (1-8 recommended)
///   Note: Multi-reader support requires custom fuser fork. Standard fuser uses single reader.
/// * `trace_rate` - Trace every Nth request (0 = disabled)
#[cfg(target_os = "linux")]
pub fn mount_vsock_with_options<P: AsRef<Path>>(
    cid: u32,
    port: u32,
    mount_point: P,
    num_readers: usize,
    trace_rate: u64,
) -> anyhow::Result<()> {
    info!(target: "fuse-pipe::client", cid, port, num_readers, "connecting via vsock");

    // Multi-reader requires custom fuser fork with FUSE_DEV_IOC_CLONE support
    // Standard fuser only supports single reader
    if num_readers > 1 {
        warn!(target: "fuse-pipe::client",
              requested = num_readers,
              "multi-reader requires custom fuser fork, falling back to single reader");
    }

    // Create vsock connection
    let transport = VsockTransport::connect(cid, port)?;
    debug!(target: "fuse-pipe::client", cid, port, "connected to server via vsock");

    // VsockTransport wraps a UnixStream internally, extract it for the multiplexer
    // This is safe because VsockTransport is just a UnixStream created from a vsock fd
    use std::os::unix::io::{AsRawFd, FromRawFd};
    let socket = unsafe { UnixStream::from_raw_fd(libc::dup(transport.as_raw_fd())) };
    socket.set_read_timeout(Some(Duration::from_secs(30)))?;
    socket.set_write_timeout(Some(Duration::from_secs(30)))?;

    // Create multiplexer for request/response handling
    // Use single reader since standard fuser doesn't support multi-reader
    let mux = Multiplexer::with_trace_rate(socket, 1, trace_rate);
    debug!(target: "fuse-pipe::client", "multiplexer started (single reader)");

    // Mount options:
    // - AllowOther: Allow non-root users to access the mount (requires user_allow_other in /etc/fuse.conf or running as root)
    // Note: We do NOT use DefaultPermissions because we implement our own permission checks
    // in the passthrough handler to properly enforce POSIX ownership rules (chmod/chown/utimes)
    let options = vec![
        fuser::MountOption::FSName("fuse-pipe".to_string()),
        fuser::MountOption::AllowOther,
    ];

    let fs = FuseClient::new(Arc::clone(&mux), 0);
    let mut session = fuser::Session::new(fs, mount_point.as_ref(), &options)?;
    info!(target: "fuse-pipe::client", mount_point = ?mount_point.as_ref(), "mounted via vsock");

    if let Err(e) = session.run() {
        error!(target: "fuse-pipe::client", reader_id = 0, error = %e, "reader error");
    }
    debug!(target: "fuse-pipe::client", "FUSE session exited");
    Ok(())
}
