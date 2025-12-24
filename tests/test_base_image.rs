//! Tests for --base-image and --cache-dir flag functionality
//!
//! Run all tests:
//!   cargo test --release --test test_base_image
//!
//! Run integration test only (creates VM, takes longer):
//!   cargo test --release --test test_base_image integration
//!
//! Override system cache location (for CI or custom setups):
//!   FCVM_SYSTEM_CACHE=/path/to/cache cargo test --release --test test_base_image

use std::path::PathBuf;
use std::process::Command;

mod common;

/// Get the system cache directory (from env or default)
fn system_cache_dir() -> PathBuf {
    std::env::var("FCVM_SYSTEM_CACHE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/mnt/fcvm-btrfs/cache"))
}

/// Get the system kernels directory (from env or default)
fn system_kernels_dir() -> PathBuf {
    std::env::var("FCVM_SYSTEM_KERNELS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/mnt/fcvm-btrfs/kernels"))
}

// ============================================================================
// Fast CLI tests
// ============================================================================

#[test]
fn test_base_image_flag_appears_in_help() {
    let fcvm_path = common::find_fcvm_binary().expect("fcvm binary not found");

    let output = Command::new(&fcvm_path)
        .arg("--help")
        .output()
        .expect("failed to run fcvm");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--base-image"),
        "--base-image flag should appear in help output"
    );
    assert!(
        stdout.contains("Base cloud image URL or local path"),
        "--base-image description should appear in help"
    );
}

#[test]
fn test_cache_dir_flag_appears_in_help() {
    let fcvm_path = common::find_fcvm_binary().expect("fcvm binary not found");

    let output = Command::new(&fcvm_path)
        .arg("--help")
        .output()
        .expect("failed to run fcvm");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--cache-dir"),
        "--cache-dir flag should appear in help output"
    );
    assert!(
        stdout.contains("Cache directory"),
        "--cache-dir description should appear in help"
    );
}

#[test]
fn test_base_image_flag_parsed_correctly() {
    let fcvm_path = common::find_fcvm_binary().expect("fcvm binary not found");

    // Test that the flag is parsed without consuming other arguments
    let output = Command::new(&fcvm_path)
        .args([
            "--base-image",
            "/some/path.qcow2",
            "podman",
            "run",
            "--name",
            "test",
            "nginx:alpine",
            "--help",
        ])
        .output()
        .expect("failed to run fcvm");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("required arguments were not provided"),
        "--base-image should not consume following arguments. stderr: {}",
        stderr
    );
}

#[test]
fn test_base_image_nonexistent_path_fails() {
    // Use a temporary user-writable directory
    let test_dir = PathBuf::from("/tmp/fcvm-test-base-image-error");
    let _ = std::fs::remove_dir_all(&test_dir);
    std::fs::create_dir_all(&test_dir).expect("failed to create test dir");

    let fcvm_path = common::find_fcvm_binary().expect("fcvm binary not found");

    // Use --base-dir to a user-writable location, --base-image to nonexistent path
    let output = Command::new(&fcvm_path)
        .args([
            "--base-dir",
            test_dir.to_str().unwrap(),
            "--base-image",
            "/nonexistent/path/to/image.qcow2",
            "podman",
            "run",
            "--name",
            "test-nonexistent",
            "--network",
            "rootless",
            "nginx:alpine",
        ])
        .output()
        .expect("failed to run fcvm");

    // Cleanup
    let _ = std::fs::remove_dir_all(&test_dir);

    // Should fail because the path doesn't exist
    assert!(
        !output.status.success(),
        "fcvm should fail with nonexistent --base-image path"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--base-image path does not exist")
            || stderr.contains("path does not exist"),
        "error message should mention path does not exist. stderr: {}",
        stderr
    );
}

// ============================================================================
// Integration test (creates actual VM)
// ============================================================================

/// Integration test that verifies --base-image and --cache-dir work with a real image.
/// Uses rootless networking, no sudo required.
/// Verifies that fc-agent starts (proves rootfs was created correctly).
#[tokio::test]
async fn integration_base_image_with_cached_image() {
    use std::time::Duration;
    use tokio::time::sleep;
    use tokio::io::{AsyncBufReadExt, BufReader};

    let cache_dir = system_cache_dir();
    let kernels_dir = system_kernels_dir();

    // Find cached image (arm64 or amd64)
    let cached_image = if cache_dir.join("ubuntu-24.04-arm64.img").exists() {
        cache_dir.join("ubuntu-24.04-arm64.img")
    } else if cache_dir.join("ubuntu-24.04-amd64.img").exists() {
        cache_dir.join("ubuntu-24.04-amd64.img")
    } else {
        panic!(
            "Cached Ubuntu image not found in {}. Run a VM first to cache the image, \
             or set FCVM_SYSTEM_CACHE to point to your cache directory.",
            cache_dir.display()
        );
    };

    // Use a separate test directory (user-writable)
    let test_dir = PathBuf::from("/tmp/fcvm-test-base-image");
    let _ = std::fs::remove_dir_all(&test_dir);
    std::fs::create_dir_all(&test_dir).expect("failed to create test dir");

    // Copy the kernel from system location (needed for VM boot)
    let kernel_dir = test_dir.join("kernels");
    let source_kernel = kernels_dir.join("vmlinux.bin");
    std::fs::create_dir_all(&kernel_dir).expect("failed to create kernel dir");
    std::fs::copy(&source_kernel, kernel_dir.join("vmlinux.bin"))
        .unwrap_or_else(|_| panic!(
            "kernel not found at {}. Set FCVM_SYSTEM_KERNELS to point to your kernels directory.",
            source_kernel.display()
        ));

    // Start VM with --base-dir (user-writable) and --base-image (cached image)
    let fcvm_path = common::find_fcvm_binary().expect("fcvm binary not found");
    let mut child = tokio::process::Command::new(&fcvm_path)
        .args([
            "--base-dir",
            test_dir.to_str().unwrap(),
            "--cache-dir",
            cache_dir.to_str().unwrap(),
            "--base-image",
            cached_image.to_str().unwrap(),
            "podman",
            "run",
            "--name",
            "base-image-test",
            "--network",
            "rootless", // No sudo required
            common::TEST_IMAGE,
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn fcvm");

    let pid = child.id().expect("failed to get child PID");
    let stderr = child.stderr.take().unwrap();

    // Read stderr looking for key success markers
    let reader = BufReader::new(stderr);
    let mut lines = reader.lines();
    let mut saw_fc_agent_start = false;
    let mut saw_container_started = false;

    let timeout = Duration::from_secs(120);
    let start = std::time::Instant::now();

    while start.elapsed() < timeout {
        tokio::select! {
            line = lines.next_line() => {
                match line {
                    Ok(Some(text)) => {
                        eprintln!("[test] {}", text);
                        if text.contains("[fc-agent] starting") {
                            saw_fc_agent_start = true;
                        }
                        if text.contains("container started") {
                            saw_container_started = true;
                            break; // Success!
                        }
                    }
                    Ok(None) => break, // EOF
                    Err(_) => break,
                }
            }
            _ = sleep(Duration::from_secs(1)) => {}
        }
    }

    // Cleanup
    common::kill_process(pid).await;
    sleep(Duration::from_secs(2)).await;
    let _ = std::fs::remove_dir_all(&test_dir);

    // Assert after cleanup
    // fc-agent starting proves the rootfs is valid, container starting proves the full pipeline works
    assert!(saw_fc_agent_start, "fc-agent should start (proves rootfs works)");
    assert!(saw_container_started, "container should start");
}
