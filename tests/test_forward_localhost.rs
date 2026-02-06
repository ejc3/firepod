//! Test --forward-localhost flag: VM localhost reaches host services.

#![cfg(feature = "privileged-tests")]

mod common;

use anyhow::{Context, Result};
use std::net::TcpListener;

/// Test that --forward-localhost makes VM's 127.0.0.1 reach host services.
#[tokio::test]
async fn test_forward_localhost() -> Result<()> {
    println!("\nTest --forward-localhost");
    println!("========================");

    // Start a TCP server on host 127.0.0.1
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    println!("  Host server on 127.0.0.1:{}", port);

    // Accept in background
    let accept_handle = tokio::task::spawn_blocking(move || {
        listener.set_nonblocking(false).ok();
        if let Ok((mut conn, _)) = listener.accept() {
            use std::io::Write;
            let _ = conn.write_all(b"HELLO\n");
        }
    });

    let (vm_name, _, _, _) = common::unique_names("fwd-localhost");

    let port_str = port.to_string();
    let (_, pid) = common::spawn_fcvm(&[
        "podman",
        "run",
        "--name",
        &vm_name,
        "--forward-localhost",
        &port_str,
        "--no-snapshot",
        common::TEST_IMAGE,
    ])
    .await
    .context("spawning fcvm")?;

    common::poll_health_by_pid(pid, 300).await?;
    println!("  VM healthy");

    // From inside VM, connect to localhost:port — should reach host
    let result = common::exec_in_vm(
        pid,
        &[
            "sh",
            "-c",
            &format!("nc -w5 127.0.0.1 {} || echo FAILED", port),
        ],
    )
    .await?;

    println!("  Result: {}", result.trim());
    assert!(
        result.contains("HELLO"),
        "VM localhost should reach host with --forward-localhost (got: {})",
        result.trim()
    );

    common::kill_process(pid).await;
    accept_handle.abort();
    println!("✅ FORWARD LOCALHOST TEST PASSED!");
    Ok(())
}
