//! Profile direct client-server without kernel FUSE overhead.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::thread;
use std::time::Instant;

mod common;

#[test]
fn profile_direct_latency() {
    // Use unique path to avoid conflicts with parallel test runs
    let socket_path = PathBuf::from(format!("/tmp/profile-direct-{}.sock", std::process::id()));
    let socket_str = socket_path.to_str().unwrap();
    let _ = fs::remove_file(&socket_path);

    // Start server
    let listener = UnixListener::bind(socket_str).expect("bind Unix socket");

    thread::spawn(move || {
        let (mut conn, _) = listener.accept().expect("accept connection");
        let mut len_buf = [0u8; 4];
        let mut req_buf = vec![0u8; 8192];

        loop {
            // Read length
            if conn.read_exact(&mut len_buf).is_err() {
                break;
            }
            let len = u32::from_be_bytes(len_buf) as usize;

            // Read body
            conn.read_exact(&mut req_buf[..len])
                .expect("read request body");

            // Deserialize (simulated)
            let _unique: u64 = u64::from_le_bytes(req_buf[..8].try_into().unwrap());

            // Write response (just 4 bytes)
            conn.write_all(&[0u8; 4]).expect("write response");
        }
    });

    // Give server time to start
    thread::sleep(std::time::Duration::from_millis(50));

    // Client
    let mut client = UnixStream::connect(socket_str).expect("connect to server");

    // Prepare 4KB write request
    let data = vec![0x42u8; 4096];
    let mut request = Vec::with_capacity(4140);
    request.extend_from_slice(&1u64.to_le_bytes()); // unique
    request.extend_from_slice(&data);

    let iterations = 10000;

    // Warmup
    for _ in 0..100 {
        let len = (request.len() as u32).to_be_bytes();
        client.write_all(&len).unwrap();
        client.write_all(&request).unwrap();
        let mut resp = [0u8; 4];
        client.read_exact(&mut resp).unwrap();
    }

    // Timed run
    let start = Instant::now();
    for _ in 0..iterations {
        let len = (request.len() as u32).to_be_bytes();
        client.write_all(&len).unwrap();
        client.write_all(&request).unwrap();
        let mut resp = [0u8; 4];
        client.read_exact(&mut resp).unwrap();
    }
    let elapsed = start.elapsed();

    eprintln!(
        "\nDirect socket (no FUSE): {} iterations, {:.2}µs/op\n",
        iterations,
        elapsed.as_micros() as f64 / iterations as f64
    );

    let _ = fs::remove_file(&socket_path);
}
