//! Profile write operations to understand latency breakdown.

use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::time::Instant;

mod common;

#[test]
fn profile_write_latency() {
    // Use unique paths to avoid conflicts with parallel test runs
    let (data_dir, mount_dir) = common::unique_paths("profile-write");

    // Clean up any stale state
    common::cleanup(&data_dir, &mount_dir);

    fs::create_dir_all(&data_dir).unwrap();

    // Create test file
    let test_file = data_dir.join("test.dat");
    File::create(&test_file)
        .unwrap()
        .write_all(&vec![0u8; 4096])
        .unwrap();

    // Mount with tracing enabled (single reader for cleaner traces)
    let (fuse, collector) = common::FuseMount::with_tracing(&data_dir, &mount_dir, 1);

    // Warmup
    let fuse_file = fuse.mount_path().join("test.dat");
    let data = vec![0x42u8; 4096];
    {
        let mut f = OpenOptions::new().write(true).open(&fuse_file).unwrap();
        for _ in 0..10 {
            f.seek(SeekFrom::Start(0)).unwrap();
            f.write_all(&data).unwrap();
        }
    }
    collector.clear();

    // Timed run
    let iterations = 1000;
    let mut f = OpenOptions::new().write(true).open(&fuse_file).unwrap();

    let start = Instant::now();
    for _ in 0..iterations {
        f.seek(SeekFrom::Start(0)).unwrap();
        f.write_all(&data).unwrap();
    }
    let elapsed = start.elapsed();

    eprintln!(
        "\n{} writes of 4KB in {:?} ({:.2}µs/write)\n",
        iterations,
        elapsed,
        elapsed.as_micros() as f64 / iterations as f64
    );

    // Print telemetry breakdown
    collector.print_summary();

    // Clean up after test completes
    drop(fuse);
    common::cleanup(&data_dir, &mount_dir);
}
