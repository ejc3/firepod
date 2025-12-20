//! Build script for fcvm - embeds fc-agent binary as an asset.
//!
//! fc-agent must be built first with:
//!   cargo build --release -p fc-agent --target <arch>-unknown-linux-musl

use std::path::Path;

fn main() {
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");

    // fc-agent binary location (copied by Makefile after musl build)
    let fc_agent_src = Path::new("target/release/fc-agent");

    if fc_agent_src.exists() {
        let dest = Path::new(&out_dir).join("fc-agent");
        std::fs::copy(fc_agent_src, &dest).expect("Failed to copy fc-agent to OUT_DIR");
        println!("cargo:rerun-if-changed=target/release/fc-agent");
    } else {
        // For first build or clean build, create empty placeholder
        // The Makefile ensures fc-agent is built before fcvm
        let dest = Path::new(&out_dir).join("fc-agent");
        std::fs::write(&dest, b"").expect("Failed to create placeholder");
        println!("cargo:warning=fc-agent not found, using empty placeholder");
    }
}
