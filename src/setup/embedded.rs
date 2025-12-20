//! Embedded fc-agent binary asset.
//!
//! The fc-agent binary is built as a static musl binary and embedded into
//! the fcvm binary at compile time. This ensures:
//! - Single binary distribution (no separate fc-agent file needed)
//! - Works on any Linux 2.6.39+ (static musl, no glibc dependency)
//! - Per-arch builds naturally match (aarch64 fcvm embeds aarch64 fc-agent)

use std::io::Write;
use std::path::PathBuf;

/// Embedded fc-agent binary (built for same arch as fcvm).
/// Built with: cargo build -p fc-agent --target <arch>-unknown-linux-musl --release
pub const FC_AGENT_BINARY: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/fc-agent"));

/// Write the embedded fc-agent binary to a temporary file and return its path.
///
/// The caller is responsible for cleaning up the temp file after use.
pub fn extract_fc_agent() -> anyhow::Result<PathBuf> {
    if FC_AGENT_BINARY.is_empty() {
        anyhow::bail!(
            "fc-agent binary not embedded. Build with: \
             cargo build -p fc-agent --target <arch>-unknown-linux-musl --release"
        );
    }

    let temp_dir = std::env::temp_dir();
    let temp_path = temp_dir.join("fc-agent");

    let mut file = std::fs::File::create(&temp_path)?;
    file.write_all(FC_AGENT_BINARY)?;

    // Make executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = file.metadata()?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&temp_path, perms)?;
    }

    Ok(temp_path)
}
