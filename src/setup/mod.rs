pub mod embedded;
pub mod kernel;
pub mod rootfs;

pub use embedded::extract_fc_agent;
pub use kernel::ensure_kernel;
pub use rootfs::ensure_rootfs;
