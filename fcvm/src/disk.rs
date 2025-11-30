use crate::error::{Result, VmError};
use crate::firecracker::{Drive, FirecrackerClient};
use crate::state::{VmState, VolumeMap, MapMode};
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::process::Command;
use tracing::{info, debug};

pub struct DiskManager {
    vm_id: String,
    work_dir: PathBuf,
}

impl DiskManager {
    pub fn new(vm_id: String) -> Result<Self> {
        let work_dir = Self::get_work_dir(&vm_id)?;
        Ok(Self { vm_id, work_dir })
    }

    fn get_work_dir(vm_id: &str) -> Result<PathBuf> {
        let base = if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home)
        } else {
            PathBuf::from("/tmp")
        };

        let dir = base.join(".local/share/fcvm/vms").join(vm_id);
        Ok(dir)
    }

    pub async fn init(&self) -> Result<()> {
        fs::create_dir_all(&self.work_dir).await?;
        fs::create_dir_all(self.work_dir.join("disks")).await?;
        Ok(())
    }

    /// Prepare the root filesystem for the VM
    pub async fn prepare_rootfs(&self, base_rootfs: &Path, snapshot_mode: bool) -> Result<PathBuf> {
        let rootfs_path = self.work_dir.join("disks/rootfs.ext4");

        if snapshot_mode {
            // Create a CoW overlay for fast cloning
            debug!("Creating CoW rootfs overlay");
            self.create_cow_disk(base_rootfs, &rootfs_path).await?;
        } else {
            // Copy the base rootfs
            debug!("Copying base rootfs");
            fs::copy(base_rootfs, &rootfs_path).await?;
        }

        Ok(rootfs_path)
    }

    /// Create a Copy-on-Write disk using qcow2 or device-mapper
    async fn create_cow_disk(&self, base: &Path, target: &Path) -> Result<()> {
        // Try to use qcow2 format for CoW
        let output = Command::new("qemu-img")
            .args(&[
                "create",
                "-f", "qcow2",
                "-F", "raw",
                "-o", &format!("backing_file={}", base.display()),
                &target.to_string_lossy(),
            ])
            .output()
            .await;

        match output {
            Ok(out) if out.status.success() => {
                info!("Created qcow2 CoW disk: {:?}", target);
                Ok(())
            }
            _ => {
                // Fallback: just copy the file
                debug!("qemu-img not available, falling back to copy");
                fs::copy(base, target).await?;
                Ok(())
            }
        }
    }

    /// Configure drives for Firecracker
    pub async fn configure_drives(
        &self,
        fc_client: &FirecrackerClient,
        rootfs_path: &Path,
        readonly_root: bool,
    ) -> Result<()> {
        // Add root drive
        let root_drive = Drive {
            drive_id: "rootfs".to_string(),
            path_on_host: rootfs_path.to_string_lossy().to_string(),
            is_root_device: true,
            is_read_only: readonly_root,
            rate_limiter: None,
        };

        fc_client.add_drive(&root_drive).await?;
        info!("Configured root drive: {:?}", rootfs_path);

        Ok(())
    }

    /// Prepare additional volume mounts
    /// Note: Firecracker doesn't support virtio-9p or virtio-fs natively,
    /// so we need to use alternative approaches:
    /// 1. Additional block devices (for block mode)
    /// 2. NFS/SSHFS mounted inside the guest (requires guest agent)
    pub async fn prepare_volumes(
        &self,
        vm: &VmState,
        fc_client: &FirecrackerClient,
    ) -> Result<()> {
        match vm.map_mode {
            MapMode::Block => {
                self.prepare_block_volumes(vm, fc_client).await?;
            }
            MapMode::Sshfs | MapMode::Nfs => {
                // These will be handled by the guest agent via MMDS
                info!("Volume mapping will be handled by guest agent (mode: {:?})", vm.map_mode);
            }
        }

        Ok(())
    }

    async fn prepare_block_volumes(
        &self,
        vm: &VmState,
        fc_client: &FirecrackerClient,
    ) -> Result<()> {
        for (idx, vol) in vm.maps.iter().enumerate() {
            let drive_id = format!("vol{}", idx);
            let disk_path = self.create_volume_disk(&vol, &drive_id).await?;

            let drive = Drive {
                drive_id: drive_id.clone(),
                path_on_host: disk_path.to_string_lossy().to_string(),
                is_root_device: false,
                is_read_only: vol.readonly,
                rate_limiter: None,
            };

            fc_client.add_drive(&drive).await?;
            info!("Configured volume drive {}: {:?} -> {:?}",
                  drive_id, vol.host_path, vol.guest_path);
        }

        Ok(())
    }

    async fn create_volume_disk(&self, vol: &VolumeMap, drive_id: &str) -> Result<PathBuf> {
        let disk_path = self.work_dir.join("disks").join(format!("{}.ext4", drive_id));

        // Create an ext4 disk image with the host directory contents
        // This is a simplified approach; in production you might want to:
        // 1. Bind mount the host directory inside the VM (requires special kernel setup)
        // 2. Use NFS/SSHFS (handled by guest agent)
        // 3. Create proper ext4 images with mke2fs

        info!("Creating volume disk for {:?} (this is a placeholder)", vol.host_path);

        // For now, create an empty file as placeholder
        // In a full implementation, you would use mke2fs or similar
        fs::write(&disk_path, b"").await?;

        Ok(disk_path)
    }

    pub async fn cleanup(&self) -> Result<()> {
        info!("Cleaning up disks for VM {}", self.vm_id);
        // Note: We might want to keep disks for stopped VMs
        // Only clean up on explicit removal
        Ok(())
    }

    pub fn get_rootfs_path(&self) -> PathBuf {
        self.work_dir.join("disks/rootfs.ext4")
    }
}

/// Helper to get the base rootfs image path
pub fn get_base_rootfs() -> Result<PathBuf> {
    let base = if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home)
    } else {
        return Err(VmError::InvalidConfig("HOME not set".to_string()));
    };

    let rootfs = base.join(".local/share/fcvm/images/rootfs.ext4");

    if !rootfs.exists() {
        return Err(VmError::InvalidConfig(format!(
            "Base rootfs not found at {:?}. Run fcvm-init.sh first.",
            rootfs
        )));
    }

    Ok(rootfs)
}

/// Helper to get the kernel path
pub fn get_kernel_path() -> Result<PathBuf> {
    let base = if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home)
    } else {
        return Err(VmError::InvalidConfig("HOME not set".to_string()));
    };

    let kernel = base.join(".local/share/fcvm/images/vmlinux");

    if !kernel.exists() {
        return Err(VmError::InvalidConfig(format!(
            "Kernel not found at {:?}. Run fcvm-init.sh first.",
            kernel
        )));
    }

    Ok(kernel)
}
