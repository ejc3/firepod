use crate::error::{Result, VmError};
use crate::firecracker::{FirecrackerClient, SnapshotCreateParams, SnapshotLoadParams, MemBackend};
use crate::state::{SnapshotState, StateManager, VmState};
use chrono::Utc;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::time::{sleep, Duration};
use tracing::{info, debug};
use uuid::Uuid;

pub struct SnapshotManager {
    state_mgr: StateManager,
}

impl SnapshotManager {
    pub fn new(state_mgr: StateManager) -> Self {
        Self { state_mgr }
    }

    /// Create a full VM snapshot
    pub async fn create_snapshot(
        &self,
        fc_client: &FirecrackerClient,
        vm: &VmState,
        snapshot_name: String,
    ) -> Result<SnapshotState> {
        info!("Creating snapshot '{}' for VM '{}'", snapshot_name, vm.name);

        let snapshot_id = Uuid::new_v4().to_string();
        let snapshot_dir = self.get_snapshot_dir(&snapshot_id)?;

        // Create snapshot directory
        fs::create_dir_all(&snapshot_dir).await?;

        let snapshot_path = snapshot_dir.join("vmstate");
        let mem_path = snapshot_dir.join("memory");

        // Pause the VM before snapshotting
        debug!("Pausing VM for snapshot");
        fc_client.pause_instance().await?;

        // Give it a moment to pause
        sleep(Duration::from_millis(100)).await;

        // Create the snapshot
        let snapshot_params = SnapshotCreateParams {
            snapshot_type: "Full".to_string(),
            snapshot_path: snapshot_path.to_string_lossy().to_string(),
            mem_file_path: mem_path.to_string_lossy().to_string(),
        };

        fc_client.create_snapshot(&snapshot_params).await?;

        // Resume the VM
        debug!("Resuming VM after snapshot");
        fc_client.resume_instance().await?;

        // Copy the rootfs for the snapshot
        let rootfs_snapshot_path = snapshot_dir.join("rootfs.ext4");
        fs::copy(&vm.rootfs_path, &rootfs_snapshot_path).await?;

        let snapshot_state = SnapshotState {
            id: snapshot_id.clone(),
            name: snapshot_name,
            vm_id: vm.id.clone(),
            vm_name: vm.name.clone(),
            mem_path,
            snapshot_path,
            rootfs_path: rootfs_snapshot_path,
            config: vm.clone(),
            created_at: Utc::now(),
        };

        // Save snapshot metadata
        self.state_mgr.save_snapshot(&snapshot_state).await?;

        info!("Snapshot created successfully: {}", snapshot_state.name);
        Ok(snapshot_state)
    }

    /// Restore a VM from snapshot (for cloning)
    pub async fn restore_snapshot(
        &self,
        fc_client: &FirecrackerClient,
        snapshot_name: &str,
    ) -> Result<SnapshotState> {
        info!("Restoring from snapshot '{}'", snapshot_name);

        let snapshot = self.state_mgr.load_snapshot(snapshot_name).await?;

        // Verify snapshot files exist
        if !snapshot.snapshot_path.exists() {
            return Err(VmError::SnapshotNotFound(format!(
                "Snapshot file not found: {:?}",
                snapshot.snapshot_path
            )));
        }

        if !snapshot.mem_path.exists() {
            return Err(VmError::SnapshotNotFound(format!(
                "Memory file not found: {:?}",
                snapshot.mem_path
            )));
        }

        // Load the snapshot
        let load_params = SnapshotLoadParams {
            snapshot_path: snapshot.snapshot_path.to_string_lossy().to_string(),
            mem_backend: MemBackend {
                backend_type: "File".to_string(),
                backend_path: snapshot.mem_path.to_string_lossy().to_string(),
            },
            enable_diff_snapshots: Some(false),
            resume_vm: Some(true),
        };

        fc_client.load_snapshot(&load_params).await?;

        info!("Snapshot restored successfully: {}", snapshot.name);
        Ok(snapshot)
    }

    /// Prepare a CoW rootfs from snapshot for fast cloning
    pub async fn prepare_clone_rootfs(
        &self,
        snapshot: &SnapshotState,
        clone_vm_id: &str,
    ) -> Result<PathBuf> {
        let clone_rootfs = self.state_mgr
            .get_vm_dir(clone_vm_id)
            .join("disks/rootfs.ext4");

        // Create parent directories
        if let Some(parent) = clone_rootfs.parent() {
            fs::create_dir_all(parent).await?;
        }

        // Create CoW overlay using qcow2
        let output = tokio::process::Command::new("qemu-img")
            .args(&[
                "create",
                "-f", "qcow2",
                "-F", "raw",
                "-o", &format!("backing_file={}", snapshot.rootfs_path.display()),
                &clone_rootfs.to_string_lossy(),
            ])
            .output()
            .await;

        match output {
            Ok(out) if out.status.success() => {
                debug!("Created CoW rootfs for clone: {:?}", clone_rootfs);
            }
            _ => {
                // Fallback: copy the rootfs
                debug!("qemu-img not available, copying rootfs");
                fs::copy(&snapshot.rootfs_path, &clone_rootfs).await?;
            }
        }

        Ok(clone_rootfs)
    }

    fn get_snapshot_dir(&self, snapshot_id: &str) -> Result<PathBuf> {
        let base = if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home)
        } else {
            PathBuf::from("/tmp")
        };

        let dir = base.join(".local/share/fcvm/snapshots").join(snapshot_id);
        Ok(dir)
    }

    /// Wait for snapshot to be ready (after creation)
    pub async fn wait_for_snapshot(&self, snapshot_path: &Path) -> Result<()> {
        let max_wait = Duration::from_secs(30);
        let start = tokio::time::Instant::now();

        while start.elapsed() < max_wait {
            if snapshot_path.exists() {
                // Check if file is being written by checking size stability
                let size1 = fs::metadata(snapshot_path).await?.len();
                sleep(Duration::from_millis(100)).await;
                let size2 = fs::metadata(snapshot_path).await?.len();

                if size1 == size2 && size1 > 0 {
                    return Ok(());
                }
            }

            sleep(Duration::from_millis(100)).await;
        }

        Err(VmError::Timeout(format!(
            "Snapshot creation timeout: {:?}",
            snapshot_path
        )))
    }

    /// Check if a snapshot exists
    pub async fn snapshot_exists(&self, name: &str) -> bool {
        self.state_mgr.load_snapshot(name).await.is_ok()
    }

    /// List all available snapshots
    pub async fn list_snapshots(&self) -> Result<Vec<SnapshotState>> {
        self.state_mgr.list_snapshots().await
    }

    /// Delete a snapshot
    pub async fn delete_snapshot(&self, name: &str) -> Result<()> {
        let snapshot = self.state_mgr.load_snapshot(name).await?;

        // Remove snapshot files
        if snapshot.snapshot_path.exists() {
            fs::remove_file(&snapshot.snapshot_path).await?;
        }

        if snapshot.mem_path.exists() {
            fs::remove_file(&snapshot.mem_path).await?;
        }

        if snapshot.rootfs_path.exists() {
            fs::remove_file(&snapshot.rootfs_path).await?;
        }

        // Remove snapshot directory
        if let Some(parent) = snapshot.snapshot_path.parent() {
            let _ = fs::remove_dir(parent).await;
        }

        info!("Snapshot deleted: {}", name);
        Ok(())
    }
}
