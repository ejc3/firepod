use crate::disk::{get_base_rootfs, get_kernel_path, DiskManager};
use crate::error::{Result, VmError};
use crate::firecracker::{Balloon, BootSource, FirecrackerClient, MachineConfig, Vsock};
use crate::state::{Mode, Publish};
use crate::mmds::{MmdsManager, ContainerPlan};
use crate::network::NetworkManager;
use crate::snapshot::SnapshotManager;
use crate::state::{StateManager, VmState, VmStatus};
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::fs;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::time::{sleep, Duration};
use tracing::{error, info, warn, debug};

pub struct VmManager {
    state_mgr: StateManager,
    snapshot_mgr: SnapshotManager,
}

impl VmManager {
    pub fn new() -> Result<Self> {
        let state_mgr = StateManager::new()?;
        let snapshot_mgr = SnapshotManager::new(state_mgr.clone());

        Ok(Self {
            state_mgr: state_mgr.clone(),
            snapshot_mgr,
        })
    }

    pub async fn init(&self) -> Result<()> {
        self.state_mgr.init().await?;
        Ok(())
    }

    /// Run a new VM with a container
    pub async fn run_vm(
        &self,
        name: Option<String>,
        image: String,
        cpu: u8,
        mem: u32,
        mode: Mode,
        publishes: Vec<Publish>,
        balloon: Option<u32>,
        save_snapshot: Option<String>,
    ) -> Result<VmState> {
        info!("Starting new VM for container image: {}", image);

        // Generate VM name if not provided
        let vm_name = name.unwrap_or_else(|| format!("vm-{}", &image.replace(['/', ':'], "-")));

        // Create VM state
        let mut vm = VmState::new(vm_name.clone(), image, mode, cpu, mem);
        vm.balloon = balloon;
        vm.publish = publishes.clone();

        // Resolve mode (auto -> privileged/rootless)
        let mut resolved_mode = vm.mode;
        let mut net_mgr = NetworkManager::new(vm.id.clone(), resolved_mode);
        net_mgr.resolve_mode()?;
        resolved_mode = net_mgr.mode;
        vm.mode = resolved_mode;

        info!("Running VM '{}' in mode: {:?}", vm_name, resolved_mode);

        // Set up disk manager
        let disk_mgr = DiskManager::new(vm.id.clone())?;
        disk_mgr.init().await?;

        // Prepare rootfs
        let base_rootfs = get_base_rootfs()?;
        let rootfs_path = disk_mgr.prepare_rootfs(&base_rootfs, false).await?;
        vm.rootfs_path = rootfs_path.clone();

        // Get kernel path
        let kernel_path = get_kernel_path()?;

        // Get socket path
        let socket_path = self.get_socket_path(&vm.id)?;
        vm.socket_path = socket_path.clone();

        // Start Firecracker
        let fc_process = self.start_firecracker(&socket_path, resolved_mode).await?;
        let fc_pid = fc_process.id().unwrap();
        vm.pid = Some(fc_pid);

        info!("Firecracker started with PID: {}", fc_pid);

        // Wait for API socket
        self.wait_for_socket(&socket_path).await?;

        // Create Firecracker client
        let fc_client = FirecrackerClient::new(&socket_path)?;

        // Configure machine
        self.configure_machine(&fc_client, cpu, mem, balloon).await?;

        // Set boot source
        self.configure_boot(&fc_client, &kernel_path).await?;

        // Configure disks
        disk_mgr.configure_drives(&fc_client, &rootfs_path, false).await?;
        disk_mgr.prepare_volumes(&vm, &fc_client).await?;

        // Configure networking
        let net_config = net_mgr.setup(&fc_client, &publishes).await?;
        vm.network = Some(net_config);

        // Configure MMDS and container plan
        let mmds_mgr = MmdsManager::new();
        mmds_mgr.configure(&fc_client).await?;
        let plan = mmds_mgr.create_plan(&vm);
        mmds_mgr.put_plan(&fc_client, &plan).await?;

        // Start the VM
        fc_client.start_instance().await?;
        vm.status = VmStatus::Running;

        info!("VM '{}' started successfully", vm_name);

        // Save VM state
        self.state_mgr.save_vm(&vm).await?;

        // If snapshot is requested, wait for readiness and create snapshot
        if let Some(snapshot_name) = save_snapshot {
            info!("Will create snapshot '{}' after VM is ready", snapshot_name);
            // Wait a bit for the container to start
            sleep(Duration::from_secs(5)).await;

            self.snapshot_mgr
                .create_snapshot(&fc_client, &vm, snapshot_name)
                .await?;
        }

        Ok(vm)
    }

    /// Clone a VM from a snapshot
    pub async fn clone_vm(
        &self,
        snapshot_name: String,
        clone_name: String,
        publishes: Vec<Publish>,
    ) -> Result<VmState> {
        info!("Cloning VM from snapshot '{}' as '{}'", snapshot_name, clone_name);

        // Load snapshot
        let snapshot = self.state_mgr.load_snapshot(&snapshot_name).await?;

        // Create new VM state based on snapshot config
        let mut vm = snapshot.config.clone();
        vm.id = self.state_mgr.generate_vm_id().await;
        vm.name = clone_name.clone();
        vm.status = VmStatus::Starting;
        vm.created_at = chrono::Utc::now();
        vm.publish = publishes.clone();

        // Prepare CoW rootfs from snapshot
        let rootfs_path = self.snapshot_mgr
            .prepare_clone_rootfs(&snapshot, &vm.id)
            .await?;
        vm.rootfs_path = rootfs_path.clone();

        // Get socket path
        let socket_path = self.get_socket_path(&vm.id)?;
        vm.socket_path = socket_path.clone();

        // Resolve mode
        let mut net_mgr = NetworkManager::new(vm.id.clone(), vm.mode);
        net_mgr.resolve_mode()?;
        vm.mode = net_mgr.mode;

        // Start Firecracker
        let fc_process = self.start_firecracker(&socket_path, vm.mode).await?;
        let fc_pid = fc_process.id().unwrap();
        vm.pid = Some(fc_pid);

        info!("Firecracker started for clone with PID: {}", fc_pid);

        // Wait for API socket
        self.wait_for_socket(&socket_path).await?;

        // Create Firecracker client
        let fc_client = FirecrackerClient::new(&socket_path)?;

        // Restore from snapshot
        self.snapshot_mgr
            .restore_snapshot(&fc_client, &snapshot_name)
            .await?;

        // Update network configuration (new ports, etc.)
        if !publishes.is_empty() {
            let net_config = net_mgr.setup(&fc_client, &publishes).await?;
            vm.network = Some(net_config);
        }

        vm.status = VmStatus::Running;

        info!("VM '{}' cloned successfully from snapshot", clone_name);

        // Save VM state
        self.state_mgr.save_vm(&vm).await?;

        Ok(vm)
    }

    /// Start Firecracker process
    async fn start_firecracker(&self, socket_path: &Path, mode: Mode) -> Result<Child> {
        // Remove old socket if exists
        if socket_path.exists() {
            fs::remove_file(socket_path).await?;
        }

        // Find firecracker binary
        let fc_bin = self.find_firecracker_binary()?;

        debug!("Starting Firecracker from: {}", fc_bin.display());

        let mut cmd = Command::new(&fc_bin);
        cmd.arg("--api-sock")
            .arg(socket_path)
            .arg("--config-file")
            .arg("/dev/null") // We configure via API
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // For rootless mode, we might need additional setup
        if mode == Mode::Rootless {
            // Firecracker should work in rootless mode with /dev/kvm access
            debug!("Starting in rootless mode");
        }

        let child = cmd.spawn().map_err(|e| {
            VmError::Process(format!("Failed to start Firecracker: {}", e))
        })?;

        Ok(child)
    }

    async fn configure_machine(
        &self,
        fc_client: &FirecrackerClient,
        cpu: u8,
        mem: u32,
        balloon: Option<u32>,
    ) -> Result<()> {
        let machine_config = MachineConfig {
            vcpu_count: cpu,
            mem_size_mib: mem,
            smt: false,
            track_dirty_pages: Some(true), // Enable for snapshots
        };

        fc_client.set_machine_config(&machine_config).await?;

        // Configure balloon if requested
        if let Some(balloon_mib) = balloon {
            let balloon_config = Balloon {
                amount_mib: balloon_mib,
                deflate_on_oom: true,
                stats_polling_interval_s: Some(1),
            };

            fc_client.set_balloon(&balloon_config).await?;
            info!("Balloon device configured: {} MiB", balloon_mib);
        }

        Ok(())
    }

    async fn configure_boot(&self, fc_client: &FirecrackerClient, kernel_path: &Path) -> Result<()> {
        let boot_source = BootSource {
            kernel_image_path: kernel_path.to_string_lossy().to_string(),
            boot_args: "console=ttyS0 reboot=k panic=1 pci=off".to_string(),
            initrd_path: None,
        };

        fc_client.set_boot_source(&boot_source).await?;
        Ok(())
    }

    async fn wait_for_socket(&self, socket_path: &Path) -> Result<()> {
        let max_wait = Duration::from_secs(5);
        let start = tokio::time::Instant::now();

        while start.elapsed() < max_wait {
            if socket_path.exists() {
                // Give it a moment to be ready
                sleep(Duration::from_millis(100)).await;
                return Ok(());
            }

            sleep(Duration::from_millis(50)).await;
        }

        Err(VmError::Timeout(format!(
            "Firecracker socket not ready: {:?}",
            socket_path
        )))
    }

    fn get_socket_path(&self, vm_id: &str) -> Result<PathBuf> {
        let dir = self.state_mgr.get_vm_dir(vm_id);
        Ok(dir.join("firecracker.sock"))
    }

    fn find_firecracker_binary(&self) -> Result<PathBuf> {
        // Try common locations
        let locations = vec![
            PathBuf::from(std::env::var("HOME").unwrap_or_default())
                .join(".local/share/fcvm/bin/firecracker"),
            PathBuf::from("/usr/local/bin/firecracker"),
            PathBuf::from("/usr/bin/firecracker"),
        ];

        for loc in locations {
            if loc.exists() {
                return Ok(loc);
            }
        }

        // Try PATH
        if let Ok(path) = which::which("firecracker") {
            return Ok(path);
        }

        Err(VmError::InvalidConfig(
            "Firecracker binary not found. Run fcvm-init.sh first.".to_string(),
        ))
    }

    /// Stop a VM
    pub async fn stop_vm(&self, name: &str) -> Result<()> {
        let vm = self.state_mgr.load_vm_by_name(name).await?;

        info!("Stopping VM '{}'", vm.name);

        if let Some(pid) = vm.pid {
            let _ = signal::kill(Pid::from_raw(pid as i32), Signal::SIGTERM);

            // Wait for process to exit
            for _ in 0..50 {
                // Check if process exists by sending signal 0
                if signal::kill(Pid::from_raw(pid as i32), None).is_err() {
                    break;
                }
                sleep(Duration::from_millis(100)).await;
            }

            // Force kill if still running
            let _ = signal::kill(Pid::from_raw(pid as i32), Signal::SIGKILL);
        }

        // Cleanup networking
        if let Some(net_config) = &vm.network {
            let net_mgr = NetworkManager::new(vm.id.clone(), vm.mode);
            net_mgr.cleanup(net_config).await?;
        }

        // Remove state
        self.state_mgr.delete_vm(&vm.id).await?;

        info!("VM '{}' stopped", vm.name);
        Ok(())
    }

    /// List all VMs
    pub async fn list_vms(&self) -> Result<Vec<VmState>> {
        self.state_mgr.list_vms().await
    }

    /// Get VM by name
    pub async fn get_vm(&self, name: &str) -> Result<VmState> {
        self.state_mgr.load_vm_by_name(name).await
    }
}

impl Clone for StateManager {
    fn clone(&self) -> Self {
        Self {
            state_dir: self.state_dir.clone(),
        }
    }
}
