use crate::error::{Result, VmError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use tokio::fs;
use uuid::Uuid;

// Core types for VM management
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Mode { Auto, Privileged, Rootless }

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum MapMode { Block, Sshfs, Nfs }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Proto { Tcp, Udp }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Publish {
    pub host_ip: Option<String>,
    pub host_port: u16,
    pub guest_port: u16,
    pub proto: Proto,
}

// Implement PartialEq for Mode manually to avoid conflicts
impl PartialEq for Mode {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Mode::Auto, Mode::Auto)
                | (Mode::Privileged, Mode::Privileged)
                | (Mode::Rootless, Mode::Rootless)
        )
    }
}

impl FromStr for Publish {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        // Parse formats:
        // - HOSTPORT:GUESTPORT (TCP by default)
        // - HOSTPORT:GUESTPORT/PROTO
        // - HOSTIP:HOSTPORT:GUESTPORT
        // - HOSTIP:HOSTPORT:GUESTPORT/PROTO

        let parts: Vec<&str> = s.split(':').collect();

        if parts.len() < 2 || parts.len() > 3 {
            return Err(format!("Invalid publish format: {}", s));
        }

        let (host_ip, host_port_str, guest_port_str) = if parts.len() == 3 {
            (Some(parts[0].to_string()), parts[1], parts[2])
        } else {
            (None, parts[0], parts[1])
        };

        // Parse protocol from guest port
        let (guest_port_str, proto) = if let Some((port, proto_str)) = guest_port_str.split_once('/') {
            let proto = match proto_str.to_lowercase().as_str() {
                "tcp" => Proto::Tcp,
                "udp" => Proto::Udp,
                _ => return Err(format!("Invalid protocol: {}", proto_str)),
            };
            (port, proto)
        } else {
            (guest_port_str, Proto::Tcp)
        };

        let host_port: u16 = host_port_str
            .parse()
            .map_err(|_| format!("Invalid host port: {}", host_port_str))?;

        let guest_port: u16 = guest_port_str
            .parse()
            .map_err(|_| format!("Invalid guest port: {}", guest_port_str))?;

        Ok(Publish {
            host_ip,
            host_port,
            guest_port,
            proto,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmState {
    pub id: String,
    pub name: String,
    pub image: String,
    pub mode: Mode,
    pub cpu: u8,
    pub mem: u32,
    pub balloon: Option<u32>,
    pub maps: Vec<VolumeMap>,
    pub map_mode: MapMode,
    pub env: HashMap<String, String>,
    pub cmd: Option<String>,
    pub publish: Vec<Publish>,
    pub socket_path: PathBuf,
    pub rootfs_path: PathBuf,
    pub snapshot_path: Option<PathBuf>,
    pub created_at: DateTime<Utc>,
    pub pid: Option<u32>,
    pub status: VmStatus,
    pub network: Option<NetworkConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeMap {
    pub host_path: PathBuf,
    pub guest_path: PathBuf,
    pub readonly: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub interface_name: String,
    pub tap_device: Option<String>,
    pub slirp_pid: Option<u32>,
    pub guest_ip: String,
    pub host_ip: String,
    pub gateway: String,
    pub netmask: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VmStatus {
    Starting,
    Running,
    Paused,
    Stopped,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotState {
    pub id: String,
    pub name: String,
    pub vm_id: String,
    pub vm_name: String,
    pub mem_path: PathBuf,
    pub snapshot_path: PathBuf,
    pub rootfs_path: PathBuf,
    pub config: VmState,
    pub created_at: DateTime<Utc>,
}

pub struct StateManager {
    pub(crate) state_dir: PathBuf,
}

impl StateManager {
    pub fn new() -> Result<Self> {
        let state_dir = Self::get_state_dir()?;
        Ok(Self { state_dir })
    }

    fn get_state_dir() -> Result<PathBuf> {
        let base = if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home)
        } else {
            PathBuf::from("/tmp")
        };

        let dir = base.join(".local/share/fcvm/state");
        Ok(dir)
    }

    pub async fn init(&self) -> Result<()> {
        fs::create_dir_all(&self.state_dir).await?;
        fs::create_dir_all(self.state_dir.join("vms")).await?;
        fs::create_dir_all(self.state_dir.join("snapshots")).await?;
        Ok(())
    }

    pub async fn save_vm(&self, vm: &VmState) -> Result<()> {
        let path = self.state_dir.join("vms").join(format!("{}.json", vm.id));
        let json = serde_json::to_string_pretty(vm)?;
        fs::write(&path, json).await?;
        Ok(())
    }

    pub async fn load_vm(&self, id: &str) -> Result<VmState> {
        let path = self.state_dir.join("vms").join(format!("{}.json", id));
        let json = fs::read_to_string(&path).await.map_err(|_| {
            VmError::VmNotFound(id.to_string())
        })?;
        let vm: VmState = serde_json::from_str(&json)?;
        Ok(vm)
    }

    pub async fn load_vm_by_name(&self, name: &str) -> Result<VmState> {
        let vms = self.list_vms().await?;
        vms.into_iter()
            .find(|vm| vm.name == name)
            .ok_or_else(|| VmError::VmNotFound(name.to_string()))
    }

    pub async fn delete_vm(&self, id: &str) -> Result<()> {
        let path = self.state_dir.join("vms").join(format!("{}.json", id));
        fs::remove_file(&path).await?;
        Ok(())
    }

    pub async fn list_vms(&self) -> Result<Vec<VmState>> {
        let vms_dir = self.state_dir.join("vms");
        let mut vms = Vec::new();

        if !vms_dir.exists() {
            return Ok(vms);
        }

        let mut entries = fs::read_dir(&vms_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            if let Some(ext) = entry.path().extension() {
                if ext == "json" {
                    if let Ok(json) = fs::read_to_string(entry.path()).await {
                        if let Ok(vm) = serde_json::from_str::<VmState>(&json) {
                            vms.push(vm);
                        }
                    }
                }
            }
        }

        Ok(vms)
    }

    pub async fn save_snapshot(&self, snapshot: &SnapshotState) -> Result<()> {
        let path = self.state_dir.join("snapshots").join(format!("{}.json", snapshot.id));
        let json = serde_json::to_string_pretty(snapshot)?;
        fs::write(&path, json).await?;
        Ok(())
    }

    pub async fn load_snapshot(&self, name: &str) -> Result<SnapshotState> {
        let snapshots = self.list_snapshots().await?;
        snapshots.into_iter()
            .find(|s| s.name == name)
            .ok_or_else(|| VmError::SnapshotNotFound(name.to_string()))
    }

    pub async fn list_snapshots(&self) -> Result<Vec<SnapshotState>> {
        let snaps_dir = self.state_dir.join("snapshots");
        let mut snapshots = Vec::new();

        if !snaps_dir.exists() {
            return Ok(snapshots);
        }

        let mut entries = fs::read_dir(&snaps_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            if let Some(ext) = entry.path().extension() {
                if ext == "json" {
                    if let Ok(json) = fs::read_to_string(entry.path()).await {
                        if let Ok(snap) = serde_json::from_str::<SnapshotState>(&json) {
                            snapshots.push(snap);
                        }
                    }
                }
            }
        }

        Ok(snapshots)
    }

    pub async fn generate_vm_id(&self) -> String {
        Uuid::new_v4().to_string()
    }

    pub async fn generate_snapshot_id(&self) -> String {
        Uuid::new_v4().to_string()
    }

    pub fn get_vm_dir(&self, vm_id: &str) -> PathBuf {
        self.state_dir.join("vms").join(vm_id)
    }

    pub fn get_snapshot_dir(&self, snapshot_id: &str) -> PathBuf {
        self.state_dir.join("snapshots").join(snapshot_id)
    }
}

impl VmState {
    pub fn new(
        name: String,
        image: String,
        mode: Mode,
        cpu: u8,
        mem: u32,
    ) -> Self {
        let id = Uuid::new_v4().to_string();
        Self {
            id,
            name,
            image,
            mode,
            cpu,
            mem,
            balloon: None,
            maps: Vec::new(),
            map_mode: MapMode::Block,
            env: HashMap::new(),
            cmd: None,
            publish: Vec::new(),
            socket_path: PathBuf::new(),
            rootfs_path: PathBuf::new(),
            snapshot_path: None,
            created_at: Utc::now(),
            pid: None,
            status: VmStatus::Starting,
            network: None,
        }
    }
}
