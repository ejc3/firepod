use crate::error::{Result, VmError};
use hyper::{body::Incoming, Request, Response, StatusCode, body::Bytes};
use hyper_util::rt::TokioIo;
use http_body_util::{BodyExt, Empty, Full};
use hyperlocal::{UnixClientExt, UnixConnector, Uri as UnixUri};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::net::UnixStream;
use hyper_util::client::legacy::Client;
use http_body_util::combinators::BoxBody;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootSource {
    pub kernel_image_path: String,
    pub boot_args: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initrd_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Drive {
    pub drive_id: String,
    pub path_on_host: String,
    pub is_root_device: bool,
    pub is_read_only: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limiter: Option<RateLimiter>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimiter {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bandwidth: Option<TokenBucket>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ops: Option<TokenBucket>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenBucket {
    pub size: u64,
    pub refill_time: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineConfig {
    pub vcpu_count: u8,
    pub mem_size_mib: u32,
    pub smt: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub track_dirty_pages: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub iface_id: String,
    pub host_dev_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guest_mac: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Balloon {
    pub amount_mib: u32,
    pub deflate_on_oom: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats_polling_interval_s: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vsock {
    pub guest_cid: u32,
    pub uds_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MmdsConfig {
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv4_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_interfaces: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotCreateParams {
    pub snapshot_type: String,
    pub snapshot_path: String,
    pub mem_file_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotLoadParams {
    pub snapshot_path: String,
    pub mem_backend: MemBackend,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_diff_snapshots: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resume_vm: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemBackend {
    pub backend_type: String,
    pub backend_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceActionInfo {
    pub action_type: String,
}

pub struct FirecrackerClient {
    client: Client<UnixConnector, BoxBody<Bytes, std::io::Error>>,
    socket_path: String,
}

impl FirecrackerClient {
    pub fn new(socket_path: impl AsRef<Path>) -> Result<Self> {
        let socket_path = socket_path.as_ref().to_string_lossy().to_string();
        let client = Client::unix();

        Ok(Self {
            client,
            socket_path,
        })
    }

    async fn request<T: Serialize>(
        &self,
        method: &str,
        path: &str,
        body: Option<&T>,
    ) -> Result<Response<Incoming>> {
        let uri = UnixUri::new(&self.socket_path, path);

        let mut req_builder = Request::builder()
            .method(method)
            .uri(uri);

        let req = if let Some(body_data) = body {
            let json = serde_json::to_string(body_data)?;
            req_builder = req_builder.header("Content-Type", "application/json");
            req_builder
                .body(Full::new(json.into()).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)).boxed())
                .map_err(|e| VmError::Http(e.to_string()))?
        } else {
            req_builder
                .body(Empty::new().map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)).boxed())
                .map_err(|e| VmError::Http(e.to_string()))?
        };

        let resp = self.client.request(req).await
            .map_err(|e| VmError::FirecrackerApi(format!("Request failed: {}", e)))?;

        Ok(resp)
    }

    pub async fn set_boot_source(&self, boot_source: &BootSource) -> Result<()> {
        let resp = self.request("PUT", "/boot-source", Some(boot_source)).await?;
        self.check_response(resp, "set_boot_source").await
    }

    pub async fn set_machine_config(&self, config: &MachineConfig) -> Result<()> {
        let resp = self.request("PUT", "/machine-config", Some(config)).await?;
        self.check_response(resp, "set_machine_config").await
    }

    pub async fn add_drive(&self, drive: &Drive) -> Result<()> {
        let path = format!("/drives/{}", drive.drive_id);
        let resp = self.request("PUT", &path, Some(drive)).await?;
        self.check_response(resp, "add_drive").await
    }

    pub async fn add_network_interface(&self, iface: &NetworkInterface) -> Result<()> {
        let path = format!("/network-interfaces/{}", iface.iface_id);
        let resp = self.request("PUT", &path, Some(iface)).await?;
        self.check_response(resp, "add_network_interface").await
    }

    pub async fn set_balloon(&self, balloon: &Balloon) -> Result<()> {
        let resp = self.request("PUT", "/balloon", Some(balloon)).await?;
        self.check_response(resp, "set_balloon").await
    }

    pub async fn set_vsock(&self, vsock: &Vsock) -> Result<()> {
        let resp = self.request("PUT", "/vsock", Some(vsock)).await?;
        self.check_response(resp, "set_vsock").await
    }

    pub async fn set_mmds_config(&self, config: &MmdsConfig) -> Result<()> {
        let resp = self.request("PUT", "/mmds/config", Some(config)).await?;
        self.check_response(resp, "set_mmds_config").await
    }

    pub async fn put_mmds<T: Serialize>(&self, data: &T) -> Result<()> {
        let resp = self.request("PUT", "/mmds", Some(data)).await?;
        self.check_response(resp, "put_mmds").await
    }

    pub async fn start_instance(&self) -> Result<()> {
        let action = InstanceActionInfo {
            action_type: "InstanceStart".to_string(),
        };
        let resp = self.request("PUT", "/actions", Some(&action)).await?;
        self.check_response(resp, "start_instance").await
    }

    pub async fn pause_instance(&self) -> Result<()> {
        let action = InstanceActionInfo {
            action_type: "Pause".to_string(),
        };
        let resp = self.request("PUT", "/actions", Some(&action)).await?;
        self.check_response(resp, "pause_instance").await
    }

    pub async fn resume_instance(&self) -> Result<()> {
        let action = InstanceActionInfo {
            action_type: "Resume".to_string(),
        };
        let resp = self.request("PUT", "/actions", Some(&action)).await?;
        self.check_response(resp, "resume_instance").await
    }

    pub async fn create_snapshot(&self, params: &SnapshotCreateParams) -> Result<()> {
        let resp = self.request("PUT", "/snapshot/create", Some(params)).await?;
        self.check_response(resp, "create_snapshot").await
    }

    pub async fn load_snapshot(&self, params: &SnapshotLoadParams) -> Result<()> {
        let resp = self.request("PUT", "/snapshot/load", Some(params)).await?;
        self.check_response(resp, "load_snapshot").await
    }

    async fn check_response(&self, resp: Response<Incoming>, operation: &str) -> Result<()> {
        let status = resp.status();
        if status.is_success() {
            Ok(())
        } else {
            let body = resp.into_body().collect().await
                .map_err(|e| VmError::Http(e.to_string()))?;
            let bytes = body.to_bytes();
            let error_msg = String::from_utf8_lossy(&bytes).to_string();
            Err(VmError::FirecrackerApi(format!(
                "{} failed with status {}: {}",
                operation, status, error_msg
            )))
        }
    }
}
