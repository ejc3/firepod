use crate::error::Result;
use crate::firecracker::{FirecrackerClient, MmdsConfig};
use crate::state::{VmState, Mode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerPlan {
    pub image: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmd: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub volumes: Option<Vec<VolumeMount>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ports: Option<Vec<PortMapping>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub podman: Option<PodmanConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub readiness: Option<ReadinessProbe>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logs: Option<LogConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VolumeMount {
    pub source: String,
    pub target: String,
    #[serde(default)]
    pub readonly: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortMapping {
    pub container_port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodmanConfig {
    #[serde(default)]
    pub rootless: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadinessProbe {
    pub mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    pub stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
}

pub struct MmdsManager;

impl MmdsManager {
    pub fn new() -> Self {
        Self
    }

    /// Configure MMDS for the VM
    pub async fn configure(&self, fc_client: &FirecrackerClient) -> Result<()> {
        let config = MmdsConfig {
            version: "V2".to_string(),
            ipv4_address: Some("169.254.169.254".to_string()),
            network_interfaces: Some(vec!["eth0".to_string()]),
        };

        fc_client.set_mmds_config(&config).await?;
        info!("MMDS configured");

        Ok(())
    }

    /// Create container plan from VM state
    pub fn create_plan(&self, vm: &VmState) -> ContainerPlan {
        let cmd = vm.cmd.as_ref().map(|c| {
            c.split_whitespace()
                .map(|s| s.to_string())
                .collect()
        });

        let env = if vm.env.is_empty() {
            None
        } else {
            Some(vm.env.clone())
        };

        let volumes = if vm.maps.is_empty() {
            None
        } else {
            Some(
                vm.maps
                    .iter()
                    .map(|v| VolumeMount {
                        source: v.host_path.to_string_lossy().to_string(),
                        target: v.guest_path.to_string_lossy().to_string(),
                        readonly: v.readonly,
                    })
                    .collect(),
            )
        };

        let ports = if vm.publish.is_empty() {
            None
        } else {
            Some(
                vm.publish
                    .iter()
                    .map(|p| PortMapping {
                        container_port: p.guest_port,
                        protocol: format!("{:?}", p.proto).to_lowercase(),
                    })
                    .collect(),
            )
        };

        let podman = Some(PodmanConfig {
            rootless: !matches!(vm.mode, Mode::Privileged),
            args: None,
        });

        ContainerPlan {
            image: vm.image.clone(),
            cmd,
            env,
            volumes,
            ports,
            podman,
            readiness: None,
            logs: Some(LogConfig {
                stream: true,
                file: Some("/var/log/container.log".to_string()),
            }),
        }
    }

    /// Put the container plan into MMDS
    pub async fn put_plan(
        &self,
        fc_client: &FirecrackerClient,
        plan: &ContainerPlan,
    ) -> Result<()> {
        fc_client.put_mmds(plan).await?;
        info!("Container plan pushed to MMDS");
        Ok(())
    }

    /// Create a complete MMDS payload with additional metadata
    pub fn create_full_metadata(&self, vm: &VmState, plan: &ContainerPlan) -> serde_json::Value {
        json!({
            "vm": {
                "id": vm.id,
                "name": vm.name,
                "created_at": vm.created_at.to_rfc3339(),
            },
            "container": plan,
            "network": {
                "guest_ip": vm.network.as_ref().map(|n| &n.guest_ip),
                "gateway": vm.network.as_ref().map(|n| &n.gateway),
            }
        })
    }
}
