use crate::error::{Result, VmError};
use crate::firecracker::{FirecrackerClient, NetworkInterface};
use crate::state::{Mode, Publish, Proto};
use crate::state::NetworkConfig;
use nix::unistd::{Uid, Gid, getuid, getgid};
use std::process::Stdio;
use tokio::process::{Child, Command};
use tracing::{info, debug, warn};

pub struct NetworkManager {
    vm_id: String,
    pub mode: Mode,
}

impl NetworkManager {
    pub fn new(vm_id: String, mode: Mode) -> Self {
        Self { vm_id, mode }
    }

    /// Determine the actual mode to use (resolve Auto)
    pub fn resolve_mode(&mut self) -> Result<()> {
        if self.mode == Mode::Auto {
            self.mode = if getuid().is_root() {
                Mode::Privileged
            } else {
                Mode::Rootless
            };
            info!("Auto-detected mode: {:?}", self.mode);
        }
        Ok(())
    }

    /// Set up networking based on mode
    pub async fn setup(
        &self,
        fc_client: &FirecrackerClient,
        publishes: &[Publish],
    ) -> Result<NetworkConfig> {
        match self.mode {
            Mode::Privileged => self.setup_privileged(fc_client, publishes).await,
            Mode::Rootless => self.setup_rootless(fc_client, publishes).await,
            Mode::Auto => Err(VmError::InvalidConfig("Mode not resolved".to_string())),
        }
    }

    /// Privileged mode: TAP device + nftables for port forwarding
    async fn setup_privileged(
        &self,
        fc_client: &FirecrackerClient,
        publishes: &[Publish],
    ) -> Result<NetworkConfig> {
        let tap_name = format!("fc-tap-{}", &self.vm_id[..8]);
        let bridge_name = "fcbr0";
        let guest_ip = self.allocate_guest_ip()?;
        let gateway = "172.20.0.1".to_string();
        let netmask = "255.255.0.0".to_string();

        // Create TAP device
        self.create_tap(&tap_name).await?;

        // Attach to bridge (create bridge if needed)
        self.setup_bridge(bridge_name, &gateway).await?;
        self.attach_tap_to_bridge(&tap_name, bridge_name).await?;

        // Configure Firecracker network interface
        let iface = NetworkInterface {
            iface_id: "eth0".to_string(),
            host_dev_name: tap_name.clone(),
            guest_mac: Some(self.generate_mac_address()),
        };

        fc_client.add_network_interface(&iface).await?;

        // Set up port forwarding with nftables
        if !publishes.is_empty() {
            self.setup_port_forwarding_privileged(&guest_ip, publishes).await?;
        }

        info!("Privileged networking configured: guest_ip={}, tap={}", guest_ip, tap_name);

        Ok(NetworkConfig {
            interface_name: "eth0".to_string(),
            tap_device: Some(tap_name),
            slirp_pid: None,
            guest_ip,
            host_ip: gateway.clone(),
            gateway,
            netmask,
        })
    }

    /// Rootless mode: slirp4netns for user-mode networking
    async fn setup_rootless(
        &self,
        fc_client: &FirecrackerClient,
        publishes: &[Publish],
    ) -> Result<NetworkConfig> {
        let tap_name = format!("fc-tap-{}", &self.vm_id[..8]);
        let guest_ip = "10.0.2.15".to_string();
        let gateway = "10.0.2.2".to_string();
        let netmask = "255.255.255.0".to_string();

        // Create TAP device in user namespace
        self.create_tap_rootless(&tap_name).await?;

        // Configure Firecracker network interface
        let iface = NetworkInterface {
            iface_id: "eth0".to_string(),
            host_dev_name: tap_name.clone(),
            guest_mac: Some(self.generate_mac_address()),
        };

        fc_client.add_network_interface(&iface).await?;

        // Note: slirp4netns will be started with the Firecracker process
        // Port forwarding is configured via slirp4netns command line

        info!("Rootless networking configured: guest_ip={}, tap={}", guest_ip, tap_name);

        Ok(NetworkConfig {
            interface_name: "eth0".to_string(),
            tap_device: Some(tap_name),
            slirp_pid: None,
            guest_ip,
            host_ip: gateway.clone(),
            gateway,
            netmask,
        })
    }

    async fn create_tap(&self, name: &str) -> Result<()> {
        let output = Command::new("ip")
            .args(&["tuntap", "add", name, "mode", "tap"])
            .output()
            .await?;

        if !output.status.success() {
            return Err(VmError::Network(format!(
                "Failed to create TAP device: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        // Bring up the interface
        Command::new("ip")
            .args(&["link", "set", name, "up"])
            .output()
            .await?;

        info!("Created TAP device: {}", name);
        Ok(())
    }

    async fn create_tap_rootless(&self, name: &str) -> Result<()> {
        // For rootless, we need to use a user namespace or rely on slirp4netns
        // This is a simplified version that assumes proper permissions
        // In production, you might need to use unshare or similar

        let output = Command::new("ip")
            .args(&["tuntap", "add", name, "mode", "tap", "user", &getuid().to_string()])
            .output()
            .await;

        match output {
            Ok(out) if out.status.success() => {
                Command::new("ip")
                    .args(&["link", "set", name, "up"])
                    .output()
                    .await?;
                info!("Created rootless TAP device: {}", name);
                Ok(())
            }
            _ => {
                // If TAP creation fails, we'll rely on slirp4netns
                warn!("Could not create TAP device, will use slirp4netns");
                Ok(())
            }
        }
    }

    async fn setup_bridge(&self, name: &str, ip: &str) -> Result<()> {
        // Check if bridge exists
        let check = Command::new("ip")
            .args(&["link", "show", name])
            .output()
            .await?;

        if !check.status.success() {
            // Create bridge
            Command::new("ip")
                .args(&["link", "add", name, "type", "bridge"])
                .output()
                .await?;

            Command::new("ip")
                .args(&["addr", "add", &format!("{}/16", ip), "dev", name])
                .output()
                .await?;

            Command::new("ip")
                .args(&["link", "set", name, "up"])
                .output()
                .await?;

            // Enable forwarding
            Command::new("sysctl")
                .args(&["-w", "net.ipv4.ip_forward=1"])
                .output()
                .await?;

            info!("Created bridge: {} with IP {}", name, ip);
        } else {
            debug!("Bridge {} already exists", name);
        }

        Ok(())
    }

    async fn attach_tap_to_bridge(&self, tap: &str, bridge: &str) -> Result<()> {
        Command::new("ip")
            .args(&["link", "set", tap, "master", bridge])
            .output()
            .await?;

        info!("Attached {} to bridge {}", tap, bridge);
        Ok(())
    }

    async fn setup_port_forwarding_privileged(
        &self,
        guest_ip: &str,
        publishes: &[Publish],
    ) -> Result<()> {
        for pub_rule in publishes {
            let host_ip = pub_rule.host_ip.as_deref().unwrap_or("0.0.0.0");
            let proto = match pub_rule.proto {
                Proto::Tcp => "tcp",
                Proto::Udp => "udp",
            };

            // Add DNAT rule with nftables
            let rule = format!(
                "add rule ip nat prerouting ip daddr {} {} dport {} dnat to {}:{}",
                host_ip, proto, pub_rule.host_port, guest_ip, pub_rule.guest_port
            );

            let output = Command::new("nft")
                .arg(&rule)
                .output()
                .await;

            match output {
                Ok(out) if out.status.success() => {
                    info!("Added port forwarding: {}:{} -> {}:{} ({})",
                          host_ip, pub_rule.host_port, guest_ip, pub_rule.guest_port, proto);
                }
                _ => {
                    warn!("Failed to add nftables rule (might not be set up yet)");
                    // Continue anyway, user can set up manually
                }
            }
        }

        Ok(())
    }

    /// Generate slirp4netns command line arguments for rootless port forwarding
    pub fn get_slirp_port_args(&self, publishes: &[Publish]) -> Vec<String> {
        let mut args = Vec::new();

        for pub_rule in publishes {
            let host_ip = pub_rule.host_ip.as_deref().unwrap_or("127.0.0.1");
            let proto = match pub_rule.proto {
                Proto::Tcp => "tcp",
                Proto::Udp => "udp",
            };

            args.push("--port".to_string());
            args.push(format!(
                "{}:{}:{}:{}",
                host_ip, pub_rule.host_port, pub_rule.guest_port, proto
            ));
        }

        args
    }

    fn allocate_guest_ip(&self) -> Result<String> {
        // Simple IP allocation based on VM ID hash
        // In production, use proper IPAM
        let hash = &self.vm_id[..8];
        let hash_num = u32::from_str_radix(hash, 16).unwrap_or(1) % 254 + 2;
        Ok(format!("172.20.{}.{}", hash_num / 254, hash_num % 254))
    }

    fn generate_mac_address(&self) -> String {
        // Generate MAC address based on VM ID
        let hash = &self.vm_id[..12];
        format!(
            "02:fc:{}:{}:{}:{}",
            &hash[0..2],
            &hash[2..4],
            &hash[4..6],
            &hash[6..8]
        )
    }

    pub async fn cleanup(&self, config: &NetworkConfig) -> Result<()> {
        info!("Cleaning up network for VM {}", self.vm_id);

        if let Some(tap) = &config.tap_device {
            let _ = Command::new("ip")
                .args(&["link", "del", tap])
                .output()
                .await;
        }

        // Note: We don't clean up the bridge or nftables rules automatically
        // to avoid disrupting other VMs

        Ok(())
    }
}

