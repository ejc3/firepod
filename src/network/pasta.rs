//! Pasta networking for IPv6 support
//!
//! Uses pasta (from passt project) instead of slirp4netns for better IPv6 support.
//! pasta provides native IPv4 and IPv6 connectivity from the host network.
//!
//! Architecture:
//! ```text
//! Host                    | User Namespace (pasta --config-net)
//!                         |
//! pasta <-----------------+-- eth0 (IPv4 + IPv6 from host)
//!   (L4 translation)      |        |
//!                         |        v (NAT/forwarding)
//!                         |     tap0 (192.168.1.1 + fd00:1::1)
//!                         |        |
//!                         |   Firecracker VM
//!                         |   (guest: 192.168.1.2 + fd00:1::2)
//! ```
//!
//! Key differences from slirp4netns:
//! - pasta creates its own interface (eth0) with host's IP addresses
//! - We create a separate tap for Firecracker
//! - NAT66 (ip6tables MASQUERADE) provides IPv6 NAT
//! - IPv4 NAT works the same way

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::process::Stdio;
use tokio::process::{Child, Command};
use tracing::{info, warn};

use super::{types::generate_mac, NetworkConfig, NetworkManager, PortMapping};

/// Guest network addressing
const GUEST_IP: &str = "192.168.1.2";
const NAMESPACE_IP: &str = "192.168.1.1";
const GUEST_SUBNET: &str = "192.168.1.0/24";

/// IPv6 ULA prefix for guest network
const GUEST_IPV6: &str = "fd00:1::2";
const NAMESPACE_IPV6: &str = "fd00:1::1";
const GUEST_IPV6_SUBNET: &str = "fd00:1::/64";

/// Pasta networking with IPv6 support
pub struct PastaNetwork {
    vm_id: String,
    tap_device: String,
    #[allow(dead_code)] // TODO: implement port forwarding for pasta
    port_mappings: Vec<PortMapping>,

    // Network addressing
    guest_ip: String,
    guest_ipv6: String,
    namespace_ip: String,
    namespace_ipv6: String,

    // State
    pasta_process: Option<Child>,
    loopback_ip: Option<String>,
    host_mac: Option<String>,
}

impl PastaNetwork {
    pub fn new(vm_id: String, tap_device: String, port_mappings: Vec<PortMapping>) -> Self {
        Self {
            vm_id,
            tap_device,
            port_mappings,
            guest_ip: GUEST_IP.to_string(),
            guest_ipv6: GUEST_IPV6.to_string(),
            namespace_ip: NAMESPACE_IP.to_string(),
            namespace_ipv6: NAMESPACE_IPV6.to_string(),
            pasta_process: None,
            loopback_ip: None,
            host_mac: None,
        }
    }

    /// Set unique loopback IP for port forwarding
    pub fn with_loopback_ip(mut self, loopback_ip: String) -> Self {
        self.loopback_ip = Some(loopback_ip);
        self
    }

    /// Set host MAC address for AWS compatibility
    pub fn with_host_mac(mut self, mac: String) -> Self {
        self.host_mac = Some(mac);
        self
    }

    pub fn loopback_ip(&self) -> Option<&str> {
        self.loopback_ip.as_deref()
    }

    /// Get the host's MAC address from the default interface
    fn get_host_mac() -> Result<String> {
        let output = std::process::Command::new("ip")
            .args(["route", "get", "1.1.1.1"])
            .output()
            .context("get default route")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        // Parse "dev enP1s33" from output
        let iface = stdout
            .split_whitespace()
            .skip_while(|w| *w != "dev")
            .nth(1)
            .context("parse interface from route")?;

        let mac_output = std::process::Command::new("ip")
            .args(["link", "show", iface])
            .output()
            .context("get interface mac")?;

        let mac_stdout = String::from_utf8_lossy(&mac_output.stdout);
        // Parse "link/ether xx:xx:xx:xx:xx:xx"
        let mac = mac_stdout
            .lines()
            .find(|l| l.contains("link/ether"))
            .and_then(|l| l.split_whitespace().nth(1))
            .context("parse MAC address")?;

        Ok(mac.to_string())
    }

    /// Build setup script for the namespace
    /// This runs after pasta has started, setting up the Firecracker tap
    pub fn build_setup_script(&self) -> String {
        format!(
            r#"
set -e

# Wait for pasta to configure eth0
sleep 1

# Create TAP device for Firecracker
ip tuntap add {tap} mode tap
ip addr add {ns_ip}/24 dev {tap}
ip -6 addr add {ns_ipv6}/64 dev {tap}
ip link set {tap} up

# Set up loopback
ip link set lo up

# Enable IP forwarding (IPv4 and IPv6)
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv4.conf.all.forwarding=1
sysctl -w net.ipv4.conf.eth0.forwarding=1
sysctl -w net.ipv4.conf.{tap}.forwarding=1
sysctl -w net.ipv6.conf.all.forwarding=1

# IPv4 NAT: masquerade guest traffic going out eth0
iptables -t nat -A POSTROUTING -s {guest_subnet} -o eth0 -j MASQUERADE 2>/dev/null || true
iptables -A FORWARD -i eth0 -o {tap} -j ACCEPT 2>/dev/null || true
iptables -A FORWARD -i {tap} -o eth0 -j ACCEPT 2>/dev/null || true

# IPv6 NAT66: masquerade guest IPv6 traffic going out eth0
ip6tables -t nat -A POSTROUTING -s {guest_ipv6_subnet} -o eth0 -j MASQUERADE 2>/dev/null || true
ip6tables -A FORWARD -i eth0 -o {tap} -j ACCEPT 2>/dev/null || true
ip6tables -A FORWARD -i {tap} -o eth0 -j ACCEPT 2>/dev/null || true

# Add default route via eth0's gateway (pasta sets this up)
# For IPv6, the route should already be there from pasta
"#,
            tap = self.tap_device,
            ns_ip = self.namespace_ip,
            ns_ipv6 = self.namespace_ipv6,
            guest_subnet = GUEST_SUBNET,
            guest_ipv6_subnet = GUEST_IPV6_SUBNET,
        )
    }

    /// Build the pasta command to start networking
    pub fn build_pasta_command(&self, holder_pid: u32) -> Vec<String> {
        let mut cmd = vec![
            "pasta".to_string(),
            "--foreground".to_string(),
            "--config-net".to_string(),
            "-I".to_string(),
            "eth0".to_string(),
        ];

        // Use host MAC for AWS compatibility
        if let Some(mac) = &self.host_mac {
            cmd.push("--ns-mac-addr".to_string());
            cmd.push(mac.clone());
        }

        // Attach to existing namespace
        cmd.push("--netns".to_string());
        cmd.push(format!("/proc/{}/ns/net", holder_pid));

        cmd
    }

    /// Start pasta attached to the namespace
    pub async fn start_pasta(&mut self, holder_pid: u32) -> Result<()> {
        // Get host MAC if not set
        if self.host_mac.is_none() {
            match Self::get_host_mac() {
                Ok(mac) => {
                    info!(mac = %mac, "detected host MAC for AWS compatibility");
                    self.host_mac = Some(mac);
                }
                Err(e) => {
                    warn!(error = %e, "could not detect host MAC, IPv6 may not work on AWS");
                }
            }
        }

        let cmd = self.build_pasta_command(holder_pid);
        info!(cmd = ?cmd, "starting pasta for IPv6 networking");

        let child = Command::new(&cmd[0])
            .args(&cmd[1..])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("spawn pasta")?;

        self.pasta_process = Some(child);

        // Wait for pasta to be ready
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;

        info!("pasta ready");
        Ok(())
    }

    /// Build nsenter prefix for running commands in the namespace
    pub fn build_nsenter_prefix(&self, holder_pid: u32) -> Vec<String> {
        vec![
            "nsenter".to_string(),
            "-t".to_string(),
            holder_pid.to_string(),
            "-U".to_string(),
            "-n".to_string(),
            "--preserve-credentials".to_string(),
            "--".to_string(),
        ]
    }

    /// Build holder command (same as slirp)
    pub fn build_holder_command(&self) -> Vec<String> {
        vec![
            "unshare".to_string(),
            "--user".to_string(),
            "--map-root-user".to_string(),
            "--net".to_string(),
            "--".to_string(),
            "sleep".to_string(),
            "infinity".to_string(),
        ]
    }
}

#[async_trait::async_trait]
impl NetworkManager for PastaNetwork {
    async fn setup(&mut self) -> Result<NetworkConfig> {
        let mac = generate_mac();

        info!(
            vm_id = %self.vm_id,
            guest_ip = %self.guest_ip,
            guest_ipv6 = %self.guest_ipv6,
            "setting up pasta networking with IPv6"
        );

        // Determine DNS server (use slirp's built-in DNS proxy address)
        // With pasta, DNS should work via the host network
        let dns_server = "10.0.2.3".to_string(); // Standard slirp DNS

        let health_check_url = self
            .loopback_ip
            .as_ref()
            .map(|ip| format!("http://{}:8080/", ip));

        Ok(NetworkConfig {
            tap_device: self.tap_device.clone(),
            guest_mac: mac,
            guest_ip: Some(self.guest_ip.clone()),
            host_ip: self.loopback_ip.clone(),
            host_veth: None,
            loopback_ip: self.loopback_ip.clone(),
            health_check_port: None,
            health_check_url,
            dns_server: Some(dns_server),
        })
    }

    async fn post_start(&mut self, vm_pid: u32) -> Result<()> {
        self.start_pasta(vm_pid).await
    }

    async fn cleanup(&mut self) -> Result<()> {
        info!(vm_id = %self.vm_id, "cleaning up pasta resources");

        if let Some(mut child) = self.pasta_process.take() {
            let _ = child.kill().await;
        }

        info!(vm_id = %self.vm_id, "pasta cleanup complete");
        Ok(())
    }

    fn tap_device(&self) -> &str {
        &self.tap_device
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
