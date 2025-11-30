mod cli;
mod error;
mod state;
mod firecracker;
mod disk;
mod network;
mod mmds;
mod snapshot;
mod vm_manager;

use anyhow::{Result, Context};
use clap::Parser;
use cli::{Cli, Commands, RunArgs, CloneArgs, NameArgs};
use state::{Mode, Publish};
use vm_manager::VmManager;
use std::str::FromStr;
use tracing::{info, error};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into())
        )
        .init();

    let cli = Cli::parse();

    let result = match cli.cmd {
        Commands::Run(args) => cmd_run(args).await,
        Commands::Clone(args) => cmd_clone(args).await,
        Commands::Stop(args) => cmd_stop(args).await,
        Commands::Ls => cmd_ls().await,
        Commands::Inspect(args) => cmd_inspect(args).await,
        Commands::Logs(args) => cmd_logs(args).await,
        Commands::Top => cmd_top().await,
    };

    if let Err(e) = &result {
        error!("Command failed: {}", e);
        std::process::exit(1);
    }

    Ok(())
}

async fn cmd_run(args: RunArgs) -> Result<()> {
    info!("Starting VM with image: {}", args.image);

    let vm_mgr = VmManager::new()
        .context("Failed to create VM manager")?;
    vm_mgr.init().await
        .context("Failed to initialize VM manager")?;

    // Parse publish args
    let publishes = parse_publishes(&args.publish)?;

    // Convert mode
    let mode = match args.mode {
        cli::ModeOpt::Auto => Mode::Auto,
        cli::ModeOpt::Privileged => Mode::Privileged,
        cli::ModeOpt::Rootless => Mode::Rootless,
    };

    // Start the VM
    let vm = vm_mgr
        .run_vm(
            args.name,
            args.image.clone(),
            args.cpu,
            args.mem,
            mode,
            publishes,
            args.balloon,
            args.save_snapshot,
        )
        .await
        .context("Failed to run VM")?;

    info!("✓ VM '{}' is running (ID: {})", vm.name, vm.id);
    info!("  Image: {}", vm.image);
    info!("  Mode: {:?}", vm.mode);
    info!("  CPU: {}, Memory: {} MiB", vm.cpu, vm.mem);

    if let Some(net) = &vm.network {
        info!("  Guest IP: {}", net.guest_ip);
    }

    if !vm.publish.is_empty() {
        info!("  Published ports:");
        for p in &vm.publish {
            let host = p.host_ip.as_deref().unwrap_or("0.0.0.0");
            info!("    {}:{} -> {} ({:?})", host, p.host_port, p.guest_port, p.proto);
        }
    }

    // Wait for VM (tie lifetime to this process)
    info!("\nVM is running. Press Ctrl+C to stop.");

    tokio::signal::ctrl_c().await?;

    info!("\nStopping VM...");
    vm_mgr.stop_vm(&vm.name).await
        .context("Failed to stop VM")?;

    info!("VM stopped");
    Ok(())
}

async fn cmd_clone(args: CloneArgs) -> Result<()> {
    info!("Cloning VM from snapshot: {}", args.snapshot);

    let vm_mgr = VmManager::new()
        .context("Failed to create VM manager")?;
    vm_mgr.init().await
        .context("Failed to initialize VM manager")?;

    // Parse publish args
    let publishes = parse_publishes(&args.publish)?;

    // Clone the VM
    let vm = vm_mgr
        .clone_vm(
            args.snapshot,
            args.name,
            publishes,
        )
        .await
        .context("Failed to clone VM")?;

    info!("✓ VM '{}' cloned successfully (ID: {})", vm.name, vm.id);
    info!("  Mode: {:?}", vm.mode);

    if let Some(net) = &vm.network {
        info!("  Guest IP: {}", net.guest_ip);
    }

    if !vm.publish.is_empty() {
        info!("  Published ports:");
        for p in &vm.publish {
            let host = p.host_ip.as_deref().unwrap_or("0.0.0.0");
            info!("    {}:{} -> {} ({:?})", host, p.host_port, p.guest_port, p.proto);
        }
    }

    // Wait for VM (tie lifetime to this process)
    info!("\nVM is running. Press Ctrl+C to stop.");

    tokio::signal::ctrl_c().await?;

    info!("\nStopping VM...");
    vm_mgr.stop_vm(&vm.name).await
        .context("Failed to stop VM")?;

    info!("VM stopped");
    Ok(())
}

async fn cmd_stop(args: NameArgs) -> Result<()> {
    let vm_mgr = VmManager::new()?;

    info!("Stopping VM: {}", args.name);
    vm_mgr.stop_vm(&args.name).await?;

    info!("✓ VM '{}' stopped", args.name);
    Ok(())
}

async fn cmd_ls() -> Result<()> {
    let vm_mgr = VmManager::new()?;
    let vms = vm_mgr.list_vms().await?;

    if vms.is_empty() {
        println!("No running VMs");
        return Ok(());
    }

    println!("{:<20} {:<36} {:<15} {:<10} {:<8}",
             "NAME", "ID", "IMAGE", "STATUS", "MODE");
    println!("{}", "-".repeat(95));

    for vm in vms {
        let image_short = if vm.image.len() > 14 {
            format!("{}...", &vm.image[..11])
        } else {
            vm.image.clone()
        };

        println!("{:<20} {:<36} {:<15} {:<10} {:<8}",
                 vm.name, vm.id, image_short, format!("{:?}", vm.status), format!("{:?}", vm.mode));
    }

    Ok(())
}

async fn cmd_inspect(args: NameArgs) -> Result<()> {
    let vm_mgr = VmManager::new()?;
    let vm = vm_mgr.get_vm(&args.name).await?;

    println!("VM Details:");
    println!("  Name: {}", vm.name);
    println!("  ID: {}", vm.id);
    println!("  Image: {}", vm.image);
    println!("  Status: {:?}", vm.status);
    println!("  Mode: {:?}", vm.mode);
    println!("  CPU: {}", vm.cpu);
    println!("  Memory: {} MiB", vm.mem);

    if let Some(balloon) = vm.balloon {
        println!("  Balloon: {} MiB", balloon);
    }

    if let Some(net) = &vm.network {
        println!("\nNetwork:");
        println!("  Guest IP: {}", net.guest_ip);
        println!("  Gateway: {}", net.gateway);
        if let Some(tap) = &net.tap_device {
            println!("  TAP Device: {}", tap);
        }
    }

    if !vm.publish.is_empty() {
        println!("\nPublished Ports:");
        for p in &vm.publish {
            let host = p.host_ip.as_deref().unwrap_or("0.0.0.0");
            println!("  {}:{} -> {} ({:?})", host, p.host_port, p.guest_port, p.proto);
        }
    }

    if !vm.maps.is_empty() {
        println!("\nVolume Mounts:");
        for m in &vm.maps {
            let ro = if m.readonly { " (ro)" } else { "" };
            println!("  {:?} -> {:?}{}", m.host_path, m.guest_path, ro);
        }
    }

    println!("\nCreated: {}", vm.created_at.format("%Y-%m-%d %H:%M:%S"));
    println!("Socket: {:?}", vm.socket_path);
    println!("Rootfs: {:?}", vm.rootfs_path);

    Ok(())
}

async fn cmd_logs(args: NameArgs) -> Result<()> {
    println!("(stub) logs for VM: {}", args.name);
    println!("Note: Logs are currently streamed to the console during VM runtime");
    Ok(())
}

async fn cmd_top() -> Result<()> {
    let vm_mgr = VmManager::new()?;
    let vms = vm_mgr.list_vms().await?;

    if vms.is_empty() {
        println!("No running VMs");
        return Ok(());
    }

    println!("VM Resource Usage:");
    println!("{:<20} {:<8} {:<10} {:<10}", "NAME", "CPU", "MEMORY", "STATUS");
    println!("{}", "-".repeat(50));

    for vm in vms {
        println!("{:<20} {:<8} {:<10} {:<10}",
                 vm.name,
                 vm.cpu,
                 format!("{} MB", vm.mem),
                 format!("{:?}", vm.status));
    }

    Ok(())
}

fn parse_publishes(publishes: &[String]) -> Result<Vec<Publish>> {
    let mut result = Vec::new();

    for p_str in publishes {
        let publish = Publish::from_str(p_str)
            .map_err(|e| anyhow::anyhow!("Invalid publish format '{}': {}", p_str, e))?;
        result.push(publish);
    }

    Ok(result)
}
