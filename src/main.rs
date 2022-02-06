use env_logger::Env;
use libc::{setgid, setuid};
use serde::Deserialize;
use std::sync::Arc;
use tokio;

mod connector;
mod payload;
mod platform;
mod processor;

use connector::*;
use platform::*;
use processor::*;

// TODO: Think about how to create networks to use
// TODO: Debug IPv4/IPv6 packets from TAP device

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Mode {
    ClientServer,
    P2P,
}

#[derive(Debug, Deserialize)]
struct ClientServerConfiguration {
    #[serde(skip)]
    uid: u32,
    #[serde(skip)]
    gid: u32,
}

#[derive(Debug, Deserialize)]
struct P2PConfiguration {
    #[serde(skip)]
    uid: u32,
    #[serde(skip)]
    gid: u32,
    #[serde(rename = "tunnel_configuration")]
    tunnel_cfg: TunnelConfiguration,
    #[serde(rename = "lan_configuration")]
    lan_cfg: LanConfiguration,
}

#[derive(Debug, Deserialize)]
struct Configuration {
    uid: u32,
    gid: u32,
    mode: Mode,
    #[serde(rename = "client_server_configuration")]
    client_server_cfg: Option<ClientServerConfiguration>,
    #[serde(rename = "p2p_configuration")]
    p2p_cfg: Option<P2PConfiguration>,
}

#[derive(Debug, thiserror::Error)]
pub enum SetupError {
    #[error("{0}")]
    UnexpectedError(String),
}

fn main() {
    // Initialize logger.
    env_logger::Builder::from_env(Env::default().default_filter_or("debug")).init();

    // Parse configuration.
    let cfg_json = r#"{
        "uid": 1000,
        "gid": 1000,
        "mode": "p2p",
        "p2p_configuration": {
            "tunnel_configuration": {
                "mode": "listener",
                "protocol": "UDP",
                "address": "0.0.0.0:9000",
                "buffer_size": 1000
            },
            "lan_configuration": {
                "buffer_size": 1000,
                "device_configuration": {
                    "device_type": "TUN",
                    "address": "10.0.0.0",
                    "destination": "10.0.1.0",
                    "netmask": "255.255.255.0"
                }
            }
        }
    }"#;

    let cfg = parse_config(&cfg_json).expect("Failed parsing configuration");

    // Prepare signal handlers.
    let (shutdown_tx, shutdown_rx) = tokio::sync::mpsc::channel(1);

    ctrlc::set_handler(move || {
        shutdown_tx.blocking_send(());
    })
    .expect("Error setting Ctrl-C handler");

    // Start VPN.
    match cfg.mode {
        Mode::ClientServer => {
            let mut client_server_cfg = match cfg.client_server_cfg {
                Some(cfg) => cfg,
                None => {
                    panic!("Client-server configuration missing");
                }
            };

            client_server_cfg.uid = cfg.uid;
            client_server_cfg.gid = cfg.gid;
            run_client_server(shutdown_rx, &client_server_cfg)
                .expect("Unable to run VPN in ClientServer mode.");
        }
        Mode::P2P => {
            let mut p2p_cfg = match cfg.p2p_cfg {
                Some(cfg) => cfg,
                None => {
                    panic!("P2P configuration missing");
                }
            };

            p2p_cfg.uid = cfg.uid;
            p2p_cfg.gid = cfg.gid;
            run_p2p(shutdown_rx, &p2p_cfg).expect("Unable to run VPN in P2P mode.");
        }
    }
}

fn parse_config(json: &str) -> Result<Configuration, Box<dyn std::error::Error>> {
    let cfg: Configuration = serde_json::from_str(json)?;
    Ok(cfg)
}

fn run_client_server(
    _shutdown_rx: tokio::sync::mpsc::Receiver<()>,
    _cfg: &ClientServerConfiguration,
) -> Result<(), Box<dyn std::error::Error>> {
    // TODO
    Ok(())
}

fn run_p2p(
    mut shutdown_rx: tokio::sync::mpsc::Receiver<()>,
    cfg: &P2PConfiguration,
) -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_io()
        .worker_threads(4)
        .build()?;

    let tunnel = match cfg.tunnel_cfg.protocol {
        TransportLayerProtocol::TCP => {
            Box::new(TCPConnector::new(cfg.tunnel_cfg)?) as Box<dyn Connector>
        }
        TransportLayerProtocol::UDP => {
            Box::new(UDPConnector::new(cfg.tunnel_cfg, runtime.handle().clone())?)
                as Box<dyn Connector>
        }
    };

    let device_cfg = cfg.lan_cfg.device_cfg;
    let device = Arc::new(Device::new(device_cfg, runtime.handle().clone())?);
    let lan = Box::new(TUNTAPConnector::new(
        cfg.lan_cfg,
        runtime.handle().clone(),
        device,
    )?) as Box<dyn Connector>;

    // Start tunnel handler, lan device handler, and the processor.
    let (tunnel_shutdown_tx, tunnel_shutdown_rx) = tokio::sync::mpsc::channel(1);
    let (tunnel_tx, tunnel_rx) = tunnel.start(tunnel_shutdown_rx)?;

    let (lan_shutdown_tx, lan_shutdown_rx) = tokio::sync::mpsc::channel(1);
    let (lan_tx, lan_rx) = lan.start(lan_shutdown_rx)?;

    let processor_cfg = ProcessorConfiguration {
        tunnel_tx: tunnel_tx,
        tunnel_rx: tunnel_rx,
        lan_tx: lan_tx,
        lan_rx: lan_rx,
    };

    let processor = Processor::new(runtime.handle().clone())?;
    let (processor_shutdown_tx, processor_shutdown_rx) = tokio::sync::mpsc::channel(1);
    processor.start(processor_shutdown_rx, processor_cfg)?;

    drop_priviliges(cfg.uid, cfg.gid)?;

    // Wait for the interrupt signal.
    shutdown_rx.blocking_recv();

    // Send shutdown signals to all components.
    let _ = tunnel_shutdown_tx.blocking_send(());
    let _ = lan_shutdown_tx.blocking_send(());
    let _ = processor_shutdown_tx.blocking_send(());

    // TODO: Wait for the components to finish.

    Ok(())
}

// Drop root priviliges.
// TODO: Couldn't make this work with capabilities, as we need to write to
// /proc/sys/net/ipv6/conf/device_name/router_solicitations.
fn drop_priviliges(uid: u32, gid: u32) -> Result<(), Box<dyn std::error::Error>> {
    match unsafe { setgid(gid) } {
        0 => {}
        -1 => return Err(Box::new(std::io::Error::last_os_error())),
        _ => unreachable!("failed dropping priviliges"),
    }

    match unsafe { setuid(uid) } {
        0 => {}
        -1 => return Err(Box::new(std::io::Error::last_os_error())),
        _ => unreachable!("failed dropping priviliges"),
    }

    Ok(())
}
