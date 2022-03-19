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

// TODO: Debug IPv4/IPv6 packets from TAP device

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
    encryption_key: String,
    decryption_key: String,
}

#[derive(Debug, Deserialize)]
struct Configuration {
    uid: u32,
    gid: u32,
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
        "p2p_configuration": {
            "encryption_key": "K19Zve3fiOdbW+6z1Mh70XjaVw5maJFps0aLwMVrYIE=",
            "decryption_key": "fbapi8HbKIFjnUg98W+AAKau0/zIHdW4Hh156EJTijs=",
            "tunnel_configuration": {
                "mode": "listener",
                "protocol": "UDP",
                "address": "0.0.0.0:9000",
                "peer_address": "192.168.1.113:9000",
                "buffer_size": 1000
            },
            "lan_configuration": {
                "buffer_size": 1000,
                "device_configuration": {
                    "device_type": "TUN",
                    "address": "172.16.0.0",
                    "destination": "172.18.0.0",
                    "netmask": "255.254.0.0",
                    "mtu": 1472
                }
            }
        }
    }"#;

    let cfg = parse_config(&cfg_json).expect("Failed parsing configuration");

    // Prepare signal handlers.
    let (shutdown_tx, shutdown_rx) = tokio::sync::mpsc::channel(1);

    ctrlc::set_handler(move || {
        shutdown_tx
            .blocking_send(())
            .expect("unable to send to shutdown channel");
    })
    .expect("Error setting Ctrl-C handler");

    // Start VPN.
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

fn parse_config(json: &str) -> Result<Configuration, Box<dyn std::error::Error>> {
    let cfg: Configuration = serde_json::from_str(json)?;
    Ok(cfg)
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

    let encryption_key = base64::decode(&cfg.encryption_key)?;
    let decryption_key = base64::decode(&cfg.decryption_key)?;

    let processor_cfg = ProcessorConfiguration {
        tunnel_tx: tunnel_tx,
        tunnel_rx: tunnel_rx,
        lan_tx: lan_tx,
        lan_rx: lan_rx,
        encryption_key: encryption_key,
        decryption_key: decryption_key,
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
