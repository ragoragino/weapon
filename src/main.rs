use env_logger::Env;
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Mode {
    ClientServer,
    P2P,
}

#[derive(Debug, Deserialize)]
struct ClientServerConfiguration {}

#[derive(Debug, Deserialize)]
struct P2PConfiguration {
    #[serde(rename = "tunnel_configuration")]
    tunnel_cfg: TunnelConfiguration,
    #[serde(rename = "lan_configuration")]
    lan_cfg: LanConfiguration,
}

#[derive(Debug, Deserialize)]
struct Configuration {
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
        "mode": "p2p",
        "p2p_configuration": {
            "tunnel_configuration": {
                "mode": "listener",
                "protocol": "UDP",
                "address": "0.0.0.0:9000",
                "buffer_size": 1000
            },
            "lan_configuration": {
                "mode": "TUN",
                "buffer_size": 1000,
                "tun_configuration": {
                    "address": "10.0.0.3",
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
            let cfg = match cfg.client_server_cfg {
                Some(cfg) => cfg,
                None => {
                    panic!("Client-server configuration missing");
                }
            };

            run_client_server(shutdown_rx, &cfg).expect("Unable to run VPN in ClientServer mode.");
        }
        Mode::P2P => {
            let cfg = match cfg.p2p_cfg {
                Some(cfg) => cfg,
                None => {
                    panic!("P2P configuration missing");
                }
            };

            run_p2p(shutdown_rx, &cfg).expect("Unable to run VPN in P2P mode.");
        }
    }
}

fn parse_config(json: &str) -> Result<Configuration, Box<dyn std::error::Error>> {
    let cfg: Configuration = serde_json::from_str(json)?;
    Ok(cfg)
}

fn run_client_server(
    shutdown_rx: tokio::sync::mpsc::Receiver<()>,
    cfg: &ClientServerConfiguration,
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

    let lan = match cfg.lan_cfg.mode {
        LanDeviceMode::TUN => {
            let device_cfg = cfg
                .lan_cfg
                .tun_cfg
                .ok_or(Box::new(SetupError::UnexpectedError(
                    "missing TUN configuration".into(),
                )))?;
            let device = Arc::new(TUNDevice::new(device_cfg, runtime.handle().clone())?);
            Box::new(TUNConnector::new(
                cfg.lan_cfg,
                runtime.handle().clone(),
                device,
            )?) as Box<dyn Connector>
        }
        LanDeviceMode::TAP => {
            let device_cfg = cfg
                .lan_cfg
                .tap_cfg
                .ok_or(Box::new(SetupError::UnexpectedError(
                    "missing TAP configuration".into(),
                )))?;
            let device = TAPDevice::new(device_cfg)?;
            Box::new(TAPConnector::new(device)?) as Box<dyn Connector>
        }
    };

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

    // Wait for the interrupt signal.
    shutdown_rx.blocking_recv();

    // Send shutdown signals to all components.
    let _ = tunnel_shutdown_tx.blocking_send(());
    let _ = lan_shutdown_tx.blocking_send(());
    let _ = processor_shutdown_tx.blocking_send(());

    // TODO: Wait for the components to finish.

    Ok(())
}
