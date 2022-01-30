use log::{debug, error};
use serde::Deserialize;
use std::sync::Arc;
use tokio;

use crate::payload::*;
use crate::platform::{config::*, error::*, TAPDevice, TUNDevice};

const MAX_DATAGRAM_SIZE: usize = 65535;
const MAX_MTU_SIZE: usize = 1500;

#[derive(Debug, Copy, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TunnelMode {
    Listener,
    Client,
}

#[derive(Debug, Copy, Clone, Deserialize)]
pub enum TransportLayerProtocol {
    TCP,
    UDP,
}

#[derive(Debug, Copy, Clone, Deserialize)]
pub struct TunnelConfiguration {
    pub mode: TunnelMode,
    pub protocol: TransportLayerProtocol,
    pub address: std::net::SocketAddr,
    pub buffer_size: usize,
}

#[derive(Debug, Copy, Clone, Deserialize)]
pub enum LanDeviceMode {
    TUN,
    TAP,
}

#[derive(Debug, Copy, Clone, Deserialize)]
pub struct LanConfiguration {
    pub mode: LanDeviceMode,
    pub buffer_size: usize,
    #[serde(rename = "tun_configuration")]
    pub tun_cfg: Option<TUNDeviceConfiguration>,
    #[serde(rename = "tap_configuration")]
    pub tap_cfg: Option<TAPDeviceConfiguration>,
}

#[derive(Debug, thiserror::Error)]
pub enum ConnectorError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error("{1}")]
    UnexpectedError(#[source] Box<dyn std::error::Error>, String),
}

pub trait Connector {
    fn start(
        &self,
        shutdown_rx: tokio::sync::mpsc::Receiver<()>,
    ) -> Result<
        (
            tokio::sync::mpsc::Sender<Payload>,
            tokio::sync::mpsc::Receiver<Payload>,
        ),
        ConnectorError,
    >;
}

pub struct UDPConnector {
    socket: Arc<tokio::net::UdpSocket>,
    runtime: tokio::runtime::Handle,
    cfg: TunnelConfiguration,
}

impl UDPConnector {
    pub fn new(
        cfg: TunnelConfiguration,
        runtime: tokio::runtime::Handle,
    ) -> Result<Self, ConnectorError> {
        let std_sock = std::net::UdpSocket::bind(cfg.address)?;
        std_sock.set_nonblocking(true)?;

        let _guard = runtime.enter();
        let sock = Arc::new(tokio::net::UdpSocket::from_std(std_sock)?);

        // TODO: Set socket timeouts and handle them.

        Ok(UDPConnector {
            cfg: cfg,
            runtime: runtime,
            socket: sock,
        })
    }
}

impl Connector for UDPConnector {
    fn start(
        &self,
        mut shutdown_rx: tokio::sync::mpsc::Receiver<()>,
    ) -> Result<
        (
            tokio::sync::mpsc::Sender<Payload>,
            tokio::sync::mpsc::Receiver<Payload>,
        ),
        ConnectorError,
    > {
        let (in_tx, in_rx) = tokio::sync::mpsc::channel::<Payload>(self.cfg.buffer_size);
        let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<Payload>(self.cfg.buffer_size);

        let socket = self.socket.clone();
        let runtime = self.runtime.clone();

        self.runtime.spawn(async move {
            let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];
            loop {
                tokio::select! {
                    result = socket.recv_from(&mut buf) => {
                        let (len, addr) = match result {
                            Ok((len, addr)) => (len, addr),
                            Err(err) => {
                                // TODO: Improve handling here.
                                error!("Failed receiving from socket: {}", err);
                                continue;
                            }
                        };

                        let payload = Payload{
                            data: buf[..len].into(),
                        };

                        debug!("Received data on UDP socket: {}", len);

                        let in_tx = in_tx.clone();
                        runtime.spawn(async move {
                            in_tx.send(payload).await;
                        });
                    },
                    payload_opt = out_rx.recv() => {
                        let payload = match payload_opt {
                            Some(payload) => payload,
                            None => {
                                continue;
                            }
                        };

                        debug!("Sending data to UDP socket: {}", payload.data.len());

                        let socket = socket.clone();
                        runtime.spawn(async move {
                            socket.send(&payload.data).await;
                        });
                    },
                    _ = shutdown_rx.recv() => {
                        return
                    },
                };
            }
        });

        Ok((out_tx, in_rx))
    }
}

pub struct TCPConnector {
    cfg: TunnelConfiguration,
}

impl TCPConnector {
    pub fn new(cfg: TunnelConfiguration) -> Result<Self, ConnectorError> {
        Ok(TCPConnector { cfg: cfg })
    }
}

impl Connector for TCPConnector {
    fn start(
        &self,
        shutdown_rx: tokio::sync::mpsc::Receiver<()>,
    ) -> Result<
        (
            tokio::sync::mpsc::Sender<Payload>,
            tokio::sync::mpsc::Receiver<Payload>,
        ),
        ConnectorError,
    > {
        let (in_tx, in_rx) = tokio::sync::mpsc::channel(self.cfg.buffer_size);
        let (out_tx, out_rx) = tokio::sync::mpsc::channel(self.cfg.buffer_size);

        // TODO
        Ok((out_tx, in_rx))
    }
}

pub struct TUNConnector {
    cfg: LanConfiguration,
    device: Arc<TUNDevice>,
    runtime: tokio::runtime::Handle,
}

impl TUNConnector {
    pub fn new(
        cfg: LanConfiguration,
        runtime: tokio::runtime::Handle,
        device: Arc<TUNDevice>,
    ) -> Result<Self, DeviceError> {
        Ok(TUNConnector {
            cfg: cfg,
            device: device,
            runtime: runtime,
        })
    }
}

impl Connector for TUNConnector {
    fn start(
        &self,
        mut shutdown_rx: tokio::sync::mpsc::Receiver<()>,
    ) -> Result<
        (
            tokio::sync::mpsc::Sender<Payload>,
            tokio::sync::mpsc::Receiver<Payload>,
        ),
        ConnectorError,
    > {
        let (in_tx, in_rx) = tokio::sync::mpsc::channel::<Payload>(self.cfg.buffer_size);
        let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<Payload>(self.cfg.buffer_size);

        let device = self.device.clone();
        let runtime = self.runtime.clone();

        self.runtime.spawn(async move {
            let mut buf = vec![0u8; MAX_MTU_SIZE];

            loop {
                tokio::select! {
                    result = device.read(&mut buf) => {
                        let len = match result {
                            Ok(len) => len,
                            Err(err) => {
                                // TODO: Improve handling here.
                                error!("Failed receiving from socket: {}", err);
                                continue;
                            }
                        };

                        let payload = Payload{
                            data: buf[..len].into(),
                        };

                        debug!("Received data on TUN device: {}", len);

                        let in_tx = in_tx.clone();
                        runtime.spawn(async move {
                            in_tx.send(payload).await;
                        });
                    },
                    payload_opt = out_rx.recv() => {
                        let mut payload = match payload_opt {
                            Some(payload) => payload,
                            None => {
                                continue;
                            }
                        };

                        debug!("Sending data to TUN device: {}", payload.data.len());

                        let device = device.clone();
                        runtime.spawn(async move {
                            device.write(&mut payload.data).await;
                        });
                    },
                    _ = shutdown_rx.recv() => {
                        return
                    },
                };
            }
        });

        Ok((out_tx, in_rx))
    }
}

pub struct TAPConnector {
    device: TAPDevice,
}

impl TAPConnector {
    pub fn new(device: TAPDevice) -> Result<Self, DeviceError> {
        Ok(TAPConnector { device: device })
    }
}

impl Connector for TAPConnector {
    fn start(
        &self,
        shutdown_rx: tokio::sync::mpsc::Receiver<()>,
    ) -> Result<
        (
            tokio::sync::mpsc::Sender<Payload>,
            tokio::sync::mpsc::Receiver<Payload>,
        ),
        ConnectorError,
    > {
        let (in_tx, in_rx) = tokio::sync::mpsc::channel::<Payload>(100); // TODO
        let (out_tx, out_rx) = tokio::sync::mpsc::channel::<Payload>(100); // TODO

        Ok((out_tx, in_rx))
    }
}
