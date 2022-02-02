use tokio;
use std::sync::Arc;

use crate::payload::*;

pub struct ProcessorConfiguration {
    pub tunnel_tx: tokio::sync::mpsc::Sender<Payload>,
    pub tunnel_rx: tokio::sync::mpsc::Receiver<Payload>,
    pub lan_tx: tokio::sync::mpsc::Sender<Payload>,
    pub lan_rx: tokio::sync::mpsc::Receiver<Payload>,
}

#[derive(Debug, thiserror::Error)]
pub enum ProcessorError {
    #[error("{1}")]
    UnexpectedError(#[source] Box<dyn std::error::Error>, String),
}

pub struct Processor {
    runtime: tokio::runtime::Handle,
}

impl Processor {
    pub fn new(runtime: tokio::runtime::Handle) -> Result<Self, ProcessorError> {
        Ok(Processor { 
            runtime: runtime,
        })
    }

    pub fn start(
        &self,
        mut shutdown_rx: tokio::sync::mpsc::Receiver<()>,
        mut cfg: ProcessorConfiguration,
    ) -> Result<(), ProcessorError> {
        let runtime = self.runtime.clone();

        self.runtime.spawn(async move {
            loop {
                tokio::select! {
                    payload_opt = cfg.lan_rx.recv() => {
                        let mut payload = match payload_opt {
                            Some(payload) => payload,
                            None => {
                                continue;
                            }
                        };

                        let tunnel_tx = cfg.tunnel_tx.clone();
                        runtime.spawn(async move {
                            tunnel_tx.send(payload).await;
                        });
                    },
                    payload_opt = cfg.tunnel_rx.recv() => {
                        let mut payload = match payload_opt {
                            Some(payload) => payload,
                            None => {
                                continue;
                            }
                        };

                        let lan_tx = cfg.lan_tx.clone();
                        runtime.spawn(async move {
                            lan_tx.send(payload).await;
                        });
                    },
                    _ = shutdown_rx.recv() => {
                        return
                    },
                }
            }
        });

        Ok(())
    }
}

pub enum PacketOrigin {
    LAN,
    TUNNEL,
}

pub trait Filter {
    fn filter(&self, payload: *mut Payload, origin: PacketOrigin);
}

struct DebugFilter {}

impl DebugFilter {
    fn new() -> DebugFilter {
        return DebugFilter{}
    }
}

impl Filter for DebugFilter {
    fn filter(&self, payload: *mut Payload, origin: PacketOrigin) {

    }
}
