use etherparse::{Ethernet2HeaderSlice, Ipv4HeaderSlice};
use log::debug;
use std::sync::Arc;
use tokio;

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
    filter: Arc<dyn Filter + Send + Sync>,
}

impl Processor {
    pub fn new(runtime: tokio::runtime::Handle) -> Result<Self, ProcessorError> {
        let filter = Arc::new(DebugFilter::new(None));

        Ok(Processor {
            runtime: runtime,
            filter: filter as Arc<dyn Filter + Send + Sync>,
        })
    }

    pub fn start(
        &self,
        mut shutdown_rx: tokio::sync::mpsc::Receiver<()>,
        mut cfg: ProcessorConfiguration,
    ) -> Result<(), ProcessorError> {
        let runtime = self.runtime.clone();

        let f = self.filter.clone();

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

                        f.filter(&mut payload, PacketOrigin::LAN);

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

                        f.filter(&mut payload, PacketOrigin::TUNNEL);

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
    fn filter(&self, payload: &mut Payload, origin: PacketOrigin);
}

struct DebugFilter {
    next: Option<Box<dyn Filter + Send + Sync>>,
}

impl DebugFilter {
    fn new(next: Option<Box<dyn Filter + Send + Sync>>) -> DebugFilter {
        return DebugFilter { next: next };
    }

    fn try_parse_layer_3(&self, data: &[u8]) -> bool {
        let header = match Ipv4HeaderSlice::from_slice(data) {
            Ok(header) => header,
            Err(_) => {
                return false;
            }
        };

        let source_addr = header.source_addr();
        let dest_addr = header.destination_addr();
        let protocol = header.protocol();

        debug!(
            "Packet received from: {:?}, destined to: {:?}, protocol: {:?}",
            source_addr, dest_addr, protocol
        );

        true
    }

    fn try_parse_layer_2(&self, data: &[u8]) -> bool {
        let header = match Ethernet2HeaderSlice::from_slice(data) {
            Ok(header) => header,
            Err(_) => {
                return false;
            }
        };

        let source_addr = header.source();
        let dest_addr = header.destination();
        let ether_type = header.ether_type();
        let ether_type_enum = match etherparse::EtherType::from_u16(ether_type) {
            Some(t) => t,
            None => return false,
        };

        if data.len() < 18 {
            return false;
        }

        let layer_3_data_start = 14;
        let layer_3_data_end = data.len() - 4;
        let l3_layer_data = &data[layer_3_data_start..layer_3_data_end];
        if !self.try_parse_layer_3(&l3_layer_data) {
            debug!(
                "Frame received from: {:?}, destined to: {:?}, ether_type: {:?}",
                source_addr, dest_addr, ether_type_enum
            );
        }

        true
    }
}

impl Filter for DebugFilter {
    fn filter(&self, payload: &mut Payload, origin: PacketOrigin) {
        let is_packet = self.try_parse_layer_3(&payload.data);
        let is_frame = self.try_parse_layer_2(&payload.data);
        if !is_packet && !is_frame {
            debug!("Received payload is not a Layer 2 or a Layer 3 payload!")
        }

        match &self.next {
            Some(f) => f.filter(payload, origin),
            None => {}
        }
    }
}
