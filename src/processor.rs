use chacha20poly1305::{
    aead::{generic_array::GenericArray, AeadInPlace, NewAead},
    ChaCha20Poly1305, Nonce,
};
use etherparse::{Ethernet2HeaderSlice, Ipv4HeaderSlice};
use log::{debug, error};
use std::collections::BTreeSet;
use std::convert::TryInto;
use std::sync::Mutex;
use tokio;

use crate::payload::*;

pub struct ProcessorConfiguration {
    pub tunnel_tx: tokio::sync::mpsc::Sender<Payload>,
    pub tunnel_rx: tokio::sync::mpsc::Receiver<Payload>,
    pub lan_tx: tokio::sync::mpsc::Sender<Payload>,
    pub lan_rx: tokio::sync::mpsc::Receiver<Payload>,

    pub encryption_key: std::vec::Vec<u8>,
    pub decryption_key: std::vec::Vec<u8>,
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
        Ok(Processor { runtime: runtime })
    }

    pub fn start(
        &self,
        mut shutdown_rx: tokio::sync::mpsc::Receiver<()>,
        mut cfg: ProcessorConfiguration,
    ) -> Result<(), ProcessorError> {
        let runtime = self.runtime.clone();

        let encryption_filter = Box::new(EncryptionFilter::new(
            cfg.encryption_key,
            cfg.decryption_key,
            None,
        ));
        let mut f = DebugFilter::new(Some(encryption_filter));

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

                        match f.filter(&mut payload, PacketOrigin::LAN) {
                            FilterDecision::ALLOW => {},
                            FilterDecision::DENY(msg) => {
                                debug!("Denying payload: {}", msg);
                                continue
                            },
                        }

                        let tunnel_tx = cfg.tunnel_tx.clone();
                        runtime.spawn(async move {
                            if let Err(_) = tunnel_tx.send(payload).await {
                                error!("Unable to send to tunnel.");
                            }
                        });
                    },
                    payload_opt = cfg.tunnel_rx.recv() => {
                        let mut payload = match payload_opt {
                            Some(payload) => payload,
                            None => {
                                continue;
                            }
                        };

                        match f.filter(&mut payload, PacketOrigin::TUNNEL) {
                            FilterDecision::ALLOW => {},
                            FilterDecision::DENY(msg) => {
                                debug!("Denying payload: {}", msg);
                                continue
                            },
                        }

                        let lan_tx = cfg.lan_tx.clone();
                        runtime.spawn(async move {
                            if let Err(_) = lan_tx.send(payload).await {
                                error!("Unable to send to LAN.");
                            }
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

enum FilterDecision {
    ALLOW,
    DENY(String),
}

trait Filter {
    fn filter(&mut self, payload: &mut Payload, origin: PacketOrigin) -> FilterDecision;
}

struct DebugFilter {
    next: Option<Box<dyn Filter + Send + Sync>>,
}

impl DebugFilter {
    fn new(next: Option<Box<dyn Filter + Send + Sync>>) -> DebugFilter {
        return DebugFilter { next: next };
    }

    fn try_parse_inet(&self, data: &[u8]) -> bool {
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

    fn try_parse_ethernet(&self, data: &[u8]) -> bool {
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
        if !self.try_parse_inet(&l3_layer_data) {
            debug!(
                "Frame received from: {:?}, destined to: {:?}, ether_type: {:?}",
                source_addr, dest_addr, ether_type_enum
            );
        }

        true
    }
}

impl Filter for DebugFilter {
    fn filter(&mut self, payload: &mut Payload, origin: PacketOrigin) -> FilterDecision {
        let is_inet = self.try_parse_inet(&payload.data);
        let is_eth = self.try_parse_ethernet(&payload.data);
        if !is_inet && !is_eth {
            debug!("Received payload is not an IPv4 packet or an Ethernet frame!")
        }

        if let Some(f) = &mut self.next {
            return f.filter(payload, origin);
        }

        FilterDecision::ALLOW
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EncryptionError {
    #[error("{0}")]
    AuthenticationError(String),
}

struct NonceManager {
    counter: u64,
    checkpoint_threshold: u64,
    window: usize,
    previous_nonces: BTreeSet<u64>,
    m: Mutex<i32>,
}

impl NonceManager {
    fn new() -> NonceManager {
        // TODO: Initialize nonce from checkpointing files.

        // TODO: Make this configurable for tests.
        NonceManager {
            counter: 0,
            checkpoint_threshold: 10000,
            window: 2000,
            previous_nonces: BTreeSet::new(),
            m: Mutex::new(0),
        }
    }

    fn mint(&mut self) -> Result<[u8; 12], EncryptionError> {
        let _ = self.m.lock().unwrap();

        let current = self.counter;
        if current % self.checkpoint_threshold == 0 {
            // TODO: Checkpoint to a file
        }

        let nonce = current.to_be_bytes();
        let mut nonce_bytes: std::vec::Vec<u8> = vec![0; 4];
        nonce_bytes.extend(nonce);

        self.counter += 1;

        Ok(nonce_bytes
            .try_into()
            .expect("unable to convert nonce to a 12-byte array"))
    }

    fn verify(&mut self, nonce_bytes: &[u8; 12]) -> Result<bool, EncryptionError> {
        let _ = self.m.lock().unwrap();

        let nonce = u64::from_be_bytes(
            nonce_bytes[4..]
                .try_into()
                .expect("unable to convert nonce into u64 bytes"),
        );

        // We don't allow replaying the same payloads.
        if self.previous_nonces.contains(&nonce) {
            return Ok(false);
        }

        // We allow all payloads when we don't have window-sized payload.
        // This allows for a possible attack - if the program crashes and then restarts,
        // as it won't remember the payloads it has seen before the checkpoint.
        // TODO: Having a control channel between the two tunnel endpoints would be useful
        // as we could negotiate the new nonce based on the last checkpoint.
        if self.previous_nonces.len() == self.window {
            let min = match self.previous_nonces.iter().next() {
                Some(i) => *i,
                None => 0,
            };

            // This is either a replayed payload or a delyed one.
            // We nonetheless deny it.
            if nonce < min {
                return Ok(false);
            }

            self.previous_nonces.remove(&min);

            // TODO: Write a new checkpoint if required.
        }

        self.previous_nonces.insert(nonce);

        Ok(true)
    }
}

// MAC: 16b, NONCE: 12b
struct EncryptionFilter {
    encrypt_key: std::vec::Vec<u8>,
    decrypt_key: std::vec::Vec<u8>,
    next: Option<Box<dyn Filter + Send + Sync>>,
    nonce_manager: NonceManager,
}

// https://crypto.stackexchange.com/questions/76365/how-does-aead-guarantee-authenticated-encryption-and-plain-aes-does-not
// https://boringssl.googlesource.com/boringssl/+/2970779684c6f164a0e261e96a3d59f331123320/crypto/cipher/aead.h
// https://crypto.stackexchange.com/questions/70686/how-to-prevent-accidental-nonce-reuse-with-aead-cipher
// https://github.com/SergioBenitez/cookie-rs/blob/master/src/secure/private.rs
impl EncryptionFilter {
    fn new(
        encrypt_key: std::vec::Vec<u8>,
        decrypt_key: std::vec::Vec<u8>,
        next: Option<Box<dyn Filter + Send + Sync>>,
    ) -> Self {
        Self {
            encrypt_key: encrypt_key,
            decrypt_key: decrypt_key,
            next: next,
            nonce_manager: NonceManager::new(),
        }
    }

    // ciphertext | tag | nonce
    fn seal(&mut self, data: &mut std::vec::Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
        let mut nonce_bytes = self.nonce_manager.mint()?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&self.encrypt_key));
        cipher.encrypt_in_place(&nonce, b"", data).map_err(|err| {
            ProcessorError::UnexpectedError(Box::new(err), "unable to encrypt the payload".into())
        })?;
        data.extend_from_slice(&mut nonce_bytes);

        Ok(())
    }

    fn open(&mut self, data: &mut std::vec::Vec<u8>) -> Result<(), EncryptionError> {
        if data.len() < 12 {
            return Err(EncryptionError::AuthenticationError(
                "payload missing nonce".into(),
            ));
        }

        let nonce_start = data.len() - 12;
        let nonce = Nonce::clone_from_slice(&data[nonce_start..]);
        data.truncate(nonce_start);

        let is_nonce_valid = self.nonce_manager.verify(
            nonce
                .as_slice()
                .try_into()
                .expect("nonce doesn't have the correct length"),
        )?;
        if !is_nonce_valid {
            return Err(EncryptionError::AuthenticationError("invalid nonce".into()));
        }

        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&self.decrypt_key));
        cipher.decrypt_in_place(&nonce, b"", data).map_err(|err| {
            EncryptionError::AuthenticationError(format!("unable to decrypt the payload: {}", err))
        })?;

        Ok(())
    }
}

impl Filter for EncryptionFilter {
    fn filter(&mut self, payload: &mut Payload, origin: PacketOrigin) -> FilterDecision {
        match origin {
            PacketOrigin::TUNNEL => {
                match self.open(&mut payload.data) {
                    Ok(_) => {}
                    Err(err) => {
                        return FilterDecision::DENY(format!(
                            "unable to open the payload: {:?}",
                            err
                        ))
                    }
                };
            }
            PacketOrigin::LAN => {
                match self.seal(&mut payload.data) {
                    Ok(_) => {}
                    Err(err) => {
                        return FilterDecision::DENY(format!(
                            "unable to seal the payload: {:?}",
                            err
                        ))
                    }
                };
            }
        }

        if let Some(f) = &mut self.next {
            return f.filter(payload, origin);
        }

        FilterDecision::ALLOW
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::{RngCore, SeedableRng};

    #[test]
    fn test_encryption_filter_success() {
        let mut r = StdRng::seed_from_u64(42);

        let mut encryption_key = vec![0; 32];
        r.fill_bytes(&mut encryption_key);
        let decryption_key = encryption_key.clone();

        let mut f = EncryptionFilter::new(encryption_key, decryption_key, None);

        let mut payload = vec![72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100];
        let expected_payload = payload.clone();

        f.seal(&mut payload).expect("unable to seal the payload");
        assert_ne!(expected_payload, payload);

        f.open(&mut payload).expect("unable to open the payload");
        assert_eq!(expected_payload, payload);
    }

    #[test]
    fn test_encryption_filter_tampering() {
        let mut r = StdRng::seed_from_u64(42);

        let mut encryption_key = vec![0; 32];
        r.fill_bytes(&mut encryption_key);
        let decryption_key = encryption_key.clone();

        let mut f = EncryptionFilter::new(encryption_key, decryption_key, None);

        let mut payload = vec![72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100];
        let expected_payload = payload.clone();

        f.seal(&mut payload).expect("unable to seal the payload");
        assert_ne!(expected_payload, payload);

        payload[5] = 38;
        match f.open(&mut payload) {
            Ok(_) => assert!(false, "expected an error"),
            Err(err) => assert!(true, "received an error: {:?}", err),
        }
    }

    #[test]
    fn test_encryption_filter_replay() {
        let mut r = StdRng::seed_from_u64(42);

        let mut encryption_key = vec![0; 32];
        r.fill_bytes(&mut encryption_key);
        let decryption_key = encryption_key.clone();

        let mut f = EncryptionFilter::new(encryption_key, decryption_key, None);

        let mut payload = vec![72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100];
        let expected_payload = payload.clone();

        f.seal(&mut payload).expect("unable to seal the payload");
        let mut replay_payload = payload.clone();

        f.open(&mut payload).expect("unable to open the payload");
        assert_eq!(expected_payload, payload);

        match f.open(&mut replay_payload) {
            Ok(_) => assert!(false, "expected an error"),
            Err(err) => assert!(true, "received an error: {:?}", err),
        }
    }

    // TODO: Test checkpoints
}
