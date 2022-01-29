use serde::{Deserialize};

#[derive(Debug, Copy, Clone, Deserialize)]
pub struct TUNDeviceConfiguration {
    pub address: std::net::IpAddr,
}

#[derive(Debug, Copy, Clone, Deserialize)]
pub struct TAPDeviceConfiguration {

}