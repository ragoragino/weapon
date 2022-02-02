use serde::Deserialize;

#[derive(Debug, Copy, Clone, Deserialize)]
pub struct TUNDeviceConfiguration {
    pub address: std::net::IpAddr,
    pub netmask: std::net::IpAddr,
    pub destination: std::net::IpAddr,
}

#[derive(Debug, Copy, Clone, Deserialize)]
pub struct TAPDeviceConfiguration {}
