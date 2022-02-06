use serde::Deserialize;

#[derive(Debug, Copy, Clone, Deserialize)]
pub enum DeviceType {
    TUN,
    TAP,
}

#[derive(Debug, Copy, Clone, Deserialize)]
pub struct DeviceConfiguration {
    pub device_type: DeviceType,
    pub address: std::net::IpAddr,
    pub netmask: std::net::IpAddr,
    pub destination: std::net::IpAddr,
}
