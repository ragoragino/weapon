#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use self::linux::{
    TUNDevice, 
    TAPDevice,
};

pub mod config;
pub use config::{
    TAPDeviceConfiguration, 
    TUNDeviceConfiguration,
};

pub mod error;
pub use error::DeviceError;