#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use self::linux::{TAPDevice, TUNDevice};

pub mod config;
pub use config::{TAPDeviceConfiguration, TUNDeviceConfiguration};

pub mod error;
pub use error::DeviceError;
