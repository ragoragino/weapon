#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub use self::linux::Device;

pub mod config;
pub use config::DeviceConfiguration;

pub mod error;
pub use error::DeviceError;
