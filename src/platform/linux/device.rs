use libc::{socket, AF_INET, O_RDWR, SOCK_DGRAM};
use tokio::io::unix::AsyncFd;

use crate::platform::linux::{fd::*, sys::*};
use crate::platform::{
    config::TAPDeviceConfiguration, config::TUNDeviceConfiguration, error::DeviceError,
};

pub struct TUNDevice {
    inner: AsyncFd<Fd>,
}

impl TUNDevice {
    pub fn new(
        cfg: TUNDeviceConfiguration,
        runtime: tokio::runtime::Handle,
    ) -> Result<Self, DeviceError> {
        unsafe {
            let tun = Fd::new(libc::open(b"/dev/net/tun\0".as_ptr() as *const _, O_RDWR))
                .map_err(|_| std::io::Error::last_os_error())?;

            tun.set_nonblock()?;

            let mut req: ifreq = std::mem::zeroed();

            // Create the device.
            req.ifru.flags |= IFF_TUN;
            tunsetiff(tun.0, &mut req as *mut _ as *mut _)?;

            let sock = match socket(AF_INET, SOCK_DGRAM, 0) {
                i if i >= 0 => i,
                _ => return Err(DeviceError::IOError(std::io::Error::last_os_error())),
            };

            // Enable the device.
            siocgifflags(sock, &req).map_err(|_| std::io::Error::last_os_error())?;

            req.ifru.flags |= IFF_UP | IFF_RUNNING;
            siocsifflags(sock, &req).map_err(|_| std::io::Error::last_os_error())?;

            // Set address.
            let ip = match cfg.address {
                std::net::IpAddr::V4(ip) => ip,
                std::net::IpAddr::V6(_) => {
                    return Err(DeviceError::UnexpectedError(format!(
                        "only v4 ip addresses are currently supported"
                    )))
                }
            };

            let servaddr = libc::sockaddr_in {
                sin_family: AF_INET as u16,
                sin_port: 0,
                sin_addr: libc::in_addr {
                    s_addr: u32::from_be_bytes(ip.octets()).to_be(),
                },
                sin_zero: std::mem::zeroed(),
            };

            let serveraddr_ptr = &servaddr as *const libc::sockaddr_in as *const libc::sockaddr;
            req.ifru.addr = *serveraddr_ptr;

            siocsifaddr(sock, &req).map_err(|_| std::io::Error::last_os_error())?;

            // Set netmask.
            let netmask_ip = match cfg.netmask {
                std::net::IpAddr::V4(mask) => mask,
                std::net::IpAddr::V6(_) => {
                    return Err(DeviceError::UnexpectedError(format!(
                        "only v4 ip addresses are currently supported"
                    )))
                }
            };

            let netmaskaddr = libc::sockaddr_in {
                sin_family: AF_INET as u16,
                sin_port: 0,
                sin_addr: libc::in_addr {
                    s_addr: u32::from_be_bytes(netmask_ip.octets()).to_be(),
                },
                sin_zero: std::mem::zeroed(),
            };

            let netmaskaddr_ptr = &netmaskaddr as *const libc::sockaddr_in as *const libc::sockaddr;
            req.ifru.netmask = *netmaskaddr_ptr;

            siocsifnetmask(sock, &req).map_err(|_| std::io::Error::last_os_error())?;

            let _guard = runtime.enter();
            Ok(Self {
                inner: AsyncFd::new(tun)?,
            })
        }
    }

    pub async fn read(&self, buf: &mut [u8]) -> Result<usize, DeviceError> {
        loop {
            let mut guard = self.inner.readable().await?;

            match guard.try_io(|inner| inner.get_ref().read(buf)) {
                Ok(result) => match result {
                    Ok(size) => return Ok(size),
                    Err(err) => return Err(DeviceError::IOError(err)),
                },
                Err(_would_block) => continue,
            }
        }
    }

    pub async fn write(&self, buf: &mut [u8]) -> Result<usize, DeviceError> {
        loop {
            let mut guard = self.inner.writable().await?;

            match guard.try_io(|inner| inner.get_ref().write(buf)) {
                Ok(result) => match result {
                    Ok(size) => return Ok(size),
                    Err(err) => return Err(DeviceError::IOError(err)),
                },
                Err(_would_block) => continue,
            }
        }
    }
}

// TODO
pub struct TAPDevice {}

impl TAPDevice {
    pub fn new(cfg: TAPDeviceConfiguration) -> Result<Self, DeviceError> {
        Ok(TAPDevice {})
    }
}
