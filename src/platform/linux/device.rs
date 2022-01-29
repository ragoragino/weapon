use libc::{
    socket,
    O_RDWR,
    AF_INET,
    SOCK_DGRAM,
};
use tokio::io::unix::AsyncFd;

use crate::platform::linux::{
    fd::*,
    sys::*,
};
use crate::platform::{
    error::DeviceError,
    config::TUNDeviceConfiguration,
    config::TAPDeviceConfiguration,
};

pub struct TUNDevice {
    inner: AsyncFd<Fd>,
}

impl TUNDevice {
    pub fn new(cfg: TUNDeviceConfiguration, runtime: tokio::runtime::Handle) -> Result<Self, DeviceError> {
        unsafe {
            let tun =  Fd::new(libc::open(b"/dev/net/tun\0".as_ptr() as *const _, O_RDWR))
                .map_err(|_| std::io::Error::last_os_error())?;

            tun.set_nonblock()?;

            let mut req: ifreq = std::mem::zeroed();

            // Create and enable the device.
            req.ifru.flags |= IFF_TUN | IFF_UP | IFF_RUNNING;
            tunsetiff(tun.0, &mut req as *mut _ as *mut _)?;

            let sock = match socket(AF_INET, SOCK_DGRAM, 0) {
                i if i >= 0 => i,
                _ => return Err(DeviceError::IOError(std::io::Error::last_os_error())),
            };

            let ip = match cfg.address {
                std::net::IpAddr::V4(ip) => ip,
                std::net::IpAddr::V6(_) => return Err(DeviceError::UnexpectedError(
                format!("only v4 ip addresses are currently supported")
                )),
            };

            let servaddr = libc::sockaddr_in {
                sin_family: AF_INET as u16,
                sin_port: 0,
                sin_addr: libc::in_addr {
                    s_addr: u32::from_be_bytes(ip.octets()).to_be()
                },
                sin_zero: std::mem::zeroed(),
            };

            // Set address.
            let serveraddr_ptr = &servaddr as *const libc::sockaddr_in as *const libc::sockaddr;
            req.ifru.addr = *serveraddr_ptr;

            siocsifaddr(sock, &req)
                .map_err(|_| std::io::Error::last_os_error())?;

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
                Ok(result) => {
                    match result {
                        Ok(size) => return Ok(size),
                        Err(err) => return Err(DeviceError::IOError(err)),
                    }
                },
                Err(_would_block) => continue,
            }
        }
    }

    pub async fn write(&self, buf: &mut [u8]) -> Result<usize, DeviceError>  {
        loop {
            let mut guard = self.inner.writable().await?;

            match guard.try_io(|inner| inner.get_ref().write(buf)) {
                Ok(result) => {
                    match result {
                        Ok(size) => return Ok(size),
                        Err(err) => return Err(DeviceError::IOError(err)),
                    }
                },
                Err(_would_block) => continue,
            }
        }
    }
}

// TODO
pub struct TAPDevice {
    
}

impl TAPDevice {
    pub fn new(cfg: TAPDeviceConfiguration) -> Result<Self, DeviceError> {
        Ok(TAPDevice{})
    }
}