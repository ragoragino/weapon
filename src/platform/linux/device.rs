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
            req.ifru.addr = ipaddr_to_sockaddr(cfg.address)?;
            siocsifaddr(sock, &req).map_err(|_| std::io::Error::last_os_error())?;

            // Add new route entry.
            add_route_entry(sock, cfg.address, cfg.destination, cfg.netmask)?;

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

fn add_route_entry(socket: i32, 
    gateway: std::net::IpAddr, 
    destination: std::net::IpAddr, 
    netmask: std::net::IpAddr) -> Result<(), DeviceError> {
    unsafe {
        let mut entry: rtentry = std::mem::zeroed();

        entry.rt_gateway = ipaddr_to_sockaddr(gateway)?;
        entry.rt_dst = ipaddr_to_sockaddr(destination)?;
        entry.rt_genmask = ipaddr_to_sockaddr(netmask)?;
        entry.rt_flags = RTF_UP | RTF_GATEWAY;

        siocaddrt(socket, &entry).map_err(|_| std::io::Error::last_os_error())?;

        Ok(())
    }
}

fn ipaddr_to_sockaddr(address: std::net::IpAddr) -> Result<libc::sockaddr, DeviceError> {
    unsafe {
        let ip = match address {
            std::net::IpAddr::V4(ip) => ip,
            std::net::IpAddr::V6(_) => {
                return Err(DeviceError::UnexpectedError(format!(
                    "only v4 ip addresses are currently supported"
                )))
            }
        };
    
        let dst_addr_in = libc::sockaddr_in {
            sin_family: AF_INET as u16,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from_be_bytes(ip.octets()).to_be(),
            },
            sin_zero: std::mem::zeroed(),
        };
    
        let dst_addr_ptr = &dst_addr_in as *const libc::sockaddr_in as *const libc::sockaddr;
        Ok(*dst_addr_ptr)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipaddr_to_sockaddr() {
        let ipaddr = std::net::IpAddr::V4(std::net::Ipv4Addr::new(127,0,0,1));

        let mut data: [libc::c_char; 14] = [0; 14];
        data[2] = 127;
        data[5] = 1;
        let expected_sockaddr = libc::sockaddr{
            sa_family: AF_INET as u16,
            sa_data: data,
        };

        let sockaddr = ipaddr_to_sockaddr(ipaddr)
            .expect("unable to parse ipaddr to sockaddr");
        assert_eq!(expected_sockaddr, sockaddr);
    }

    #[test]
    #[should_panic]
    fn test_ipaddr_v6_to_sockaddr() {
        let ipaddr = std::net::IpAddr::V6(std::net::Ipv6Addr::new(0,0,0,0,0,0,0,1));
        let _ = ipaddr_to_sockaddr(ipaddr)
            .expect("unable to parse ipaddr to sockaddr");
    }
}