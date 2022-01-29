use libc::{
    self,
    fcntl,
    F_GETFL, 
    F_SETFL, 
    O_NONBLOCK,
};
use std::os::unix::io::{
    RawFd,
    AsRawFd,
};
use crate::platform::error::DeviceError;

pub struct Fd(pub RawFd);

impl Fd {
    pub fn new(value: RawFd) -> Result<Self, DeviceError> {
        if value < 0 {
            return Err(DeviceError::UnexpectedError(format!("invalid file descriptor: {}", value)));
        }

        Ok(Fd(value))
    }

    pub fn set_nonblock(&self) -> std::io::Result<()> {
        match unsafe { fcntl(self.0, F_SETFL, fcntl(self.0, F_GETFL) | O_NONBLOCK) } {
            0 => Ok(()),
            _ => Err(std::io::Error::last_os_error()),
        }
    }

    pub fn read(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        unsafe {
            let amount = libc::read(self.0, buf.as_mut_ptr() as *mut _, buf.len());

            if amount < 0 {
                return Err(std::io::Error::last_os_error().into());
            }

            Ok(amount as usize)
        }
    }

    pub fn write(&self, buf: &[u8]) -> std::io::Result<usize> {
        unsafe {
            let amount = libc::write(self.0, buf.as_ptr() as *const _, buf.len());

            if amount < 0 {
                return Err(std::io::Error::last_os_error().into());
            }

            Ok(amount as usize)
        }
    }
}

impl AsRawFd for Fd {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

impl Drop for Fd {
    fn drop(&mut self) {
        unsafe {
            if self.0 >= 0 {
                libc::close(self.0);
            }
        }
    }
}