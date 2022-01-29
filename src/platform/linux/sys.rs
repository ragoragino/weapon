use nix::{
    ioctl_write_ptr,
    ioctl_write_ptr_bad,
};
use libc::sockaddr;
use libc::{
    c_char, 
    c_int, 
    c_short, 
    c_uchar,
    c_uint, 
    c_ulong, 
    c_ushort, 
    c_void,
};

pub const IFNAMSIZ: usize = 16;

pub const IFF_UP: c_short = 0x1;
pub const IFF_RUNNING: c_short = 0x40;

pub const SIOCGIFFLAGS: c_ulong = 0x8913;
pub const SIOCSIFFLAGS: c_ulong = 0x8914;
pub const SIOCSIFADDR: c_ulong = 0x8916;

pub const IFF_TUN: c_short = 0x0001;
pub const IFF_TAP: c_short = 0x0002;
pub const IFF_NO_PI: c_short = 0x1000;
pub const IFF_MULTI_QUEUE: c_short = 0x0100;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ifmap {
    pub mem_start: c_ulong,
    pub mem_end: c_ulong,
    pub base_addr: c_ushort,
    pub irq: c_uchar,
    pub dma: c_uchar,
    pub port: c_uchar,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union ifsu {
    pub raw_hdlc_proto: *mut c_void,
    pub cisco: *mut c_void,
    pub fr: *mut c_void,
    pub fr_pvc: *mut c_void,
    pub fr_pvc_info: *mut c_void,
    pub sync: *mut c_void,
    pub te1: *mut c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct if_settings {
    pub type_: c_uint,
    pub size: c_uint,
    pub ifsu: ifsu,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union ifrn {
    pub name: [c_char; IFNAMSIZ],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union ifru {
    pub addr: sockaddr,
    pub dstaddr: sockaddr,
    pub broadaddr: sockaddr,
    pub netmask: sockaddr,
    pub hwaddr: sockaddr,

    pub flags: c_short,
    pub ivalue: c_int,
    pub mtu: c_int,
    pub map: ifmap,
    pub slave: [c_char; IFNAMSIZ],
    pub newname: [c_char; IFNAMSIZ],
    pub data: *mut c_void,
    pub settings: if_settings,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ifreq {
    pub ifrn: ifrn,
    pub ifru: ifru,
}

const TUN_IOC_MAGIC: u8 = 'T' as u8;
const TUN_IOC_SET_IFF: u8 = 202;
ioctl_write_ptr!(tunsetiff, TUN_IOC_MAGIC, TUN_IOC_SET_IFF, u32);
ioctl_write_ptr_bad!(siocgifflags, SIOCGIFFLAGS, ifreq);
ioctl_write_ptr_bad!(siocsifflags, SIOCSIFFLAGS, ifreq);
ioctl_write_ptr_bad!(siocsifaddr, SIOCSIFADDR, ifreq);