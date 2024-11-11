extern crate nix;
use nix::errno::Errno;
use nix::sys::socket::{AddressFamily, SockAddr, SockFlag, SockType, bind, socket};
use std::ffi::CString;
use std::io;
use std::mem::{size_of, zeroed};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::io::RawFd;
use std::ptr::null_mut;

const NFNL_SUBSYS_IPSET: u16 = 6;
const IPSET_ATTR_DATA: u16 = 7;
const IPSET_ATTR_IP: u16 = 1;
const IPSET_ATTR_IPADDR_IPV4: u16 = 1;
const IPSET_ATTR_IPADDR_IPV6: u16 = 2;
const IPSET_ATTR_PROTOCOL: u16 = 1;
const IPSET_ATTR_SETNAME: u16 = 2;
const IPSET_CMD_ADD: u16 = 9;
const IPSET_CMD_DEL: u16 = 10;
const IPSET_MAXNAMELEN: usize = 32;
const IPSET_PROTOCOL: u8 = 6;

const NFNETLINK_V0: u8 = 0;
const NLA_F_NESTED: u16 = 1 << 15;
const NLA_F_NET_BYTEORDER: u16 = 1 << 14;

const BUFF_SZ: usize = 256;

macro_rules! nl_align {
    ($len:expr) => {
        (($len + 3) & !3)
    };
}

#[repr(C)]
struct MyNlAttr {
    nla_len: u16,
    nla_type: u16,
}

#[repr(C)]
struct MyNfGenMsg {
    nfgen_family: u8,
    version: u8,
    res_id: u16,
}

static SNL: libc::sockaddr_nl = libc::sockaddr_nl {
    nl_family: libc::AF_NETLINK as libc::sa_family_t,
    nl_pad: 0,
    nl_pid: 0,
    nl_groups: 0,
};

static mut IPSET_SOCK: RawFd = 0;
static mut OLD_KERNEL: bool = false;
static mut BUFFER: [u8; BUFF_SZ] = [0; BUFF_SZ];

fn add_attr(nlh: &mut libc::nlmsghdr, attr_type: u16, len: usize, data: *const libc::c_void) {
    unsafe {
        let attr = (nlh as *mut libc::nlmsghdr).cast::<u8>().add(nl_align!(nlh.nlmsg_len as usize)) as *mut MyNlAttr;
        let payload_len = nl_align!(size_of::<MyNlAttr>()) + len;
        (*attr).nla_type = attr_type;
        (*attr).nla_len = payload_len as u16;
        std::ptr::copy_nonoverlapping(data as *const u8, attr.add(1) as *mut u8, len);
        nlh.nlmsg_len += nl_align!(payload_len) as u32;
    }
}

fn ipset_init() {
    unsafe {
        OLD_KERNEL = false; // You need to change this logic accordingly
        if OLD_KERNEL {
            IPSET_SOCK = socket(AddressFamily::Inet, SockType::Raw, SockFlag::empty(), Some(nix::sys::socket::SockProtocol::Raw)).unwrap();
            return;
        }

        if let Ok(sock) = socket(AddressFamily::Netlink, SockType::Raw, SockFlag::empty(), Some(nix::sys::socket::SockProtocol::Netfilter)) {
            IPSET_SOCK = sock;
            BUFFER = [0; BUFF_SZ];
            bind(IPSET_SOCK, &SockAddr::new_netlink(0, 0)).unwrap();
            return;
        }
    }
    panic!("failed to create IPset control socket");
}

fn new_add_to_ipset(setname: &str, ipaddr: &[u8], af: AddressFamily, remove: bool) -> Result<(), io::Error> {
    if setname.len() >= IPSET_MAXNAMELEN {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "name too long"));
    }

    unsafe {
        std::ptr::write_bytes(BUFFER.as_mut_ptr(), 0, BUFF_SZ);

        let nlh = BUFFER.as_ptr() as *mut libc::nlmsghdr;
        let nlh_len = nl_align!(size_of::<libc::nlmsghdr>()) as u32;
        (*nlh).nlmsg_len = nlh_len;
        (*nlh).nlmsg_type = (if remove { IPSET_CMD_DEL } else { IPSET_CMD_ADD }) | (NFNL_SUBSYS_IPSET << 8);
        (*nlh).nlmsg_flags = libc::NLM_F_REQUEST;

        let nfg = (BUFFER.as_ptr().add(nlh_len as usize)) as *mut MyNfGenMsg;
        let nfg_len = nl_align!(size_of::<MyNfGenMsg>()) as u32;
        (*nlh).nlmsg_len += nfg_len;
        (*nfg).nfgen_family = af as u8;
        (*nfg).version = NFNETLINK_V0;
        (*nfg).res_id = 0;

        let proto: u8 = IPSET_PROTOCOL;
        add_attr(nlh, IPSET_ATTR_PROTOCOL, size_of::<u8>(), &proto as *const u8 as *const libc::c_void);
        add_attr(nlh, IPSET_ATTR_SETNAME, setname.len() + 1, setname.as_ptr() as *const libc::c_void);
        add_attr(nlh, IPSET_ATTR_IP, ipaddr.len(), ipaddr.as_ptr() as *const libc::c_void);
        
        Ok(())
    }
}

fn main() {
    ipset_init();
    
    let setname = "example_set";
    let ipaddr_v4 = Ipv4Addr::new(192, 168, 0, 1);
    let ipaddr_v6 = Ipv6Addr::new(0x2001, 0x0db8, 0x85a3, 0, 0, 0, 0, 0x1);

    if let Ok(_) = new_add_to_ipset(setname, &ipaddr_v4.octets(), AddressFamily::Inet, false) {
        println!("IPv4 address added to IP set");
    }

    if let Ok(_) = new_add_to_ipset(setname, &ipaddr_v6.octets(), AddressFamily::Inet6, false) {
        println!("IPv6 address added to IP set");
    }
}