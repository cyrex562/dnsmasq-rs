#![cfg(feature = "dhcp")]

//! Helper process for DHCP lease-change (and ARP/TFTP/relay-snoop) scripts.
//!
//! Port of `helper.c`. Upstream forks a child *before* the main process
//! drops its own privileges (`dnsmasq.c:744`); that child immediately drops
//! to `script-user`/`script-group` itself, then loops forever reading
//! `struct script_data` events off a pipe and `exec`ing `dhcp-script` for
//! each one. The script therefore never runs with the daemon's own
//! privileges, even transiently — see the file-level comment in helper.c.
//!
//! [`create_helper`] is the entry point and must be called before the main
//! process's own privilege drop, exactly as `dnsmasq.c:744` calls
//! `create_helper()` ahead of `drop_root()`.

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::process::CommandExt as _;
use std::process::{Command, Stdio};

use nix::unistd::{fork, pipe, setgid, setgroups, setuid, ForkResult, Gid, Pid, Uid};

use crate::dhcp_protocol::DHCP_CHADDR_MAX;
use crate::types::dhcp::{
    ACTION_ADD, ACTION_ARP, ACTION_ARP_DEL, ACTION_DEL, ACTION_OLD, ACTION_OLD_HOSTNAME,
    ACTION_RELAY_SNOOP, ACTION_TFTP, DhcpLease, LEASE_NA, LEASE_TA,
};
use crate::util::legal_hostname;

const IF_NAMESIZE: usize = 16;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HelperError {
    #[error("truncated script_data event")]
    Truncated,
    #[error("unsupported script_data wire version {0}")]
    UnsupportedVersion(u8),
}

/// A single lease-change / ARP / TFTP / relay-snoop event.
///
/// Port of `struct script_data` (helper.c:52-74), encoded as one
/// fixed-size, versioned header followed by a variable-length blob of
/// `clid ++ hostname (NUL-terminated) ++ extradata` — the same three-part
/// trailing blob and ordering `queue_script()` packs (helper.c:829-844).
///
/// Unlike the C struct, every header field is always present at a fixed
/// offset regardless of build features: this is our own wire format for our
/// own pipe, not something exchanged with the C binary, so there is no
/// reason to make the layout `#[cfg]`-conditional the way upstream's
/// `#ifdef HAVE_DHCP6` / `#ifdef HAVE_TFTP` struct members are.
#[derive(Debug, Clone, PartialEq)]
pub struct ScriptData {
    pub action: u32,
    /// Lease flags for ADD/OLD/DEL; address family (`AF_INET`/`AF_INET6`)
    /// for TFTP/ARP — upstream reuses this field the same way (see the
    /// "nastily re-uses DHCP-fields" comment at helper.c:872).
    pub flags: u32,
    pub hwaddr_type: u16,
    pub hwaddr: Vec<u8>,
    pub addr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    pub addr6: Ipv6Addr,
    pub remaining_time: u32,
    pub expires: i64,
    pub iaid: u32,
    pub vendorclass_count: i32,
    pub file_len: u64,
    pub interface: String,
    pub clid: Vec<u8>,
    pub hostname: Option<String>,
    pub extradata: Vec<u8>,
}

impl ScriptData {
    const WIRE_VERSION: u8 = 1;
    pub const HEADER_LEN: usize = 104;

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::HEADER_LEN + self.clid.len() + self.extradata.len() + 16);

        let mut hwaddr_buf = [0u8; DHCP_CHADDR_MAX];
        let hwaddr_len = self.hwaddr.len().min(DHCP_CHADDR_MAX);
        hwaddr_buf[..hwaddr_len].copy_from_slice(&self.hwaddr[..hwaddr_len]);

        let mut interface_buf = [0u8; IF_NAMESIZE];
        let iface_bytes = self.interface.as_bytes();
        let iface_len = iface_bytes.len().min(IF_NAMESIZE - 1);
        interface_buf[..iface_len].copy_from_slice(&iface_bytes[..iface_len]);

        let hostname_bytes: Vec<u8> = match &self.hostname {
            Some(h) => {
                let mut v = h.as_bytes().to_vec();
                v.push(0);
                v
            }
            None => Vec::new(),
        };

        out.push(Self::WIRE_VERSION);
        out.extend_from_slice(&self.action.to_be_bytes());
        out.extend_from_slice(&self.flags.to_be_bytes());
        out.extend_from_slice(&self.hwaddr_type.to_be_bytes());
        out.push(hwaddr_len as u8);
        out.extend_from_slice(&hwaddr_buf);
        out.extend_from_slice(&(self.clid.len() as u16).to_be_bytes());
        out.extend_from_slice(&(hostname_bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(&(self.extradata.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.addr.octets());
        out.extend_from_slice(&self.giaddr.octets());
        out.extend_from_slice(&self.addr6.octets());
        out.extend_from_slice(&self.remaining_time.to_be_bytes());
        out.extend_from_slice(&self.expires.to_be_bytes());
        out.extend_from_slice(&self.iaid.to_be_bytes());
        out.extend_from_slice(&self.vendorclass_count.to_be_bytes());
        out.extend_from_slice(&self.file_len.to_be_bytes());
        out.extend_from_slice(&interface_buf);

        debug_assert_eq!(out.len(), Self::HEADER_LEN);

        out.extend_from_slice(&self.clid);
        out.extend_from_slice(&hostname_bytes);
        out.extend_from_slice(&self.extradata);
        out
    }

    /// Decode a full `encode()`-produced buffer (header + blob together).
    pub fn decode(bytes: &[u8]) -> Result<Self, HelperError> {
        if bytes.len() < Self::HEADER_LEN {
            return Err(HelperError::Truncated);
        }
        let (header, blob_len) = Self::decode_header(&bytes[..Self::HEADER_LEN])?;
        let blob = &bytes[Self::HEADER_LEN..];
        if blob.len() != blob_len {
            return Err(HelperError::Truncated);
        }
        Self::from_header_and_blob(header, blob)
    }

    /// Decode just the fixed header, returning the parsed fields and the
    /// number of trailing blob bytes (`clid_len + hostname_len + ed_len`)
    /// still to be read. Used by the pipe-reading loop, which — like
    /// `create_helper`'s `read_write(... sizeof(data) ...)` followed by a
    /// second `read_write` for the variable part (helper.c:199,260) — reads
    /// the header and the blob as two separate reads.
    fn decode_header(bytes: &[u8]) -> Result<(HeaderFields, usize), HelperError> {
        if bytes.len() < Self::HEADER_LEN {
            return Err(HelperError::Truncated);
        }
        let mut p = 0usize;
        let mut take = |n: usize| {
            let s = &bytes[p..p + n];
            p += n;
            s
        };

        let version = take(1)[0];
        if version != Self::WIRE_VERSION {
            return Err(HelperError::UnsupportedVersion(version));
        }
        let action = u32::from_be_bytes(take(4).try_into().unwrap());
        let flags = u32::from_be_bytes(take(4).try_into().unwrap());
        let hwaddr_type = u16::from_be_bytes(take(2).try_into().unwrap());
        let hwaddr_len = take(1)[0] as usize;
        let hwaddr_raw = take(DHCP_CHADDR_MAX).to_vec();
        let hwaddr = hwaddr_raw[..hwaddr_len.min(DHCP_CHADDR_MAX)].to_vec();
        let clid_len = u16::from_be_bytes(take(2).try_into().unwrap());
        let hostname_len = u16::from_be_bytes(take(2).try_into().unwrap());
        let ed_len = u32::from_be_bytes(take(4).try_into().unwrap());
        let addr = Ipv4Addr::from(<[u8; 4]>::try_from(take(4)).unwrap());
        let giaddr = Ipv4Addr::from(<[u8; 4]>::try_from(take(4)).unwrap());
        let addr6 = Ipv6Addr::from(<[u8; 16]>::try_from(take(16)).unwrap());
        let remaining_time = u32::from_be_bytes(take(4).try_into().unwrap());
        let expires = i64::from_be_bytes(take(8).try_into().unwrap());
        let iaid = u32::from_be_bytes(take(4).try_into().unwrap());
        let vendorclass_count = i32::from_be_bytes(take(4).try_into().unwrap());
        let file_len = u64::from_be_bytes(take(8).try_into().unwrap());
        let interface_raw = take(IF_NAMESIZE);
        let interface_end = interface_raw.iter().position(|&b| b == 0).unwrap_or(interface_raw.len());
        let interface = String::from_utf8_lossy(&interface_raw[..interface_end]).into_owned();

        debug_assert_eq!(p, Self::HEADER_LEN);

        let blob_len = clid_len as usize + hostname_len as usize + ed_len as usize;

        Ok((
            HeaderFields {
                action,
                flags,
                hwaddr_type,
                hwaddr,
                clid_len,
                hostname_len,
                ed_len,
                addr,
                giaddr,
                addr6,
                remaining_time,
                expires,
                iaid,
                vendorclass_count,
                file_len,
                interface,
            },
            blob_len,
        ))
    }

    fn from_header_and_blob(header: HeaderFields, blob: &[u8]) -> Result<Self, HelperError> {
        let clid_len = header.clid_len as usize;
        let hostname_len = header.hostname_len as usize;
        let ed_len = header.ed_len as usize;
        if blob.len() != clid_len + hostname_len + ed_len {
            return Err(HelperError::Truncated);
        }

        let clid = blob[..clid_len].to_vec();
        let hostname_raw = &blob[clid_len..clid_len + hostname_len];
        let hostname = if hostname_raw.is_empty() {
            None
        } else {
            // hostname_len includes the trailing NUL (matches helper.c:293).
            let end = hostname_raw.iter().position(|&b| b == 0).unwrap_or(hostname_raw.len());
            Some(String::from_utf8_lossy(&hostname_raw[..end]).into_owned())
        };
        let extradata = blob[clid_len + hostname_len..].to_vec();

        Ok(ScriptData {
            action: header.action,
            flags: header.flags,
            hwaddr_type: header.hwaddr_type,
            hwaddr: header.hwaddr,
            addr: header.addr,
            giaddr: header.giaddr,
            addr6: header.addr6,
            remaining_time: header.remaining_time,
            expires: header.expires,
            iaid: header.iaid,
            vendorclass_count: header.vendorclass_count,
            file_len: header.file_len,
            interface: header.interface,
            clid,
            hostname,
            extradata,
        })
    }

    /// Port of `queue_script()` (helper.c:777-846): pack a lease-change
    /// event ready to send to the helper.
    pub fn for_lease(action: u32, lease: &DhcpLease, hostname: Option<&str>, now: std::time::SystemTime) -> Self {
        let remaining_time = match lease.expires {
            Some(exp) => exp.duration_since(now).map(|d| d.as_secs() as u32).unwrap_or(0),
            None => 0,
        };
        let expires = lease
            .expires
            .and_then(|e| e.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        #[cfg(feature = "dhcp6")]
        let (addr6, iaid, vendorclass_count) = (lease.addr6, lease.iaid, lease.vendorclass_count);
        #[cfg(not(feature = "dhcp6"))]
        let (addr6, iaid, vendorclass_count) = (Ipv6Addr::UNSPECIFIED, 0u32, 0i32);

        ScriptData {
            action,
            flags: lease.flags,
            hwaddr_type: lease.hwaddr_type as u16,
            hwaddr: lease.hwaddr[..lease.hwaddr_len.min(DHCP_CHADDR_MAX)].to_vec(),
            addr: lease.addr,
            giaddr: lease.giaddr,
            addr6,
            remaining_time,
            expires,
            iaid,
            vendorclass_count,
            file_len: 0,
            interface: String::new(),
            clid: lease.clid.clone().unwrap_or_default(),
            hostname: hostname.map(str::to_string),
            extradata: lease.extradata.clone(),
        }
    }

    /// Port of `queue_arp()` (helper.c:900-920).
    pub fn for_arp(is_del: bool, mac: &[u8], addr: std::net::IpAddr) -> Self {
        const ARPHRD_ETHER: u16 = 1;
        let mut data = ScriptData {
            action: if is_del { ACTION_ARP_DEL } else { ACTION_ARP },
            flags: 0,
            hwaddr_type: ARPHRD_ETHER,
            hwaddr: mac.to_vec(),
            addr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            addr6: Ipv6Addr::UNSPECIFIED,
            remaining_time: 0,
            expires: 0,
            iaid: 0,
            vendorclass_count: 0,
            file_len: 0,
            interface: String::new(),
            clid: Vec::new(),
            hostname: None,
            extradata: Vec::new(),
        };
        match addr {
            std::net::IpAddr::V4(v4) => {
                data.flags = libc::AF_INET as u32;
                data.addr = v4;
            }
            std::net::IpAddr::V6(v6) => {
                data.flags = libc::AF_INET6 as u32;
                data.addr6 = v6;
            }
        }
        data
    }

    /// Port of `queue_tftp()` (helper.c:873-897).
    pub fn for_tftp(filename: &str, file_len: u64, peer: &std::net::SocketAddr) -> Self {
        let mut data = ScriptData {
            action: ACTION_TFTP,
            flags: 0,
            hwaddr_type: 0,
            hwaddr: Vec::new(),
            addr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            addr6: Ipv6Addr::UNSPECIFIED,
            remaining_time: 0,
            expires: 0,
            iaid: 0,
            vendorclass_count: 0,
            file_len,
            interface: String::new(),
            clid: Vec::new(),
            hostname: Some(filename.to_string()),
            extradata: Vec::new(),
        };
        match peer.ip() {
            std::net::IpAddr::V4(v4) => {
                data.flags = libc::AF_INET as u32;
                data.addr = v4;
            }
            std::net::IpAddr::V6(v6) => {
                data.flags = libc::AF_INET6 as u32;
                data.addr6 = v6;
            }
        }
        data
    }

    /// Port of `queue_relay_snoop()` (helper.c:849-868).
    ///
    /// Upstream resolves `if_index` to an interface name via `indextoname()`
    /// before storing it (helper.c:865); the caller here does the same
    /// resolution and passes the resulting name directly, so `if_index`
    /// itself does not need a wire-format slot.
    #[cfg(feature = "dhcp6")]
    pub fn for_relay_snoop(client: Ipv6Addr, if_index: i32, prefix: Ipv6Addr, prefix_len: u8, interface: &str) -> Self {
        let _ = if_index;
        ScriptData {
            action: ACTION_RELAY_SNOOP,
            flags: 0,
            hwaddr_type: 0,
            hwaddr: Vec::new(),
            addr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            addr6: client,
            remaining_time: 0,
            expires: 0,
            iaid: 0,
            vendorclass_count: 0,
            file_len: 0,
            interface: interface.to_string(),
            clid: Vec::new(),
            hostname: Some(format!("{}/{}", prefix, prefix_len)),
            extradata: Vec::new(),
        }
    }
}

struct HeaderFields {
    action: u32,
    flags: u32,
    hwaddr_type: u16,
    hwaddr: Vec<u8>,
    clid_len: u16,
    hostname_len: u16,
    ed_len: u32,
    addr: Ipv4Addr,
    giaddr: Ipv4Addr,
    addr6: Ipv6Addr,
    remaining_time: u32,
    expires: i64,
    iaid: u32,
    vendorclass_count: i32,
    file_len: u64,
    interface: String,
}

/// Format a hardware address as colon-separated hex (lowercase).
pub fn format_mac(hwaddr: &[u8]) -> String {
    hwaddr.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":")
}

/// Format a client ID as colon-separated hex (lowercase).
pub fn format_client_id(clid: &[u8]) -> String {
    clid.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(":")
}

/// Parse one NUL-terminated entry from an extra-data buffer.
///
/// Port of `grab_extradata()` from helper.c:704-733.
pub fn grab_extradata(buf: &[u8]) -> Option<(&str, &[u8])> {
    if buf.is_empty() {
        return None;
    }
    let null_pos = buf.iter().position(|&b| b == 0)?;
    let value = std::str::from_utf8(&buf[..null_pos]).unwrap_or("");
    let remaining = &buf[null_pos + 1..];
    Some((value, remaining))
}

/// The parent-side handle returned by [`create_helper`]: the write end of
/// the pipe to the forked, privilege-dropped child, plus that child's pid.
pub struct HelperHandle {
    write: std::fs::File,
    pub child_pid: Pid,
}

impl HelperHandle {
    /// Queue one event to the helper. Mirrors `helper_write()`
    /// (helper.c:927-946): this is a `write()` on a pipe, never a wait on
    /// the script itself, so a hung or crashed script can never block the
    /// caller.
    pub fn send(&mut self, data: &ScriptData) -> io::Result<()> {
        self.write.write_all(&data.encode())
    }
}

/// Fork the privilege-dropped helper child and return the parent's handle
/// to it.
///
/// Port of `create_helper()` (helper.c:79-98 parent half). Must be called
/// before the main process's own privilege drop (`dnsmasq.c:744`), and — like
/// `dnsmasq::fork_into_background` — before any tokio runtime is started:
/// `fork()` gives the child only the calling thread, so forking a live
/// reactor is not safe.
///
/// `drop_to`, when `Some((uid, gid))` with `uid != 0`, is applied in the
/// child before it touches any data from the pipe — matching helper.c's
/// ordering (`setgroups`/`setgid`/`setuid` at :109-127, *before*
/// `close_fds` and the read loop). `uid == 0` is treated as "no drop",
/// exactly as `create_helper`'s `uid != 0` guard.
pub fn create_helper(command: Option<String>, drop_to: Option<(Uid, Gid)>) -> io::Result<HelperHandle> {
    let (read_fd, write_fd) = pipe()?;

    match unsafe { fork() }? {
        ForkResult::Parent { child } => {
            drop(read_fd); // close reader in parent (helper.c:96)
            Ok(HelperHandle { write: std::fs::File::from(write_fd), child_pid: child })
        }
        ForkResult::Child => {
            drop(write_fd);

            // Ignore SIGTERM/SIGALRM/SIGINT so we can clean up when the main
            // process is hit, and so sleep() (used for fork retry below)
            // works (helper.c:100-107).
            unsafe {
                let ignore = nix::sys::signal::SigAction::new(
                    nix::sys::signal::SigHandler::SigIgn,
                    nix::sys::signal::SaFlags::empty(),
                    nix::sys::signal::SigSet::empty(),
                );
                let _ = nix::sys::signal::sigaction(nix::sys::signal::Signal::SIGTERM, &ignore);
                let _ = nix::sys::signal::sigaction(nix::sys::signal::Signal::SIGALRM, &ignore);
                let _ = nix::sys::signal::sigaction(nix::sys::signal::Signal::SIGINT, &ignore);
            }

            if let Some((uid, gid)) = drop_to {
                if uid.as_raw() != 0 && drop_privileges(uid, gid).is_err() {
                    // Upstream sends EVENT_USER_ERR/EVENT_DIE back to the main
                    // process and exits (helper.c:116-126); we have no event
                    // channel wired up yet (tracked in tasks.md), so exit
                    // non-zero rather than silently continuing to run with
                    // undropped privileges.
                    unsafe { libc::_exit(1) };
                }
            }

            run_helper_loop(std::fs::File::from(read_fd), command.as_deref());
            unsafe { libc::_exit(0) };
        }
    }
}

/// Port of the `setgroups(0,…)` / `setgid()` / `setuid()` sequence at
/// helper.c:109-127.
fn drop_privileges(uid: Uid, gid: Gid) -> nix::Result<()> {
    setgroups(&[])?;
    setgid(gid)?;
    setuid(uid)?;
    Ok(())
}

/// Determine whether an event is IPv6, replicating helper.c:212-240's
/// per-action reinterpretation of the `flags` field.
fn is6(data: &ScriptData) -> bool {
    match data.action {
        ACTION_TFTP | ACTION_ARP | ACTION_ARP_DEL => data.flags != libc::AF_INET as u32,
        ACTION_RELAY_SNOOP => true,
        _ => data.flags & (LEASE_TA | LEASE_NA) != 0,
    }
}

/// Stringify a hardware address the way helper.c:244-253 builds
/// `dhcp_buff`: prefixed with the ARP hardware type in hex when it is not
/// plain Ethernet (or there is no address at all), then colon-hex bytes.
fn format_hwaddr_field(data: &ScriptData) -> String {
    const ARPHRD_ETHER: u16 = 1;
    let mut s = String::new();
    if data.hwaddr_type != ARPHRD_ETHER || data.hwaddr.is_empty() {
        s.push_str(&format!("{:02x}-", data.hwaddr_type));
    }
    s.push_str(&format_mac(&data.hwaddr));
    s
}

/// Split a hostname into `(hostname, domain)`, applying `legal_hostname()`
/// and the first-dot split from helper.c:289-304. TFTP/relay-snoop
/// `hostname_len` actually carries a filename/prefix, not a DNS name, so
/// upstream skips both checks for those two actions.
fn hostname_and_domain(data: &ScriptData) -> (Option<String>, Option<String>) {
    let Some(raw) = data.hostname.clone() else { return (None, None) };
    if matches!(data.action, ACTION_TFTP | ACTION_RELAY_SNOOP) {
        return (Some(raw), None);
    }
    if !legal_hostname(&raw) {
        return (None, None);
    }
    match raw.split_once('.') {
        Some((h, d)) => (Some(h.to_string()), Some(d.to_string())),
        None => (Some(raw), None),
    }
}

/// Pull one `DNSMASQ_*` env var out of the extradata blob and advance past
/// it. Port of the `grab_extradata()` call sites at helper.c:611-658.
fn grab_env(cmd: &mut Command, buf: &[u8], name: &str) -> Vec<u8> {
    match grab_extradata(buf) {
        Some((val, rest)) => {
            cmd.env(name, val);
            rest.to_vec()
        }
        None => Vec::new(),
    }
}

/// Set the `DNSMASQ_*` environment variables carried in `extradata`, in the
/// exact order helper.c:611-658 grabs them. Only reached for lease actions
/// (TFTP/ARP/relay-snoop skip this whole block upstream, helper.c:584).
fn set_extradata_env(cmd: &mut Command, extradata: &[u8], is6: bool) {
    let mut buf = extradata.to_vec();
    if !is6 {
        buf = grab_env(cmd, &buf, "DNSMASQ_VENDOR_CLASS");
    }
    buf = grab_env(cmd, &buf, "DNSMASQ_SUPPLIED_HOSTNAME");
    if !is6 {
        buf = grab_env(cmd, &buf, "DNSMASQ_CPEWAN_OUI");
        buf = grab_env(cmd, &buf, "DNSMASQ_CPEWAN_SERIAL");
        buf = grab_env(cmd, &buf, "DNSMASQ_CPEWAN_CLASS");
        buf = grab_env(cmd, &buf, "DNSMASQ_CIRCUIT_ID");
        buf = grab_env(cmd, &buf, "DNSMASQ_SUBSCRIBER_ID");
        buf = grab_env(cmd, &buf, "DNSMASQ_REMOTE_ID");
    }
    buf = grab_env(cmd, &buf, "DNSMASQ_REQUESTED_OPTIONS");
    buf = grab_env(cmd, &buf, "DNSMASQ_MUD_URL");
    buf = grab_env(cmd, &buf, "DNSMASQ_TAGS");
    if is6 {
        buf = grab_env(cmd, &buf, "DNSMASQ_RELAY_ADDRESS");
    }
    let mut i = 0;
    loop {
        let Some((val, rest)) = grab_extradata(&buf) else { break };
        cmd.env(format!("DNSMASQ_USER_CLASS{i}"), val);
        buf = rest.to_vec();
        i += 1;
    }
}

/// Build and run the script `Command` for one event, capturing its
/// stdout/stderr and its exit status the way the doubly-forked grandchild
/// in helper.c:504-689 does — except here `std::process::Command` handles
/// the fork+exec+wait itself, since we already are the privilege-dropped
/// process the script must inherit from (no second privilege drop needed).
fn run_script_child(command: &str, action_str: &str, data: &ScriptData) {
    let is6 = is6(data);
    let (hostname, domain) = hostname_and_domain(data);

    let basename = std::path::Path::new(command)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(command)
        .to_string();

    let second_field = if data.action == ACTION_TFTP {
        data.file_len.to_string()
    } else {
        format_hwaddr_field(data)
    };
    let addr_field = if is6 { data.addr6.to_string() } else { data.addr.to_string() };

    let mut cmd = Command::new(command);
    cmd.arg0(&basename);
    cmd.arg(action_str);
    cmd.arg(&second_field);
    cmd.arg(&addr_field);
    if let Some(h) = &hostname {
        cmd.arg(h);
    }
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    if !matches!(data.action, ACTION_TFTP | ACTION_ARP | ACTION_ARP_DEL | ACTION_RELAY_SNOOP) {
        if !is6 && !data.clid.is_empty() {
            cmd.env("DNSMASQ_CLIENT_ID", format_client_id(&data.clid));
        }
        if !data.interface.is_empty() {
            cmd.env("DNSMASQ_INTERFACE", &data.interface);
        }
        cmd.env("DNSMASQ_LEASE_EXPIRES", data.expires.to_string());
        if let Some(d) = &domain {
            cmd.env("DNSMASQ_DOMAIN", d);
        }
        if data.extradata.is_empty() {
            cmd.env("DNSMASQ_DATA_MISSING", "1");
        }
        set_extradata_env(&mut cmd, &data.extradata, is6);
        if !is6 && data.giaddr != Ipv4Addr::UNSPECIFIED {
            cmd.env("DNSMASQ_RELAY_ADDRESS", data.giaddr.to_string());
        }
        if data.action != ACTION_DEL && data.remaining_time != 0 {
            cmd.env("DNSMASQ_TIME_REMAINING", data.remaining_time.to_string());
        }
        if data.action == ACTION_OLD_HOSTNAME {
            if let Some(h) = &hostname {
                cmd.env("DNSMASQ_OLD_HOSTNAME", h);
            }
        }
    }

    let output = match cmd.output() {
        Ok(o) => o,
        Err(e) => {
            tracing::warn!("dhcp-script exec failed: {e}");
            return;
        }
    };

    for line in String::from_utf8_lossy(&output.stdout).lines() {
        tracing::info!(target: "dhcp-script", "{line}");
    }
    for line in String::from_utf8_lossy(&output.stderr).lines() {
        tracing::info!(target: "dhcp-script", "{line}");
    }

    use std::os::unix::process::ExitStatusExt as _;
    if let Some(sig) = output.status.signal() {
        tracing::warn!("dhcp-script killed by signal {sig}");
    } else if let Some(code) = output.status.code() {
        if code != 0 {
            tracing::warn!("dhcp-script exited with status {code}");
        }
    }
}

/// The forked, privilege-dropped helper's main loop: read one
/// [`ScriptData`] event at a time off `read`, and run `command` for it.
/// Port of the `while(1)` loop body at helper.c:182-690, minus the Lua
/// integration (helper.c:319-498), which is deliberately out of scope (see
/// `tasks.md`).
///
/// Returns when the pipe hits EOF (helper.c:199: "we read zero bytes when
/// pipe closed: this is our signal to exit").
fn run_helper_loop(mut read: std::fs::File, command: Option<&str>) {
    loop {
        let mut header_buf = [0u8; ScriptData::HEADER_LEN];
        if read.read_exact(&mut header_buf).is_err() {
            return;
        }
        let Ok((header, blob_len)) = ScriptData::decode_header(&header_buf) else {
            // A corrupt/unsupported-version header from our own pipe would
            // mean a version skew bug, not attacker-controlled input (this
            // pipe has no other writer) -- skip rather than trust it and
            // hope the stream resynchronizes on the next read.
            continue;
        };
        let mut blob = vec![0u8; blob_len];
        if !blob.is_empty() && read.read_exact(&mut blob).is_err() {
            return;
        }
        let Ok(data) = ScriptData::from_header_and_blob(header, &blob) else {
            continue;
        };

        let action_str = match data.action {
            ACTION_DEL => "del",
            ACTION_ADD => "add",
            ACTION_OLD | ACTION_OLD_HOSTNAME => "old",
            ACTION_TFTP => "tftp",
            ACTION_ARP => "arp-add",
            ACTION_ARP_DEL => "arp-del",
            ACTION_RELAY_SNOOP => "relay-snoop",
            _ => continue,
        };

        // "no script, just lua" (helper.c:501-502) -- lua isn't ported, so
        // an event with no configured command is simply consumed and
        // discarded.
        let Some(command) = command else { continue };

        run_script_child(command, action_str, &data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, SocketAddr};
    use std::time::{Duration, SystemTime};

    fn sample_lease() -> DhcpLease {
        let mut hwaddr = [0u8; DHCP_CHADDR_MAX];
        hwaddr[..6].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        DhcpLease {
            clid: Some(vec![0x01, 0xaa, 0xbb]),
            hostname: Some("myhost".to_string()),
            fqdn: None,
            old_hostname: None,
            flags: 0,
            expires: Some(SystemTime::now() + Duration::from_secs(3600)),
            hwaddr,
            hwaddr_len: 6,
            hwaddr_type: 1, // ARPHRD_ETHER
            addr: "192.168.1.10".parse().unwrap(),
            giaddr: Ipv4Addr::UNSPECIFIED,
            extradata: b"vendorclass\0suppliedhost\0".to_vec(),
            last_interface: 0,
            new_interface: 0,
            new_prefixlen: 0,
            agent_id: None,
            vendorclass: None,
            #[cfg(feature = "dhcp6")]
            addr6: Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            iaid: 0,
            #[cfg(feature = "dhcp6")]
            slaac_address: vec![],
            #[cfg(feature = "dhcp6")]
            vendorclass_count: 0,
        }
    }

    // ── ScriptData wire format ──────────────────────────────────────────

    #[test]
    fn roundtrip_lease_add() {
        let lease = sample_lease();
        let data = ScriptData::for_lease(ACTION_ADD, &lease, lease.hostname.as_deref(), SystemTime::now());
        let bytes = data.encode();
        let got = ScriptData::decode(&bytes).unwrap();
        assert_eq!(got, data);
    }

    #[test]
    fn roundtrip_preserves_all_fields() {
        let lease = sample_lease();
        let data = ScriptData::for_lease(ACTION_DEL, &lease, None, SystemTime::now());
        let bytes = data.encode();
        let got = ScriptData::decode(&bytes).unwrap();
        assert_eq!(got.action, ACTION_DEL);
        assert_eq!(got.hwaddr, &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(got.addr, "192.168.1.10".parse::<Ipv4Addr>().unwrap());
        assert_eq!(got.clid, vec![0x01, 0xaa, 0xbb]);
        assert_eq!(got.hostname, None);
        assert_eq!(got.extradata, b"vendorclass\0suppliedhost\0".to_vec());
    }

    #[test]
    fn decode_rejects_truncated_header() {
        let err = ScriptData::decode(&[0u8; 10]).unwrap_err();
        assert_eq!(err, HelperError::Truncated);
    }

    #[test]
    fn decode_rejects_short_blob() {
        let lease = sample_lease();
        let data = ScriptData::for_lease(ACTION_ADD, &lease, lease.hostname.as_deref(), SystemTime::now());
        let mut bytes = data.encode();
        bytes.truncate(bytes.len() - 1);
        let err = ScriptData::decode(&bytes).unwrap_err();
        assert_eq!(err, HelperError::Truncated);
    }

    #[test]
    fn decode_rejects_unknown_version() {
        let lease = sample_lease();
        let data = ScriptData::for_lease(ACTION_ADD, &lease, lease.hostname.as_deref(), SystemTime::now());
        let mut bytes = data.encode();
        bytes[0] = 99;
        let err = ScriptData::decode(&bytes).unwrap_err();
        assert_eq!(err, HelperError::UnsupportedVersion(99));
    }

    #[test]
    fn for_arp_encodes_family_and_mac() {
        let data = ScriptData::for_arp(false, &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66], "10.0.0.1".parse().unwrap());
        assert_eq!(data.action, ACTION_ARP);
        assert_eq!(data.hwaddr, vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        assert_eq!(data.addr, "10.0.0.1".parse::<Ipv4Addr>().unwrap());
        let bytes = data.encode();
        let got = ScriptData::decode(&bytes).unwrap();
        assert_eq!(got, data);
    }

    #[test]
    fn for_arp_del_sets_action() {
        let data = ScriptData::for_arp(true, &[0; 6], "10.0.0.1".parse().unwrap());
        assert_eq!(data.action, ACTION_ARP_DEL);
    }

    #[test]
    fn for_arp_ipv6_sets_addr6() {
        let data = ScriptData::for_arp(false, &[0xaa; 6], "fd00::1".parse().unwrap());
        assert_eq!(data.addr6, "fd00::1".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn for_tftp_roundtrip() {
        let peer: SocketAddr = "10.0.0.1:69".parse().unwrap();
        let data = ScriptData::for_tftp("test.bin", 1024, &peer);
        assert_eq!(data.action, ACTION_TFTP);
        assert_eq!(data.file_len, 1024);
        assert_eq!(data.hostname.as_deref(), Some("test.bin"));
        let bytes = data.encode();
        let got = ScriptData::decode(&bytes).unwrap();
        assert_eq!(got, data);
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn for_relay_snoop_roundtrip() {
        let data = ScriptData::for_relay_snoop(
            "2001:db8::1".parse().unwrap(),
            5,
            "2001:db8::".parse().unwrap(),
            64,
            "eth0",
        );
        assert_eq!(data.action, ACTION_RELAY_SNOOP);
        assert_eq!(data.addr6, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(data.hostname.as_deref(), Some("2001:db8::/64"));
        let bytes = data.encode();
        let got = ScriptData::decode(&bytes).unwrap();
        assert_eq!(got, data);
    }

    // ── format_mac / format_client_id / grab_extradata (unchanged ports) ─

    #[test]
    fn format_mac_typical() {
        assert_eq!(format_mac(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn format_client_id_typical() {
        assert_eq!(format_client_id(&[0x01, 0xaa]), "01:aa");
    }

    #[test]
    fn grab_extradata_chained() {
        let buf = b"first\0second\0";
        let (v1, r1) = grab_extradata(buf).unwrap();
        assert_eq!(v1, "first");
        let (v2, r2) = grab_extradata(r1).unwrap();
        assert_eq!(v2, "second");
        assert!(r2.is_empty());
    }

    // ── create_helper: process model ────────────────────────────────────

    /// The core acceptance criterion: the script runs in a forked child
    /// whose privileges have actually been dropped, not the parent's.
    /// Root-gated because `setuid`/`setgid` to an unprivileged account only
    /// succeeds when we start out as root.
    #[test]
    fn create_helper_drops_privileges_in_child() {
        if !Uid::effective().is_root() {
            eprintln!("skipping: requires root to exercise a real privilege drop");
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let out_path = dir.path().join("id_out");
        let script = dir.path().join("report_id.sh");
        std::fs::write(
            &script,
            format!("#!/bin/sh\nid -u > {0}\nid -g >> {0}\n", out_path.display()),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();

        // "nobody" is 65534 on essentially every Linux distribution.
        let target_uid = Uid::from_raw(65534);
        let target_gid = Gid::from_raw(65534);

        let mut helper = create_helper(
            Some(script.to_str().unwrap().to_string()),
            Some((target_uid, target_gid)),
        )
        .unwrap();

        let lease = sample_lease();
        let data = ScriptData::for_lease(ACTION_ADD, &lease, None, SystemTime::now());
        helper.send(&data).unwrap();

        // Give the helper's grandchild time to run and write the file, then
        // shut the helper down cleanly (EOF on the pipe).
        std::thread::sleep(Duration::from_millis(500));
        drop(helper);

        let contents = std::fs::read_to_string(&out_path).unwrap();
        let mut lines = contents.lines();
        let reported_uid: u32 = lines.next().unwrap().parse().unwrap();
        let reported_gid: u32 = lines.next().unwrap().parse().unwrap();
        assert_eq!(reported_uid, 65534);
        assert_eq!(reported_gid, 65534);
        assert_ne!(reported_uid, 0);
    }

    #[test]
    fn drop_privileges_changes_ids_when_run_as_root() {
        if !Uid::effective().is_root() {
            eprintln!("skipping: requires root");
            return;
        }
        // Exercise in a forked child so we don't actually de-escalate this
        // test process out from under the rest of the suite.
        let (read_fd, write_fd) = pipe().unwrap();
        match unsafe { fork() }.unwrap() {
            ForkResult::Child => {
                drop(read_fd);
                drop_privileges(Uid::from_raw(65534), Gid::from_raw(65534)).unwrap();
                let uid = nix::unistd::geteuid().as_raw();
                let gid = nix::unistd::getegid().as_raw();
                let mut f = std::fs::File::from(write_fd);
                let _ = f.write_all(&uid.to_be_bytes());
                let _ = f.write_all(&gid.to_be_bytes());
                unsafe { libc::_exit(0) };
            }
            ForkResult::Parent { child } => {
                drop(write_fd);
                let mut f = std::fs::File::from(read_fd);
                let mut buf = [0u8; 8];
                f.read_exact(&mut buf).unwrap();
                nix::sys::wait::waitpid(child, None).unwrap();
                let uid = u32::from_be_bytes(buf[0..4].try_into().unwrap());
                let gid = u32::from_be_bytes(buf[4..8].try_into().unwrap());
                assert_eq!(uid, 65534);
                assert_eq!(gid, 65534);
            }
        }
    }

    /// The parent must never block on a script the helper runs, however
    /// long that script takes.
    #[test]
    fn parent_is_not_blocked_by_a_hanging_script() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("hang.sh");
        std::fs::write(&script, "#!/bin/sh\nsleep 30\n").unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();

        let mut helper = create_helper(Some(script.to_str().unwrap().to_string()), None).unwrap();
        let lease = sample_lease();
        let data = ScriptData::for_lease(ACTION_ADD, &lease, None, SystemTime::now());

        let start = std::time::Instant::now();
        helper.send(&data).unwrap();
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "send() should be a pipe write, not a wait on the script"
        );

        // Reap the helper process so the test suite doesn't accumulate
        // zombies; it and its hung grandchild are killed outright since we
        // are not waiting out the 30s sleep.
        let _ = nix::sys::signal::kill(helper.child_pid, nix::sys::signal::Signal::SIGKILL);
        let _ = nix::sys::wait::waitpid(helper.child_pid, None);
    }

    /// If the helper process itself dies (crash, OOM-kill, ...), writing
    /// further events must return an error rather than taking down the
    /// caller — no panics, no `SIGPIPE`-default process death.
    #[test]
    fn parent_survives_helper_child_crashing() {
        let mut helper = create_helper(None, None).unwrap();
        let _ = nix::sys::signal::kill(helper.child_pid, nix::sys::signal::Signal::SIGKILL);
        let _ = nix::sys::wait::waitpid(helper.child_pid, None);

        let lease = sample_lease();
        let data = ScriptData::for_lease(ACTION_ADD, &lease, None, SystemTime::now());
        // Repeat until the kernel reports the reader gone (EPIPE) or we give
        // up after enough attempts to fill the pipe buffer; either way this
        // must return, not panic or kill the test process via SIGPIPE.
        for _ in 0..64 {
            if helper.send(&data).is_err() {
                return;
            }
        }
    }

    #[test]
    fn create_helper_no_script_configured_does_not_panic() {
        let mut helper = create_helper(None, None).unwrap();
        let lease = sample_lease();
        let data = ScriptData::for_lease(ACTION_ADD, &lease, None, SystemTime::now());
        helper.send(&data).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        // Dropping closes our write end, which is the EOF shutdown signal
        // the helper loop watches for (helper.c:199).
        drop(helper);
    }
}
