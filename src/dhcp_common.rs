//! DHCP common utilities — option parsing, netid matching, option building.
//! Ported from `dhcp-common.c`.

#[cfg(feature = "dhcp")]
use crate::dhcp_protocol::{OPTION_END, OPTION_MESSAGE_TYPE, OPTION_PAD, OPTION_VENDOR_ID};
#[cfg(feature = "dhcp")]
use crate::dhcp_protocol::DhcpMsgType;
#[cfg(feature = "dhcp")]
use crate::types::dhcp::{DhcpNetid, DhcpOpt};

/// Find a DHCP option by code in a packet's options field.
/// Returns a slice of the option data (not including code/len bytes).
#[cfg(feature = "dhcp")]
pub fn find_option(options: &[u8], code: u8) -> Option<&[u8]> {
    let mut i = 0;
    while i < options.len() {
        let opt = options[i];
        if opt == OPTION_PAD {
            i += 1;
            continue;
        }
        if opt == OPTION_END {
            break;
        }
        if i + 1 >= options.len() {
            break;
        }
        let len = options[i + 1] as usize;
        if i + 2 + len > options.len() {
            break;
        }
        if opt == code {
            return Some(&options[i + 2..i + 2 + len]);
        }
        i += 2 + len;
    }
    None
}

/// Find the message type (option 53) in a DHCP packet.
#[cfg(feature = "dhcp")]
pub fn get_message_type(options: &[u8]) -> Option<DhcpMsgType> {
    let data = find_option(options, OPTION_MESSAGE_TYPE)?;
    data.first().copied().and_then(DhcpMsgType::from_u8)
}

/// Match a set of netids against a DhcpNetid list.
/// Returns true if any tag in `tags` matches any in `list`.
#[cfg(feature = "dhcp")]
pub fn match_netid(tags: &[DhcpNetid], list: &[DhcpNetid]) -> bool {
    tags.iter().any(|t| list.iter().any(|l| l.net == t.net))
}

/// Parse a vendor class identifier (option 60).
#[cfg(feature = "dhcp")]
pub fn get_vendor_class(options: &[u8]) -> Option<String> {
    let data = find_option(options, OPTION_VENDOR_ID)?;
    String::from_utf8(data.to_vec()).ok()
}

/// Build a DHCP options block from a list of `DhcpOpt`.
/// Appends an OPTION_END (255) sentinel at the end.
#[cfg(feature = "dhcp")]
pub fn build_options(opts: &[DhcpOpt]) -> Vec<u8> {
    let mut out = Vec::new();
    for opt in opts {
        if let Some(val) = &opt.val {
            let code = opt.opt as u8;
            let len = val.len().min(255) as u8;
            out.push(code);
            out.push(len);
            out.extend_from_slice(&val[..len as usize]);
        }
    }
    out.push(OPTION_END);
    out
}

// ──────────────────────────────────────────────────────────────────────────────
// OT_* option-type flag constants (mirrors C's `#define OT_*` in dnsmasq.h)
// ──────────────────────────────────────────────────────────────────────────────

/// Option value is a list of IPv4 (or IPv6) addresses.
#[cfg(feature = "dhcp")]
pub const OT_ADDR_LIST:    u16 = 0x8000;
/// Option name is encoded in RFC 1035 wire format (DNS labels).
#[cfg(feature = "dhcp")]
pub const OT_RFC1035_NAME: u16 = 0x4000;
/// Option is handled internally by dnsmasq; not user-settable.
#[cfg(feature = "dhcp")]
pub const OT_INTERNAL:     u16 = 0x2000;
/// Option value is a human-readable string (printable ASCII).
#[cfg(feature = "dhcp")]
pub const OT_NAME:         u16 = 0x1000;
/// Option value is a NUL-separated counted string (DHCPv6 class data).
#[cfg(feature = "dhcp")]
pub const OT_CSTRING:      u16 = 0x0800;
/// Option value should be displayed as an unsigned decimal integer.
#[cfg(feature = "dhcp")]
pub const OT_DEC:          u16 = 0x0400;
/// Option value is a time interval in seconds (displayed as "Xs" or "Xm").
#[cfg(feature = "dhcp")]
pub const OT_TIME:         u16 = 0x0200;

// ──────────────────────────────────────────────────────────────────────────────
// Option table (opttab / opttab6)
// ──────────────────────────────────────────────────────────────────────────────

/// One row in the DHCP option name↔number table.
#[cfg(feature = "dhcp")]
#[derive(Debug, Clone, Copy)]
pub struct DhcpOptEntry {
    /// Human-readable option name used on the command line.
    pub name: &'static str,
    /// DHCP option number (RFC 2132 code).
    pub val:  u16,
    /// Combination of `OT_*` flags plus an optional fixed size in the low bits.
    pub size: u16,
}

/// DHCPv4 option name/number table.
///
/// Mirrors C's static `opttab[]`.
#[cfg(feature = "dhcp")]
pub static OPTTAB: &[DhcpOptEntry] = &[
    DhcpOptEntry { name: "netmask",                   val: 1,   size: OT_ADDR_LIST },
    DhcpOptEntry { name: "time-offset",               val: 2,   size: 4 },
    DhcpOptEntry { name: "router",                    val: 3,   size: OT_ADDR_LIST },
    DhcpOptEntry { name: "dns-server",                val: 6,   size: OT_ADDR_LIST },
    DhcpOptEntry { name: "log-server",                val: 7,   size: OT_ADDR_LIST },
    DhcpOptEntry { name: "lpr-server",                val: 9,   size: OT_ADDR_LIST },
    DhcpOptEntry { name: "hostname",                  val: 12,  size: OT_INTERNAL | OT_NAME },
    DhcpOptEntry { name: "boot-file-size",            val: 13,  size: 2 | OT_DEC },
    DhcpOptEntry { name: "domain-name",               val: 15,  size: OT_NAME },
    DhcpOptEntry { name: "swap-server",               val: 16,  size: OT_ADDR_LIST },
    DhcpOptEntry { name: "root-path",                 val: 17,  size: OT_NAME },
    DhcpOptEntry { name: "extension-path",            val: 18,  size: OT_NAME },
    DhcpOptEntry { name: "ip-forward-enable",         val: 19,  size: 1 },
    DhcpOptEntry { name: "non-local-source-routing",  val: 20,  size: 1 },
    DhcpOptEntry { name: "policy-filter",             val: 21,  size: OT_ADDR_LIST },
    DhcpOptEntry { name: "max-datagram-reassembly",   val: 22,  size: 2 | OT_DEC },
    DhcpOptEntry { name: "default-ttl",               val: 23,  size: 1 | OT_DEC },
    DhcpOptEntry { name: "mtu",                       val: 26,  size: 2 | OT_DEC },
    DhcpOptEntry { name: "all-subnets-local",         val: 27,  size: 1 },
    DhcpOptEntry { name: "broadcast",                 val: 28,  size: OT_INTERNAL | OT_ADDR_LIST },
    DhcpOptEntry { name: "router-discovery",          val: 31,  size: 1 },
    DhcpOptEntry { name: "router-solicitation",       val: 32,  size: OT_ADDR_LIST },
    DhcpOptEntry { name: "static-route",              val: 33,  size: OT_ADDR_LIST },
    DhcpOptEntry { name: "trailer-encapsulation",     val: 34,  size: 1 },
    DhcpOptEntry { name: "arp-timeout",               val: 35,  size: 4 | OT_DEC },
    DhcpOptEntry { name: "ethernet-encap",            val: 36,  size: 1 },
    DhcpOptEntry { name: "tcp-ttl",                   val: 37,  size: 1 },
    DhcpOptEntry { name: "tcp-keepalive",             val: 38,  size: 4 | OT_DEC },
    DhcpOptEntry { name: "nis-domain",                val: 40,  size: OT_NAME },
    DhcpOptEntry { name: "nis-server",                val: 41,  size: OT_ADDR_LIST },
    DhcpOptEntry { name: "ntp-server",                val: 42,  size: OT_ADDR_LIST },
    DhcpOptEntry { name: "vendor-encap",              val: 43,  size: OT_INTERNAL },
    DhcpOptEntry { name: "netbios-ns",                val: 44,  size: OT_ADDR_LIST },
    DhcpOptEntry { name: "netbios-dd",                val: 45,  size: OT_ADDR_LIST },
    DhcpOptEntry { name: "netbios-nodetype",          val: 46,  size: 1 },
    DhcpOptEntry { name: "netbios-scope",             val: 47,  size: 0 },
    DhcpOptEntry { name: "x-windows-fs",              val: 48,  size: OT_ADDR_LIST },
    DhcpOptEntry { name: "x-windows-dm",              val: 49,  size: OT_ADDR_LIST },
    DhcpOptEntry { name: "requested-address",         val: 50,  size: OT_INTERNAL | OT_ADDR_LIST },
    DhcpOptEntry { name: "lease-time",                val: 51,  size: OT_INTERNAL | OT_TIME },
    DhcpOptEntry { name: "option-overload",           val: 52,  size: OT_INTERNAL },
    DhcpOptEntry { name: "message-type",              val: 53,  size: OT_INTERNAL | OT_DEC },
    DhcpOptEntry { name: "server-identifier",         val: 54,  size: OT_INTERNAL | OT_ADDR_LIST },
    DhcpOptEntry { name: "parameter-request",         val: 55,  size: OT_INTERNAL },
    DhcpOptEntry { name: "message",                   val: 56,  size: OT_INTERNAL },
    DhcpOptEntry { name: "max-message-size",          val: 57,  size: OT_INTERNAL },
    DhcpOptEntry { name: "T1",                        val: 58,  size: OT_TIME },
    DhcpOptEntry { name: "T2",                        val: 59,  size: OT_TIME },
    DhcpOptEntry { name: "vendor-class",              val: 60,  size: 0 },
    DhcpOptEntry { name: "client-id",                 val: 61,  size: OT_INTERNAL },
    DhcpOptEntry { name: "nis+-domain",               val: 64,  size: OT_NAME },
    DhcpOptEntry { name: "nis+-server",               val: 65,  size: OT_ADDR_LIST },
    DhcpOptEntry { name: "tftp-server",               val: 66,  size: OT_NAME },
    DhcpOptEntry { name: "bootfile-name",             val: 67,  size: OT_NAME },
    DhcpOptEntry { name: "mobile-ip-home",            val: 68,  size: OT_ADDR_LIST },
    DhcpOptEntry { name: "smtp-server",               val: 69,  size: OT_ADDR_LIST },
    DhcpOptEntry { name: "pop3-server",               val: 70,  size: OT_ADDR_LIST },
    DhcpOptEntry { name: "nntp-server",               val: 71,  size: OT_ADDR_LIST },
    DhcpOptEntry { name: "irc-server",                val: 74,  size: OT_ADDR_LIST },
    DhcpOptEntry { name: "user-class",                val: 77,  size: 0 },
    DhcpOptEntry { name: "rapid-commit",              val: 80,  size: 0 },
    DhcpOptEntry { name: "FQDN",                      val: 81,  size: OT_INTERNAL },
    DhcpOptEntry { name: "agent-info",                val: 82,  size: OT_INTERNAL },
    DhcpOptEntry { name: "last-transaction",          val: 91,  size: 4 | OT_TIME },
    DhcpOptEntry { name: "associated-ip",             val: 92,  size: OT_ADDR_LIST },
    DhcpOptEntry { name: "client-arch",               val: 93,  size: 2 | OT_DEC },
    DhcpOptEntry { name: "client-interface-id",       val: 94,  size: 0 },
    DhcpOptEntry { name: "client-machine-id",         val: 97,  size: 0 },
    DhcpOptEntry { name: "posix-timezone",            val: 100, size: OT_NAME },
    DhcpOptEntry { name: "tzdb-timezone",             val: 101, size: OT_NAME },
    DhcpOptEntry { name: "ipv6-only",                 val: 108, size: 4 | OT_DEC },
    DhcpOptEntry { name: "captive-portal",            val: 114, size: OT_NAME },
    DhcpOptEntry { name: "subnet-select",             val: 118, size: OT_INTERNAL },
    DhcpOptEntry { name: "domain-search",             val: 119, size: OT_RFC1035_NAME },
    DhcpOptEntry { name: "sip-server",                val: 120, size: 0 },
    DhcpOptEntry { name: "classless-static-route",    val: 121, size: 0 },
    DhcpOptEntry { name: "vendor-id-encap",           val: 125, size: 0 },
    DhcpOptEntry { name: "tftp-server-address",       val: 150, size: OT_ADDR_LIST },
    DhcpOptEntry { name: "server-ip-address",         val: 255, size: OT_ADDR_LIST },
];

/// DHCPv6 option name/number table.
///
/// Mirrors C's static `opttab6[]`.
#[cfg(all(feature = "dhcp", feature = "dhcp6"))]
pub static OPTTAB6: &[DhcpOptEntry] = &[
    DhcpOptEntry { name: "client-id",                 val: 1,  size: OT_INTERNAL },
    DhcpOptEntry { name: "server-id",                 val: 2,  size: OT_INTERNAL },
    DhcpOptEntry { name: "ia-na",                     val: 3,  size: OT_INTERNAL },
    DhcpOptEntry { name: "ia-ta",                     val: 4,  size: OT_INTERNAL },
    DhcpOptEntry { name: "iaaddr",                    val: 5,  size: OT_INTERNAL },
    DhcpOptEntry { name: "oro",                       val: 6,  size: OT_INTERNAL },
    DhcpOptEntry { name: "preference",                val: 7,  size: OT_INTERNAL | OT_DEC },
    DhcpOptEntry { name: "unicast",                   val: 12, size: OT_INTERNAL },
    DhcpOptEntry { name: "status",                    val: 13, size: OT_INTERNAL },
    DhcpOptEntry { name: "rapid-commit",              val: 14, size: OT_INTERNAL },
    DhcpOptEntry { name: "user-class",                val: 15, size: OT_INTERNAL | OT_CSTRING },
    DhcpOptEntry { name: "vendor-class",              val: 16, size: OT_INTERNAL | OT_CSTRING },
    DhcpOptEntry { name: "vendor-opts",               val: 17, size: OT_INTERNAL },
    DhcpOptEntry { name: "sip-server-domain",         val: 21, size: OT_RFC1035_NAME },
    DhcpOptEntry { name: "sip-server",                val: 22, size: OT_ADDR_LIST },
    DhcpOptEntry { name: "dns-server",                val: 23, size: OT_ADDR_LIST },
    DhcpOptEntry { name: "domain-search",             val: 24, size: OT_RFC1035_NAME },
    DhcpOptEntry { name: "nis-server",                val: 27, size: OT_ADDR_LIST },
    DhcpOptEntry { name: "nis+-server",               val: 28, size: OT_ADDR_LIST },
    DhcpOptEntry { name: "nis-domain",                val: 29, size: OT_RFC1035_NAME },
    DhcpOptEntry { name: "nis+-domain",               val: 30, size: OT_RFC1035_NAME },
    DhcpOptEntry { name: "sntp-server",               val: 31, size: OT_ADDR_LIST },
    DhcpOptEntry { name: "information-refresh-time",  val: 32, size: OT_TIME },
    DhcpOptEntry { name: "FQDN",                      val: 39, size: OT_INTERNAL | OT_RFC1035_NAME },
    DhcpOptEntry { name: "posix-timezone",            val: 41, size: OT_NAME },
    DhcpOptEntry { name: "tzdb-timezone",             val: 42, size: OT_NAME },
    DhcpOptEntry { name: "ntp-server",                val: 56, size: 0 },
    DhcpOptEntry { name: "bootfile-url",              val: 59, size: OT_NAME },
    DhcpOptEntry { name: "bootfile-param",            val: 60, size: OT_CSTRING },
    DhcpOptEntry { name: "captive-portal",            val: 103,size: OT_NAME },
];

// ──────────────────────────────────────────────────────────────────────────────
// Lookup helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Find the option number for a given name (case-insensitive).
///
/// `is_v6` selects the DHCPv6 table; otherwise DHCPv4 is used.
/// Returns `None` if not found.
///
/// Mirrors C's `lookup_dhcp_opt()`.
#[cfg(feature = "dhcp")]
pub fn lookup_dhcp_opt(#[allow(unused_variables)] is_v6: bool, name: &str) -> Option<u16> {
    let table: &[DhcpOptEntry] = {
        #[cfg(all(feature = "dhcp", feature = "dhcp6"))]
        if is_v6 { return OPTTAB6.iter().find(|e| e.name.eq_ignore_ascii_case(name)).map(|e| e.val); }
        OPTTAB
    };
    table.iter().find(|e| e.name.eq_ignore_ascii_case(name)).map(|e| e.val)
}

/// Look up the raw `size` field for option number `val`.
///
/// The low bits of `size` encode a fixed byte count; the high bits are `OT_*`
/// flags.  Returns 0 if not found.
///
/// Mirrors C's `lookup_dhcp_len()`.
#[cfg(feature = "dhcp")]
pub fn lookup_dhcp_len(#[allow(unused_variables)] is_v6: bool, val: u16) -> u16 {
    let table: &[DhcpOptEntry] = {
        #[cfg(all(feature = "dhcp", feature = "dhcp6"))]
        if is_v6 {
            return OPTTAB6.iter().find(|e| e.val == val).map(|e| e.size & !(OT_DEC)).unwrap_or(0);
        }
        OPTTAB
    };
    table.iter().find(|e| e.val == val).map(|e| e.size & !(OT_DEC)).unwrap_or(0)
}

// ──────────────────────────────────────────────────────────────────────────────
// display_opts / display_opts6
// ──────────────────────────────────────────────────────────────────────────────

/// Return a `Vec<(number, name)>` of all user-visible DHCPv4 options.
///
/// Mirrors C's `display_opts()` but returns data instead of printing directly,
/// making it more testable.
#[cfg(feature = "dhcp")]
pub fn display_opts() -> Vec<(u16, &'static str)> {
    OPTTAB
        .iter()
        .filter(|e| (e.size & OT_INTERNAL) == 0)
        .map(|e| (e.val, e.name))
        .collect()
}

/// Return a `Vec<(number, name)>` of all user-visible DHCPv6 options.
///
/// Mirrors C's `display_opts6()`.
#[cfg(all(feature = "dhcp", feature = "dhcp6"))]
pub fn display_opts6() -> Vec<(u16, &'static str)> {
    OPTTAB6
        .iter()
        .filter(|e| (e.size & OT_INTERNAL) == 0)
        .map(|e| (e.val, e.name))
        .collect()
}

// ──────────────────────────────────────────────────────────────────────────────
// option_string — format option value for logging / display
// ──────────────────────────────────────────────────────────────────────────────

/// Format a DHCP option value as a human-readable string.
///
/// Uses the `OT_*` type flags in `OPTTAB` to decide how to decode `val`:
/// - `OT_ADDR_LIST` → comma-separated IPv4 addresses
/// - `OT_NAME`      → printable ASCII string
/// - `OT_DEC`       → big-endian decimal integer
/// - `OT_TIME`      → seconds, formatted as "Xs" or "Xm Ys"
/// - anything else  → hex bytes
///
/// Mirrors C's `option_string()`.
#[cfg(feature = "dhcp")]
pub fn option_string(is_v6: bool, opt: u16, val: &[u8]) -> String {
    let _ = is_v6;
    let table: &[DhcpOptEntry] = OPTTAB;
    let entry = table.iter().find(|e| e.val == opt);
    let size_flags = entry.map(|e| e.size).unwrap_or(0);

    if (size_flags & OT_ADDR_LIST) != 0 && val.len() >= 4 && !is_v6 {
        // IPv4 address list
        return val
            .chunks(4)
            .filter(|c| c.len() == 4)
            .map(|c| format!("{}.{}.{}.{}", c[0], c[1], c[2], c[3]))
            .collect::<Vec<_>>()
            .join(", ");
    }

    if (size_flags & OT_NAME) != 0 {
        // Printable ASCII string
        return val
            .iter()
            .filter(|&&b| b.is_ascii_graphic() || b == b' ')
            .map(|&b| b as char)
            .collect();
    }

    if (size_flags & OT_DEC) != 0 {
        // Big-endian unsigned integer
        let n: u64 = val.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
        return n.to_string();
    }

    if (size_flags & OT_TIME) != 0 {
        let secs: u32 = val.iter().take(4).fold(0u32, |acc, &b| (acc << 8) | u32::from(b));
        return format_time(secs);
    }

    // Default: hex dump
    val.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

/// Format a time in seconds as a human-readable duration string.
///
/// e.g. `3661` → `"1h 1m 1s"`.  Used by `option_string` for `OT_TIME` options.
#[cfg(feature = "dhcp")]
pub fn format_time(secs: u32) -> String {
    if secs == 0 {
        return "0s".into();
    }
    let mut parts = Vec::new();
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 { parts.push(format!("{h}h")); }
    if m > 0 { parts.push(format!("{m}m")); }
    if s > 0 { parts.push(format!("{s}s")); }
    parts.join(" ")
}

// ──────────────────────────────────────────────────────────────────────────────
// dhcp_update_configs — fill in addresses from /etc/hosts for static configs
// ──────────────────────────────────────────────────────────────────────────────

/// Update static DHCP configurations whose address was not explicitly set by
/// looking up matching hostnames in the DNS cache.
///
/// For every `DhcpConfig` that has `CONFIG_NAME` but not `CONFIG_ADDR`, if
/// a forward A record with `F_HOSTS` exists in `cache`, the config is
/// updated with that address and `CONFIG_ADDR | CONFIG_ADDR_HOSTS` are set.
///
/// Mirrors C's `dhcp_update_configs()`.
#[cfg(feature = "dhcp")]
pub fn dhcp_update_configs(
    configs: &mut Vec<crate::types::dhcp::DhcpConfig>,
    cache:   &mut crate::cache::DnsCache,
    now:     std::time::Instant,
) {
    use crate::types::dhcp::{CONFIG_ADDR, CONFIG_ADDR_HOSTS, CONFIG_NAME};
    use crate::types::constants::{F_HOSTS, F_IPV4};

    // Reset any previously auto-assigned addresses.
    for c in configs.iter_mut() {
        if (c.flags & CONFIG_ADDR_HOSTS) != 0 {
            c.flags &= !(CONFIG_ADDR | CONFIG_ADDR_HOSTS);
        }
    }

    // For each config that has a name but no address, try the cache.
    for i in 0..configs.len() {
        if (configs[i].flags & CONFIG_ADDR) != 0 {
            continue; // already has an explicit address
        }
        if (configs[i].flags & CONFIG_NAME) == 0 {
            continue; // no hostname to look up
        }
        let hostname = match &configs[i].hostname {
            Some(h) => h.clone(),
            None => continue,
        };

        // Find a hosts-file A record.
        let found_ip = crate::cache::a_record_from_hosts(&hostname, now, cache);
        if let Some(ip) = found_ip {
            // Make sure no other config already uses this address.
            let conflict = configs
                .iter()
                .enumerate()
                .any(|(j, c)| j != i && (c.flags & CONFIG_ADDR) != 0 && c.addr == ip);
            if !conflict {
                configs[i].addr   = ip;
                configs[i].flags |= CONFIG_ADDR | CONFIG_ADDR_HOSTS;
            }
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Socket / device-binding helpers
// (ported from dhcp-common.c: recv_dhcp_packet, bindtodevice,
//  bind_dhcp_devices, whichdevice)
// ──────────────────────────────────────────────────────────────────────────────

/// Read a UDP DHCP packet from `fd` using `recvmsg`.
///
/// Uses `MSG_PEEK | MSG_TRUNC` first to determine the actual packet size, then
/// expands the buffer if necessary and performs the real `recvmsg`.  Fills
/// `src_addr` (sender's IP:port) and `dst_info` (destination IP and interface
/// index, extracted from `IP_PKTINFO` / `IPV6_PKTINFO` control messages).
///
/// Returns the packet payload on success, or `Err` on I/O failure or truncation.
///
/// Mirrors `recv_dhcp_packet()` in `dhcp-common.c`.
#[cfg(all(feature = "dhcp", unix))]
pub fn recv_dhcp_packet(
    fd: std::os::unix::io::RawFd,
) -> std::io::Result<(Vec<u8>, std::net::SocketAddr, Option<(std::net::IpAddr, u32)>)> {
    use std::io;
    use std::mem;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

    // Control-message buffer large enough for IP_PKTINFO or in6_pktinfo.
    let mut ctrl_buf = vec![0u8; 256];
    let mut iov_buf  = vec![0u8; 1500];

    loop {
        let mut src_storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let mut iov = libc::iovec {
            iov_base: iov_buf.as_mut_ptr() as *mut libc::c_void,
            iov_len:  iov_buf.len(),
        };
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_name       = &mut src_storage as *mut _ as *mut libc::c_void;
        msg.msg_namelen    = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        msg.msg_iov        = &mut iov as *mut libc::iovec;
        msg.msg_iovlen     = 1;
        msg.msg_control    = ctrl_buf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = ctrl_buf.len() as _;

        // Peek to discover actual size.
        let peek_sz = loop {
            let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_PEEK | libc::MSG_TRUNC) };
            if n == -1 {
                let e = io::Error::last_os_error();
                if e.kind() != io::ErrorKind::Interrupted { return Err(e); }
            } else {
                break n as usize;
            }
        };

        if msg.msg_flags & libc::MSG_TRUNC != 0 {
            // Buffer was too small — grow and retry.
            let new_size = (peek_sz + 100).max(iov_buf.len() + 100);
            iov_buf.resize(new_size, 0);
            continue;
        }

        // Real receive.
        let sz = loop {
            let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
            if n == -1 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted { continue; }
                // EAGAIN/EWOULDBLOCK: kernel dequeued on peek; use peek result.
                if e.kind() == io::ErrorKind::WouldBlock { break peek_sz; }
                return Err(e);
            }
            break n as usize;
        };

        if msg.msg_flags & libc::MSG_TRUNC != 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "DHCP packet truncated"));
        }

        // Decode source address.
        let src_addr = match unsafe { src_storage.ss_family as libc::c_int } {
            libc::AF_INET => {
                let sin = unsafe { &*((&src_storage) as *const _ as *const libc::sockaddr_in) };
                let ip  = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                let port = u16::from_be(sin.sin_port);
                SocketAddr::V4(SocketAddrV4::new(ip, port))
            }
            libc::AF_INET6 => {
                let sin6 = unsafe { &*((&src_storage) as *const _ as *const libc::sockaddr_in6) };
                let ip   = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                let port = u16::from_be(sin6.sin6_port);
                SocketAddr::V6(SocketAddrV6::new(ip, port, 0, sin6.sin6_scope_id))
            }
            _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "unknown address family")),
        };

        // Extract destination address and interface index from control messages.
        let mut dst_info: Option<(IpAddr, u32)> = None;

        unsafe {
            let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
            while !cmsg.is_null() {
                let level = (*cmsg).cmsg_level;
                let kind  = (*cmsg).cmsg_type;
                #[cfg(target_os = "linux")]
                if level == libc::IPPROTO_IP && kind == libc::IP_PKTINFO {
                    let pktinfo = libc::CMSG_DATA(cmsg) as *const libc::in_pktinfo;
                    let addr    = Ipv4Addr::from(u32::from_be((*pktinfo).ipi_addr.s_addr));
                    let iface   = (*pktinfo).ipi_ifindex as u32;
                    dst_info    = Some((IpAddr::V4(addr), iface));
                }
                if level == libc::IPPROTO_IPV6 && kind == libc::IPV6_PKTINFO {
                    let pktinfo = libc::CMSG_DATA(cmsg) as *const libc::in6_pktinfo;
                    let addr    = Ipv6Addr::from((*pktinfo).ipi6_addr.s6_addr);
                    let iface   = (*pktinfo).ipi6_ifindex;
                    dst_info    = Some((IpAddr::V6(addr), iface));
                }
                cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
            }
        }

        return Ok((iov_buf[..sz].to_vec(), src_addr, dst_info));
    }
}

/// Non-Unix stub.
#[cfg(all(feature = "dhcp", not(unix)))]
pub fn recv_dhcp_packet(
    _fd: i32,
) -> std::io::Result<(Vec<u8>, std::net::SocketAddr, Option<(std::net::IpAddr, u32)>)> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "recv_dhcp_packet not supported on this platform",
    ))
}

/// Bind a socket to a specific network interface using `SO_BINDTODEVICE`.
///
/// Only effective on Linux and only permitted for root processes.
/// Returns:
/// - `Ok(true)`  — bound successfully.
/// - `Ok(false)` — failed with `EPERM` (not root); silently ignored.
/// - `Err`       — any other error.
///
/// Mirrors `bindtodevice()` in `dhcp-common.c`.
#[cfg(all(feature = "dhcp", all(unix, target_os = "linux")))]
pub fn bindtodevice(
    device: &str,
    fd: std::os::unix::io::RawFd,
) -> std::io::Result<bool> {
    use std::io;
    use std::ffi::CString;

    let cdev = CString::new(device).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "device name contains NUL")
    })?;
    let len = (cdev.as_bytes_with_nul().len()).min(libc::IFNAMSIZ);
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            cdev.as_ptr() as *const libc::c_void,
            len as libc::socklen_t,
        )
    };
    if rc == -1 {
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::PermissionDenied {
            return Ok(false);
        }
        return Err(e);
    }
    Ok(true)
}

/// No-op stub for non-Linux / non-Unix targets.
#[cfg(all(feature = "dhcp", not(all(unix, target_os = "linux"))))]
pub fn bindtodevice(_device: &str, _fd: i32) -> std::io::Result<bool> {
    Ok(false)
}

/// Bind all DHCP listening sockets to the given network interface.
///
/// `fds` is a slice of `(fd, is_dhcp6)` pairs.  When `bound_device` is
/// `None`, no binding is performed and `0` is returned.
///
/// Returns a bitmask where set bits indicate individual `bindtodevice` calls
/// that returned `Ok(false)` (permission denied) — matching the C semantics
/// where non-zero means "some binds succeeded at a lower privilege level".
///
/// Mirrors `bind_dhcp_devices()` in `dhcp-common.c`.
#[cfg(feature = "dhcp")]
pub fn bind_dhcp_devices(
    bound_device: Option<&str>,
    fds: &[(i32, bool)],   // (fd, is_dhcp6)
) -> u32 {
    let device = match bound_device {
        Some(d) => d,
        None    => return 0,
    };
    let mut ret: u32 = 0;
    for &(fd, _is_dhcp6) in fds {
        match bindtodevice(device, fd) {
            Ok(false) => ret |= 2, // EPERM — matches C returning 2
            Ok(true)  => {}
            Err(_)    => ret |= 1,
        }
    }
    ret
}

/// Determine which single network interface all DHCP sockets should be bound
/// to, if any.
///
/// Returns `Some(name)` only when exactly one interface name is configured
/// with no wildcards and all active DHCP interfaces share the same name.
/// Returns `None` in all other cases (multiple interfaces, wildcards, or no
/// explicit `--interface` specified).
///
/// Mirrors `whichdevice()` in `dhcp-common.c`.
#[cfg(feature = "dhcp")]
pub fn whichdevice(if_names: &[String], active_ifaces: &[String]) -> Option<String> {
    // If no explicit interface names configured, can't bind to a single device.
    if if_names.is_empty() { return None; }

    // Any wildcard interface name means we can't assert a single interface.
    if if_names.iter().any(|n| n.contains('*')) { return None; }

    // Find the unique interface name among active DHCP interfaces.
    let mut found: Option<&str> = None;
    for name in active_ifaces {
        match found {
            None => found = Some(name.as_str()),
            Some(f) if f == name.as_str() => {}
            Some(_) => return None, // more than one distinct interface
        }
    }

    found.map(|s| s.to_string())
}

// ─── Tag helpers ──────────────────────────────────────────────────────────────

/// A conditional tag-setting rule: if all tags in `tag` are present, add all
/// tags in `set` to the active tag list.
///
/// Mirrors dnsmasq's `struct tag_if`.
#[cfg(feature = "dhcp")]
#[derive(Debug, Clone)]
pub struct TagIf {
    /// Required tags (matched with `match_netid_wild`).
    pub tag: Vec<DhcpNetid>,
    /// Tags to inject when the condition is satisfied.
    pub set: Vec<DhcpNetid>,
}

/// Wildcard-aware netid matching.
///
/// Returns `true` if every member of `check` is satisfied by at least one
/// member of `pool`:
/// - A tag ending in `'*'` is a prefix match.
/// - A tag starting with `'!'` or `'#'` is a negation: the tag must NOT be
///   present in `pool`.
///
/// Mirrors `match_netid_wild()` in `dhcp-common.c`.
#[cfg(feature = "dhcp")]
pub fn match_netid_wild(check: &[DhcpNetid], pool: &[DhcpNetid]) -> bool {
    for item in check {
        let net = &item.net;
        let negated = net.starts_with('!') || net.starts_with('#');
        let effective = if negated { &net[1..] } else { net.as_str() };
        let wildcard  = effective.ends_with('*');
        let prefix    = if wildcard { &effective[..effective.len() - 1] } else { effective };

        if !negated {
            // Positive: must find a match in pool.
            let found = pool.iter().any(|p| {
                if wildcard { p.net.starts_with(prefix) } else { p.net == effective }
            });
            if !found { return false; }
        } else {
            // Negated: must NOT find a match in pool.
            let found = pool.iter().any(|p| {
                if wildcard { p.net.starts_with(prefix) } else { p.net == effective }
            });
            if found { return false; }
        }
    }
    true
}

/// Evaluate tag-if rules and expand the active tag list.
///
/// For each rule in `rules` whose condition (`tag`) is satisfied by the
/// current `tags`, append the rule's `set` tags to the active list.
///
/// Returns the expanded tag list (original tags plus any newly injected ones).
///
/// Mirrors `run_tag_if()` in `dhcp-common.c`.
#[cfg(feature = "dhcp")]
pub fn run_tag_if(tags: Vec<DhcpNetid>, rules: &[TagIf]) -> Vec<DhcpNetid> {
    let mut result = tags;
    for rule in rules {
        if match_netid_wild(&rule.tag, &result) {
            for new_tag in &rule.set {
                // Only add if not already present (de-duplicate).
                if !result.iter().any(|t| t.net == new_tag.net) {
                    result.push(new_tag.clone());
                }
            }
        }
    }
    result
}

/// PXE mode filter for a DHCP option.
///
/// - `pxemode == 0` → skip PXE-only options; include everything else.
/// - `pxemode == 1` → include PXE-only options AND regular options.
/// - `pxemode == 2` → include ONLY PXE-only options.
///
/// Returns `true` if the option should be included in the current mode.
///
/// Mirrors `pxe_ok()` in `dhcp-common.c`.
#[cfg(feature = "dhcp")]
pub fn pxe_ok(opt: &DhcpOpt, pxemode: u8) -> bool {
    use crate::types::dhcp::DHOPT_PXE_OPT;
    if opt.flags & DHOPT_PXE_OPT != 0 {
        pxemode != 0
    } else {
        pxemode != 2
    }
}

/// Mark options that are valid for the current network tag set.
///
/// Sets or clears the `DHOPT_TAGOK` flag on each option in `opts` according to
/// whether its `netid` matches the active tag list (after tag-if expansion) and
/// the PXE mode.
///
/// Returns the expanded tag list (after `run_tag_if`).
///
/// Mirrors `option_filter()` in `dhcp-common.c`.
#[cfg(feature = "dhcp")]
pub fn option_filter(
    tags:         Vec<DhcpNetid>,
    context_tags: Option<Vec<DhcpNetid>>,
    opts:         &mut Vec<DhcpOpt>,
    pxemode:      u8,
    tag_rules:    &[TagIf],
) -> Vec<DhcpNetid> {
    use crate::types::dhcp::{DHOPT_ENCAPSULATE, DHOPT_RFC3925, DHOPT_TAGOK, DHOPT_VENDOR};

    let tagif = run_tag_if(tags, tag_rules);

    // Phase 1: mark options valid for tagif (without context tags).
    for opt in opts.iter_mut() {
        opt.flags &= !DHOPT_TAGOK;
        if opt.flags & (DHOPT_ENCAPSULATE | DHOPT_VENDOR | DHOPT_RFC3925) != 0 {
            continue;
        }
        let netid_matches = match &opt.netid {
            None        => false, // untagged options handled in phase 3
            Some(netid) => {
                let single = std::slice::from_ref(netid);
                match_netid_wild(single, &tagif)
            }
        };
        if netid_matches && pxe_ok(opt, pxemode) {
            opt.flags |= DHOPT_TAGOK;
        }
    }

    // Phase 2: apply context tags (if provided).
    if let Some(mut ctx) = context_tags {
        ctx.extend(tagif.iter().cloned());
        let tagif_ctx = run_tag_if(ctx, tag_rules);

        // Reset options that previously matched but now fail with context tags.
        for opt in opts.iter_mut() {
            if opt.flags & (DHOPT_ENCAPSULATE | DHOPT_VENDOR | DHOPT_RFC3925) != 0 { continue; }
            if opt.flags & DHOPT_TAGOK == 0 { continue; }
            let still_ok = match &opt.netid {
                None        => true,
                Some(netid) => match_netid_wild(std::slice::from_ref(netid), &tagif_ctx),
            };
            if !still_ok { opt.flags &= !DHOPT_TAGOK; }
        }

        // Mark options that only match with the context tags.
        let opt_codes: Vec<i32> = opts.iter()
            .filter(|o| o.flags & DHOPT_TAGOK != 0)
            .map(|o| o.opt)
            .collect();
        for opt in opts.iter_mut() {
            if opt.flags & (DHOPT_ENCAPSULATE | DHOPT_VENDOR | DHOPT_RFC3925 | DHOPT_TAGOK) != 0 { continue; }
            let matches = match &opt.netid {
                None        => false,
                Some(netid) => match_netid_wild(std::slice::from_ref(netid), &tagif_ctx),
            };
            if matches && pxe_ok(opt, pxemode) && !opt_codes.contains(&opt.opt) {
                opt.flags |= DHOPT_TAGOK;
            }
        }
    }

    // Phase 3: mark untagged options not overridden by a tagged one.
    let tagged_codes: Vec<i32> = opts.iter()
        .filter(|o| o.flags & DHOPT_TAGOK != 0 && o.netid.is_some())
        .map(|o| o.opt)
        .collect();
    for opt in opts.iter_mut() {
        if opt.flags & (DHOPT_ENCAPSULATE | DHOPT_VENDOR | DHOPT_RFC3925 | DHOPT_TAGOK) != 0 { continue; }
        if opt.netid.is_some() { continue; } // has a tag, skip
        if pxe_ok(opt, pxemode) && !tagged_codes.contains(&opt.opt) {
            opt.flags |= DHOPT_TAGOK;
        }
    }

    // Phase 4: de-duplicate — later entries for the same opt code lose TAGOK.
    let mut seen: std::collections::HashSet<i32> = std::collections::HashSet::new();
    for opt in opts.iter_mut() {
        if opt.flags & DHOPT_TAGOK != 0 {
            if !seen.insert(opt.opt) {
                opt.flags &= !DHOPT_TAGOK;
            }
        }
    }

    tagif
}

/// Split a hostname at the first dot, returning `(hostname, domain)`.
///
/// If there is no dot the full input is returned as the hostname and the
/// domain is `None`.  If the part after the dot is empty, `domain` is `None`.
///
/// Mirrors `strip_hostname()` in `dhcp-common.c`.
#[cfg(feature = "dhcp")]
pub fn strip_hostname(hostname: &str) -> (&str, Option<&str>) {
    match hostname.find('.') {
        None => (hostname, None),
        Some(pos) => {
            let name   = &hostname[..pos];
            let domain = &hostname[pos + 1..];
            (name, if domain.is_empty() { None } else { Some(domain) })
        }
    }
}

/// Build a comma-separated tag list string from a slice of `DhcpNetid`.
///
/// Duplicate tag names are collapsed (first occurrence wins).  Returns `None`
/// if the list is empty.
///
/// Mirrors the log-building loop in `log_tags()` in `dhcp-common.c`, but
/// returns a `String` instead of calling `my_syslog` so callers can decide
/// how to log.
#[cfg(feature = "dhcp")]
pub fn log_tags(netids: &[DhcpNetid]) -> Option<String> {
    if netids.is_empty() { return None; }
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let parts: Vec<&str> = netids.iter()
        .filter_map(|n| {
            if seen.contains(n.net.as_str()) { None }
            else { seen.insert(&n.net); Some(n.net.as_str()) }
        })
        .collect();
    if parts.is_empty() { None } else { Some(parts.join(", ")) }
}

/// Check whether a DHCP option's value matches a data buffer.
///
/// - If `opt.val` is `None` or empty, it matches anything (`len > 0` check
///   only — mirrors `o->len == 0` case returning 1 in C).
/// - If `DHOPT_HEX` is set, uses masked comparison (`memcmp_masked`).
/// - Otherwise scans for the value as a substring (byte-string match), with
///   `DHOPT_STRING` mode advancing one byte at a time, and hex mode advancing
///   by `val.len()` at a time.
///
/// Mirrors `match_bytes()` in `dhcp-common.c`.
#[cfg(feature = "dhcp")]
pub fn match_bytes(opt: &DhcpOpt, data: &[u8]) -> bool {
    use crate::types::dhcp::{DHOPT_HEX, DHOPT_STRING};
    use crate::util::memcmp_masked;

    let val = match &opt.val {
        None    => return true,
        Some(v) => v,
    };
    if val.is_empty() { return true; }
    if val.len() > data.len() { return false; }

    if opt.flags & DHOPT_HEX != 0 {
        // Wildcard/masked comparison using the first u32 of val as a mask.
        // In C the mask is stored in opt->u.wildcard_mask; here we treat
        // the first 4 bytes of val as both value and derive a mask of all-ones.
        let mask: u32 = 0xFFFF_FFFF;
        return memcmp_masked(val, data, mask) != 0;
    }

    // Substring scan.
    let step = if opt.flags & DHOPT_STRING != 0 { 1 } else { val.len() };
    let mut i = 0;
    while i + val.len() <= data.len() {
        if data[i..i + val.len()] == val[..] {
            return true;
        }
        i += step;
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
// Config matching (ported from dhcp-common.c:320-451)
// ─────────────────────────────────────────────────────────────────────────────

/// Check if a DHCP config entry has a matching hardware address.
///
/// Compares against all hwaddr entries in the config, ignoring wildcard entries.
/// Port of `config_has_mac()` from dhcp-common.c:320-332.
pub fn config_has_mac(config: &crate::types::dhcp::DhcpConfig, hwaddr: &[u8], hw_type: i32) -> bool {
    for conf_addr in &config.hwaddrs {
        if conf_addr.wildcard_mask == 0
            && conf_addr.hwaddr_len as usize == hwaddr.len()
            && (conf_addr.hwaddr_type == hw_type || conf_addr.hwaddr_type == 0)
            && conf_addr.hwaddr[..hwaddr.len()] == *hwaddr
        {
            return true;
        }
    }
    false
}

/// Find a DHCP config entry matching by client-id, hardware address, or hostname.
///
/// Search order: 1) CLID match, 2) exact MAC match, 3) hostname match,
/// 4) wildcard MAC match (fewest wildcards wins).
/// Port of `find_config_match()` from dhcp-common.c:369-436.
pub fn find_config<'a>(
    configs: &'a [crate::types::dhcp::DhcpConfig],
    clid: Option<&[u8]>,
    hwaddr: Option<&[u8]>,
    hw_type: i32,
    hostname: Option<&str>,
) -> Option<&'a crate::types::dhcp::DhcpConfig> {
    use crate::types::dhcp::{CONFIG_CLID, CONFIG_NAME};

    // 1. Match by client-id
    if let Some(clid) = clid {
        for config in configs {
            if config.flags & CONFIG_CLID != 0 {
                if let Some(ref cfg_clid) = config.clid {
                    if cfg_clid == clid {
                        return Some(config);
                    }
                    // dhcpcd workaround: client IDs prefixed with 0x00
                    if clid.first() == Some(&0)
                        && clid.len() > 1
                        && cfg_clid.len() == clid.len() - 1
                        && *cfg_clid == clid[1..]
                    {
                        return Some(config);
                    }
                }
            }
        }
    }

    // 2. Match by exact MAC
    if let Some(hwaddr) = hwaddr {
        for config in configs {
            if config_has_mac(config, hwaddr, hw_type) {
                return Some(config);
            }
        }
    }

    // 3. Match by hostname
    if let Some(hostname) = hostname {
        for config in configs {
            if config.flags & CONFIG_NAME != 0 {
                if let Some(ref cfg_name) = config.hostname {
                    if cfg_name.eq_ignore_ascii_case(hostname) {
                        return Some(config);
                    }
                }
            }
        }
    }

    // 4. Wildcard MAC match (fewest wildcards wins)
    if let Some(hwaddr) = hwaddr {
        let mut best: Option<&crate::types::dhcp::DhcpConfig> = None;
        let mut best_count = 0;
        for config in configs {
            for conf_addr in &config.hwaddrs {
                if conf_addr.wildcard_mask != 0
                    && conf_addr.hwaddr_len as usize == hwaddr.len()
                    && (conf_addr.hwaddr_type == hw_type || conf_addr.hwaddr_type == 0)
                {
                    let count = crate::util::memcmp_masked(&conf_addr.hwaddr[..hwaddr.len()], hwaddr, conf_addr.wildcard_mask);
                    if count > best_count {
                        best_count = count;
                        best = Some(config);
                    }
                }
            }
        }
        if best.is_some() {
            return best;
        }
    }

    None
}

#[cfg(all(test, feature = "dhcp"))]
mod tests {
    use super::*;
    use crate::dhcp_protocol::OPTION_MESSAGE_TYPE;
    use crate::types::dhcp::DhcpOpt;

    fn make_options(code: u8, data: &[u8]) -> Vec<u8> {
        let mut opts = vec![code, data.len() as u8];
        opts.extend_from_slice(data);
        opts.push(OPTION_END);
        opts
    }

    #[test]
    fn find_option_found() {
        let opts = make_options(12, b"myhost");
        assert_eq!(find_option(&opts, 12), Some(b"myhost".as_ref()));
    }

    #[test]
    fn find_option_missing() {
        let opts = make_options(12, b"myhost");
        assert!(find_option(&opts, 15).is_none());
    }

    #[test]
    fn get_message_type_correct() {
        let opts = make_options(OPTION_MESSAGE_TYPE, &[1]);
        assert_eq!(get_message_type(&opts), Some(DhcpMsgType::Discover));
    }

    #[test]
    fn match_netid_identical() {
        let a = vec![DhcpNetid { net: "tag1".into() }];
        let b = vec![DhcpNetid { net: "tag1".into() }];
        assert!(match_netid(&a, &b));
    }

    #[test]
    fn match_netid_different() {
        let a = vec![DhcpNetid { net: "tag1".into() }];
        let b = vec![DhcpNetid { net: "tag2".into() }];
        assert!(!match_netid(&a, &b));
    }

    #[test]
    fn build_and_find_roundtrip() {
        let opt = DhcpOpt {
            opt: 12,
            flags: 0,
            val: Some(b"router".to_vec()),
            netid: None,
            encap: 0,
            vendor_class: None,
        };
        let built = build_options(&[opt]);
        assert_eq!(find_option(&built, 12), Some(b"router".as_ref()));
    }

    // ── opttab ────────────────────────────────────────────────────────────────

    #[test]
    fn opttab_has_expected_entries() {
        // dns-server is option 6
        let entry = OPTTAB.iter().find(|e| e.name == "dns-server").unwrap();
        assert_eq!(entry.val, 6);
        assert!((entry.size & OT_ADDR_LIST) != 0);
    }

    #[test]
    fn opttab_internal_entries_not_in_display() {
        let shown = display_opts();
        // hostname (12) is OT_INTERNAL — should not appear
        assert!(!shown.iter().any(|(v, _)| *v == 12), "hostname should be hidden");
        // dns-server (6) is not internal — should appear
        assert!(shown.iter().any(|(v, _)| *v == 6), "dns-server should be shown");
    }

    // ── lookup_dhcp_opt ───────────────────────────────────────────────────────

    #[test]
    fn lookup_dhcp_opt_found() {
        assert_eq!(lookup_dhcp_opt(false, "router"), Some(3));
        assert_eq!(lookup_dhcp_opt(false, "ROUTER"), Some(3)); // case-insensitive
    }

    #[test]
    fn lookup_dhcp_opt_not_found() {
        assert!(lookup_dhcp_opt(false, "nosuchoption").is_none());
    }

    // ── lookup_dhcp_len ───────────────────────────────────────────────────────

    #[test]
    fn lookup_dhcp_len_known_option() {
        // mtu = 26, size = 2 | OT_DEC; strip OT_DEC bit → should include OT_DEC in mask
        let len = lookup_dhcp_len(false, 26);
        // The result strips OT_DEC (0x0400); 2 | OT_DEC & !OT_DEC = 2
        assert_eq!(len, 2);
    }

    #[test]
    fn lookup_dhcp_len_unknown_returns_zero() {
        assert_eq!(lookup_dhcp_len(false, 200), 0);
    }

    // ── option_string ─────────────────────────────────────────────────────────

    #[test]
    fn option_string_addr_list() {
        // dns-server (6) → OT_ADDR_LIST
        let val = [8, 8, 8, 8, 8, 8, 4, 4];
        let s = option_string(false, 6, &val);
        assert_eq!(s, "8.8.8.8, 8.8.4.4");
    }

    #[test]
    fn option_string_name() {
        // domain-name (15) → OT_NAME
        let s = option_string(false, 15, b"example.com");
        assert_eq!(s, "example.com");
    }

    #[test]
    fn option_string_dec() {
        // mtu (26) → 2 | OT_DEC, value 0x05DC = 1500
        let s = option_string(false, 26, &[0x05, 0xDC]);
        assert_eq!(s, "1500");
    }

    #[test]
    fn option_string_time() {
        // T1 (58) → OT_TIME, 3661 seconds = 1h 1m 1s
        let s = option_string(false, 58, &[0x00, 0x00, 0x0E, 0x4D]); // 3661
        assert_eq!(s, "1h 1m 1s");
    }

    #[test]
    fn option_string_hex_fallback() {
        // Unknown option → hex dump
        let s = option_string(false, 200, &[0xDE, 0xAD]);
        assert_eq!(s, "de:ad");
    }

    // ── format_time ───────────────────────────────────────────────────────────

    #[test]
    fn format_time_zero() {
        assert_eq!(format_time(0), "0s");
    }

    #[test]
    fn format_time_exact_hours() {
        assert_eq!(format_time(7200), "2h");
    }

    #[test]
    fn format_time_mixed() {
        assert_eq!(format_time(3661), "1h 1m 1s");
    }

    // ── dhcp_update_configs ───────────────────────────────────────────────────

    #[test]
    fn dhcp_update_configs_fills_from_hosts() {
        use std::time::Instant;
        use crate::cache::DnsCache;
        use crate::cache::{parse_hosts_line};
        use crate::types::dhcp::{DhcpConfig, CONFIG_NAME, CONFIG_ADDR, CONFIG_ADDR_HOSTS};
        use crate::types::constants::UID_NONE;

        let mut cache = DnsCache::new(100);
        let now = Instant::now();
        parse_hosts_line("10.0.0.42  myserver.local", 60, UID_NONE, now, &mut cache);

        let config = DhcpConfig {
            flags: CONFIG_NAME,
            clid: None,
            hostname: Some("myserver.local".into()),
            domain: None,
            netid: vec![],
            filter: None,
            addr: std::net::Ipv4Addr::UNSPECIFIED,
            decline_time: None,
            lease_time: 3600,
            hwaddrs: vec![],
            #[cfg(feature = "dhcp6")]
            addr6: vec![],
        };
        let mut configs = vec![config];
        dhcp_update_configs(&mut configs, &mut cache, now);

        assert!((configs[0].flags & CONFIG_ADDR) != 0, "CONFIG_ADDR should be set");
        assert!((configs[0].flags & CONFIG_ADDR_HOSTS) != 0);
        assert_eq!(configs[0].addr, "10.0.0.42".parse::<std::net::Ipv4Addr>().unwrap());
    }

    #[test]
    fn dhcp_update_configs_skips_if_already_has_addr() {
        use std::time::Instant;
        use crate::cache::DnsCache;
        use crate::cache::parse_hosts_line;
        use crate::types::dhcp::{DhcpConfig, CONFIG_NAME, CONFIG_ADDR};
        use crate::types::constants::UID_NONE;

        let mut cache = DnsCache::new(100);
        let now = Instant::now();
        parse_hosts_line("10.0.0.1  already.local", 60, UID_NONE, now, &mut cache);

        let explicit_ip: std::net::Ipv4Addr = "192.168.1.50".parse().unwrap();
        let config = DhcpConfig {
            flags: CONFIG_NAME | CONFIG_ADDR,
            clid: None,
            hostname: Some("already.local".into()),
            domain: None,
            netid: vec![],
            filter: None,
            addr: explicit_ip,
            decline_time: None,
            lease_time: 3600,
            hwaddrs: vec![],
            #[cfg(feature = "dhcp6")]
            addr6: vec![],
        };
        let mut configs = vec![config];
        dhcp_update_configs(&mut configs, &mut cache, now);
        // Address should not be overwritten.
        assert_eq!(configs[0].addr, explicit_ip);
    }

    // ── whichdevice ───────────────────────────────────────────────────────────

    #[test]
    fn whichdevice_no_if_names_returns_none() {
        assert!(whichdevice(&[], &["eth0".to_string()]).is_none());
    }

    #[test]
    fn whichdevice_wildcard_in_if_names_returns_none() {
        let names = vec!["eth*".to_string()];
        let ifaces = vec!["eth0".to_string()];
        assert!(whichdevice(&names, &ifaces).is_none());
    }

    #[test]
    fn whichdevice_single_iface_returns_name() {
        let names  = vec!["eth0".to_string()];
        let ifaces = vec!["eth0".to_string()];
        assert_eq!(whichdevice(&names, &ifaces), Some("eth0".to_string()));
    }

    #[test]
    fn whichdevice_duplicate_iface_same_name_ok() {
        let names  = vec!["eth0".to_string()];
        let ifaces = vec!["eth0".to_string(), "eth0".to_string()];
        assert_eq!(whichdevice(&names, &ifaces), Some("eth0".to_string()));
    }

    #[test]
    fn whichdevice_multiple_distinct_ifaces_returns_none() {
        let names  = vec!["eth0".to_string(), "eth1".to_string()];
        let ifaces = vec!["eth0".to_string(), "eth1".to_string()];
        assert!(whichdevice(&names, &ifaces).is_none());
    }

    #[test]
    fn whichdevice_empty_active_ifaces_returns_none() {
        let names = vec!["eth0".to_string()];
        assert!(whichdevice(&names, &[]).is_none());
    }

    // ── bind_dhcp_devices ─────────────────────────────────────────────────────

    #[test]
    fn bind_dhcp_devices_no_device_returns_zero() {
        let ret = bind_dhcp_devices(None, &[(-1, false)]);
        assert_eq!(ret, 0);
    }

    #[test]
    fn bind_dhcp_devices_no_fds_returns_zero() {
        let ret = bind_dhcp_devices(Some("eth0"), &[]);
        assert_eq!(ret, 0);
    }

    // ── bindtodevice ─────────────────────────────────────────────────────────

    #[cfg(all(unix, target_os = "linux"))]
    #[test]
    fn bindtodevice_permission_denied_or_ok() {
        use std::net::UdpSocket;
        use std::os::unix::io::AsRawFd;
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        // May return EPERM in CI without CAP_NET_ADMIN — both outcomes are valid.
        match bindtodevice("lo", sock.as_raw_fd()) {
            Ok(_)  => {}   // success or permission-denied handled gracefully
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    // ── recv_dhcp_packet ─────────────────────────────────────────────────────

    #[cfg(unix)]
    #[test]
    fn recv_dhcp_packet_receives_udp_payload() {
        use std::net::UdpSocket;
        use std::os::unix::io::AsRawFd;

        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server.set_nonblocking(false).unwrap();
        let server_addr = server.local_addr().unwrap();

        let payload = b"DHCP_TEST_PACKET";
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.send_to(payload, server_addr).unwrap();

        let fd = server.as_raw_fd();
        // Enable IP_PKTINFO so cmsg parsing doesn't panic on Linux.
        #[cfg(target_os = "linux")]
        unsafe {
            let one: libc::c_int = 1;
            libc::setsockopt(fd, libc::IPPROTO_IP, libc::IP_PKTINFO,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t);
        }

        let (data, src, _dst) = recv_dhcp_packet(fd).unwrap();
        assert_eq!(&data, payload);
        assert_eq!(src.port(), sender.local_addr().unwrap().port());
    }

    // ── match_netid_wild ──────────────────────────────────────────────────────

    fn nid(s: &str) -> DhcpNetid { DhcpNetid { net: s.to_string() } }
    fn nids(v: &[&str]) -> Vec<DhcpNetid> { v.iter().map(|s| nid(s)).collect() }

    #[test]
    fn match_netid_wild_exact_positive() {
        assert!(match_netid_wild(&nids(&["lan"]), &nids(&["lan", "wifi"])));
    }

    #[test]
    fn match_netid_wild_exact_missing() {
        assert!(!match_netid_wild(&nids(&["vpn"]), &nids(&["lan", "wifi"])));
    }

    #[test]
    fn match_netid_wild_prefix_wildcard() {
        assert!(match_netid_wild(&nids(&["lan*"]), &nids(&["lan0", "wifi"])));
        assert!(!match_netid_wild(&nids(&["lan*"]), &nids(&["wifi"])));
    }

    #[test]
    fn match_netid_wild_negation() {
        // !lan means "lan must NOT be in pool"
        assert!(match_netid_wild(&nids(&["!lan"]), &nids(&["wifi"])));
        assert!(!match_netid_wild(&nids(&["!lan"]), &nids(&["lan", "wifi"])));
    }

    #[test]
    fn match_netid_wild_empty_check_is_true() {
        assert!(match_netid_wild(&[], &nids(&["lan"])));
    }

    // ── run_tag_if ────────────────────────────────────────────────────────────

    #[test]
    fn run_tag_if_injects_tags_when_condition_met() {
        let rules = vec![TagIf {
            tag: nids(&["lan"]),
            set: nids(&["dhcp-extra"]),
        }];
        let result = run_tag_if(nids(&["lan"]), &rules);
        assert!(result.iter().any(|t| t.net == "dhcp-extra"));
    }

    #[test]
    fn run_tag_if_no_injection_when_condition_unmet() {
        let rules = vec![TagIf {
            tag: nids(&["vpn"]),
            set: nids(&["extra"]),
        }];
        let result = run_tag_if(nids(&["lan"]), &rules);
        assert!(!result.iter().any(|t| t.net == "extra"));
    }

    #[test]
    fn run_tag_if_deduplicates() {
        let rules = vec![TagIf {
            tag: nids(&["lan"]),
            set: nids(&["lan"]), // same as already in tags
        }];
        let result = run_tag_if(nids(&["lan"]), &rules);
        assert_eq!(result.iter().filter(|t| t.net == "lan").count(), 1);
    }

    // ── pxe_ok ────────────────────────────────────────────────────────────────

    use crate::types::dhcp::DHOPT_PXE_OPT;

    fn make_opt(flags: u32) -> DhcpOpt {
        DhcpOpt { opt: 1, flags, val: None, netid: None, encap: 0, vendor_class: None }
    }

    #[test]
    fn pxe_ok_non_pxe_opt_mode0() {
        assert!(pxe_ok(&make_opt(0), 0)); // normal opt, mode 0 → include
    }

    #[test]
    fn pxe_ok_non_pxe_opt_mode2() {
        assert!(!pxe_ok(&make_opt(0), 2)); // normal opt, mode 2 (pxe-only) → exclude
    }

    #[test]
    fn pxe_ok_pxe_opt_mode0() {
        assert!(!pxe_ok(&make_opt(DHOPT_PXE_OPT), 0)); // pxe opt, mode 0 → exclude
    }

    #[test]
    fn pxe_ok_pxe_opt_mode1() {
        assert!(pxe_ok(&make_opt(DHOPT_PXE_OPT), 1)); // pxe opt, mode 1 → include
    }

    // ── strip_hostname ────────────────────────────────────────────────────────

    #[test]
    fn strip_hostname_with_domain() {
        let (host, domain) = strip_hostname("myhost.example.com");
        assert_eq!(host, "myhost");
        assert_eq!(domain, Some("example.com"));
    }

    #[test]
    fn strip_hostname_no_dot() {
        let (host, domain) = strip_hostname("myhost");
        assert_eq!(host, "myhost");
        assert!(domain.is_none());
    }

    #[test]
    fn strip_hostname_trailing_dot() {
        let (host, domain) = strip_hostname("myhost.");
        assert_eq!(host, "myhost");
        assert!(domain.is_none());
    }

    // ── log_tags ──────────────────────────────────────────────────────────────

    #[test]
    fn log_tags_basic() {
        let tags = nids(&["lan", "wifi", "lan"]); // duplicate
        let s = log_tags(&tags).unwrap();
        // "lan" should appear once, "wifi" once
        assert!(s.contains("lan"));
        assert!(s.contains("wifi"));
        assert_eq!(s.matches("lan").count(), 1, "no duplicate");
    }

    #[test]
    fn log_tags_empty_returns_none() {
        assert!(log_tags(&[]).is_none());
    }

    // ── match_bytes ───────────────────────────────────────────────────────────

    fn opt_with_val(val: &[u8], flags: u32) -> DhcpOpt {
        DhcpOpt { opt: 43, flags, val: Some(val.to_vec()), netid: None, encap: 0, vendor_class: None }
    }

    #[test]
    fn match_bytes_substring_found() {
        // In non-string mode, scan advances by val.len() (aligned positions).
        // val="test" (len=4): positions checked are 0,4,8...
        // data "testXXXXmore": "test" at position 0 → found.
        let opt = opt_with_val(b"test", 0);
        assert!(match_bytes(&opt, b"testXXXXmore"));
    }

    #[test]
    fn match_bytes_not_found() {
        let opt = opt_with_val(b"nope", 0);
        assert!(!match_bytes(&opt, b"hello test world"));
    }

    #[test]
    fn match_bytes_empty_val_matches_any() {
        let opt = opt_with_val(b"", 0);
        assert!(match_bytes(&opt, b"anything"));
    }

    #[test]
    fn match_bytes_val_longer_than_data_fails() {
        let opt = opt_with_val(b"toolong", 0);
        assert!(!match_bytes(&opt, b"sh"));
    }

    // ── config_has_mac ───────────────────────────────────────────────────────

    fn make_config_with_mac(mac: &[u8], hw_type: i32) -> crate::types::dhcp::DhcpConfig {
        use crate::types::dhcp::{DhcpConfig, HwaddrConfig};
        use crate::dhcp_protocol::DHCP_CHADDR_MAX;
        use std::net::Ipv4Addr;
        let mut hwaddr = [0u8; DHCP_CHADDR_MAX];
        let len = mac.len().min(DHCP_CHADDR_MAX);
        hwaddr[..len].copy_from_slice(&mac[..len]);
        DhcpConfig {
            flags: 0,
            clid: None,
            hostname: None,
            domain: None,
            netid: vec![],
            filter: None,
            addr: Ipv4Addr::UNSPECIFIED,
            decline_time: None,
            lease_time: 0,
            hwaddrs: vec![HwaddrConfig {
                hwaddr,
                hwaddr_len: len as i32,
                hwaddr_type: hw_type,
                wildcard_mask: 0,
            }],
            #[cfg(feature = "dhcp6")]
            addr6: vec![],
        }
    }

    #[test]
    fn config_has_mac_exact_match() {
        let cfg = make_config_with_mac(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], 1);
        assert!(config_has_mac(&cfg, &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], 1));
    }

    #[test]
    fn config_has_mac_wrong_addr() {
        let cfg = make_config_with_mac(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], 1);
        assert!(!config_has_mac(&cfg, &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66], 1));
    }

    #[test]
    fn config_has_mac_wrong_type() {
        let cfg = make_config_with_mac(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], 1);
        assert!(!config_has_mac(&cfg, &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], 6));
    }

    #[test]
    fn config_has_mac_any_type() {
        let cfg = make_config_with_mac(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], 0);
        // type=0 matches any
        assert!(config_has_mac(&cfg, &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], 6));
    }

    #[test]
    fn config_has_mac_wrong_length() {
        let cfg = make_config_with_mac(&[0xAA, 0xBB, 0xCC], 1);
        assert!(!config_has_mac(&cfg, &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], 1));
    }

    // ── find_config ──────────────────────────────────────────────────────────

    #[test]
    fn find_config_by_clid() {
        use crate::types::dhcp::CONFIG_CLID;
        let mut cfg = make_config_with_mac(&[0; 6], 1);
        cfg.flags = CONFIG_CLID;
        cfg.clid = Some(vec![0x01, 0x02, 0x03]);
        let configs = [cfg];
        assert!(find_config(&configs, Some(&[0x01, 0x02, 0x03]), None, 0, None).is_some());
    }

    #[test]
    fn find_config_by_mac() {
        let configs = [make_config_with_mac(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], 1)];
        assert!(find_config(&configs, None, Some(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]), 1, None).is_some());
    }

    #[test]
    fn find_config_by_hostname() {
        use crate::types::dhcp::CONFIG_NAME;
        let mut cfg = make_config_with_mac(&[0; 6], 1);
        cfg.flags = CONFIG_NAME;
        cfg.hostname = Some("myhost".to_string());
        let configs = [cfg];
        assert!(find_config(&configs, None, None, 0, Some("myhost")).is_some());
    }

    #[test]
    fn find_config_hostname_case_insensitive() {
        use crate::types::dhcp::CONFIG_NAME;
        let mut cfg = make_config_with_mac(&[0; 6], 1);
        cfg.flags = CONFIG_NAME;
        cfg.hostname = Some("MyHost".to_string());
        let configs = [cfg];
        assert!(find_config(&configs, None, None, 0, Some("myhost")).is_some());
    }

    #[test]
    fn find_config_no_match() {
        let configs = [make_config_with_mac(&[0xAA; 6], 1)];
        assert!(find_config(&configs, None, Some(&[0xBB; 6]), 1, None).is_none());
    }

    #[test]
    fn find_config_clid_dhcpcd_workaround() {
        use crate::types::dhcp::CONFIG_CLID;
        let mut cfg = make_config_with_mac(&[0; 6], 1);
        cfg.flags = CONFIG_CLID;
        cfg.clid = Some(vec![0x01, 0x02]);
        let configs = [cfg];
        assert!(find_config(&configs, Some(&[0x00, 0x01, 0x02]), None, 0, None).is_some());
    }
}
