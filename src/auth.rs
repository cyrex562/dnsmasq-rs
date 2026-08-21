//! Authoritative DNS server module — Rust port of dnsmasq's `auth.c`.
//!
//! Handles answering DNS queries for zones that dnsmasq is configured to
//! serve authoritatively. `answer_auth` answers directly from the live
//! `Daemon` configuration and the shared `DnsCache` (which also carries
//! DHCP-lease- and hosts-file-sourced records), matching upstream's use of
//! `daemon->auth_zones`, `daemon->int_names`, `daemon->mxnames`, and the
//! global record cache.

#![cfg(feature = "auth")]

use bytes::BytesMut;
use std::net::{Ipv6Addr, SocketAddr};
use std::time::Instant;

use crate::cache::{cache_find_non_terminal, DnsCache};
use crate::dns_protocol::{DnsHeader, RrType, HB3_AA, HB3_QR, HB3_TC, HB4_AD, HB4_RA, PACKETSZ};
use crate::rfc1035::{hostname_issubdomain, in_arpa_name_2_addr, write_name, DnsPacket, DnsQuestion, DnsRr};
use crate::types::addr::AllAddr;
use crate::types::constants::{F_DHCP, F_FORWARD, F_HOSTS, F_IPV4, F_IPV6, F_NEG, F_NXDOMAIN};
use crate::types::dns_records::{
    Addrlist, AuthZone, Cname, InterfaceName, MxSrvRecord, Naptr, TxtRecord, ADDRLIST_IPV6,
    ADDRLIST_REVONLY,
};
use crate::types::network::Iname;

// ──────────────────────────────────────────────────────────────────────────────
// Public types
// ──────────────────────────────────────────────────────────────────────────────

/// Borrowed view of the daemon state `answer_auth` needs, mirroring
/// `rfc1035::LocalConfig`'s convention of borrowing slices out of the live
/// config rather than taking the whole `Daemon`.
///
/// `mxnames` is `&mut` because upstream rotates the first matching SRV
/// record to the end of `daemon->mxnames` on every query that touches it
/// (`auth.c:312-345`) — a real, observable side effect (SRV answer sets
/// round-robin across queries), not an implementation detail to drop.
pub struct AuthConfig<'a> {
    pub auth_zones: &'a [AuthZone],
    pub mxnames: &'a mut Vec<MxSrvRecord>,
    pub naptr: &'a [Naptr],
    /// `daemon->rr` — arbitrary cached-RR types; `TxtRecord::class` holds the
    /// wire RR type, not a DNS class.
    pub rr: &'a [TxtRecord],
    pub txt: &'a [TxtRecord],
    pub int_names: &'a [InterfaceName],
    pub cnames: &'a [Cname],
    pub auth_peers: &'a [Iname],
    /// Whether the machine running dnsmasq should include itself in NS
    /// answers (`daemon->authinterface` truthy — approximated by the caller
    /// as "any `--auth-server` interface is configured").
    pub auth_interface: bool,
    pub authserver: &'a str,
    pub hostmaster: &'a str,
    pub secondary_forward_servers: &'a [String],
    pub soa_sn: u32,
    pub soa_refresh: u32,
    pub soa_retry: u32,
    pub soa_expiry: u32,
    pub auth_ttl: u32,
    /// `OPT_DHCP_FQDN`: DHCP-sourced cache entries are stored under their
    /// bare hostname when this is unset, and under the FQDN when set.
    pub dhcp_fqdn: bool,
    /// Advertised EDNS0 UDP payload size, used only to size the truncation
    /// budget when the query carries an OPT record.
    pub edns_pktsz: u16,
}

// ──────────────────────────────────────────────────────────────────────────────
// in_zone
// ──────────────────────────────────────────────────────────────────────────────

/// Test whether `name` is in `zone_name`.
///
/// Returns `None` if `name` is not equal to, or a subdomain of, `zone_name`.
/// Otherwise returns `Some(cut)`: `None` if `name` is exactly `zone_name`
/// (the zone apex), or `Some(byte_index)` of the `.` separating the local
/// part of `name` from the zone suffix.
///
/// Port of `in_zone()` (`auth.c:72-96`), which additionally returns that cut
/// point via an output parameter — dropped in the previous Rust port, which
/// only returned a `bool`.
pub fn in_zone(name: &str, zone_name: &str) -> Option<Option<usize>> {
    let name = name.trim_end_matches('.');
    let zone = zone_name.trim_end_matches('.');
    let namelen = name.len();
    let zonelen = zone.len();

    if namelen < zonelen || !name[namelen - zonelen..].eq_ignore_ascii_case(zone) {
        return None;
    }
    if namelen == zonelen {
        return Some(None);
    }
    let cut = namelen - zonelen - 1;
    if name.as_bytes()[cut] == b'.' {
        Some(Some(cut))
    } else {
        None
    }
}

/// `hostname_issubdomain`'s upstream three-way return: `0` = unrelated, `1` =
/// a strict subdomain, `2` = an exact (case-insensitive) match. Distinct
/// callers use `rc == 2` to mean "answer this" and `rc != 0` to mean "the
/// name exists somewhere below here, so don't NXDOMAIN" (`auth.c:298-388`).
fn issubdomain_rc(name: &str, domain: &str) -> u8 {
    if name.eq_ignore_ascii_case(domain) {
        2
    } else if hostname_issubdomain(name, domain) {
        1
    } else {
        0
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Zone subnet/exclude filtering (ported from auth.c:21-70)
// ──────────────────────────────────────────────────────────────────────────────

/// Inline IPv6 same-prefix check (avoids dependency on feature-gated dhcp6 module).
fn is_same_net6_inline(a: &Ipv6Addr, b: &Ipv6Addr, prefix_len: i32) -> bool {
    let a_oct = a.octets();
    let b_oct = b.octets();
    let mut remaining = prefix_len as usize;
    for i in 0..16 {
        if remaining == 0 { break; }
        if remaining >= 8 {
            if a_oct[i] != b_oct[i] { return false; }
            remaining -= 8;
        } else {
            let mask = 0xFF << (8 - remaining);
            if (a_oct[i] & mask) != (b_oct[i] & mask) { return false; }
            remaining = 0;
        }
    }
    true
}

/// Check if `addr` matches any entry in the address list (subnet or exclude).
///
/// For IPv4: compares using a netmask derived from the prefix length.
/// For IPv6: compares using `is_same_net6`.
/// Port of `find_addrlist()` from auth.c:21-42.
pub fn find_addrlist(list: &[Addrlist], addr: &AllAddr) -> Option<usize> {
    for (i, entry) in list.iter().enumerate() {
        match (&entry.addr, addr) {
            (AllAddr::Addr4(net), AllAddr::Addr4(a)) if entry.flags & ADDRLIST_IPV6 == 0 => {
                let prefix = entry.prefixlen.clamp(0, 32) as u32;
                let mask = if prefix == 0 { 0u32 } else { !0u32 << (32 - prefix) };
                if (u32::from(*a) & mask) == (u32::from(*net) & mask) {
                    return Some(i);
                }
            }
            (AllAddr::Addr6(net), AllAddr::Addr6(a)) if entry.flags & ADDRLIST_IPV6 != 0 => {
                if is_same_net6_inline(a, net, entry.prefixlen) {
                    return Some(i);
                }
            }
            _ => continue,
        }
    }
    None
}

/// Check if `addr` matches a subnet entry in the zone.
///
/// Port of `find_subnet()` from auth.c:44-50.
pub fn find_subnet(zone: &AuthZone, addr: &AllAddr) -> bool {
    if zone.subnet.is_empty() {
        return false;
    }
    find_addrlist(&zone.subnet, addr).is_some()
}

/// Check if `addr` matches an exclude entry in the zone.
///
/// Port of `find_exclude()` from auth.c:52-58.
pub fn find_exclude(zone: &AuthZone, addr: &AllAddr) -> bool {
    if zone.exclude.is_empty() {
        return false;
    }
    find_addrlist(&zone.exclude, addr).is_some()
}

/// Filter an address against a zone's subnet/exclude lists.
///
/// Returns `true` if the address should be included (not excluded, and either
/// no subnet filter or matches a subnet).
/// Port of `filter_zone()` from auth.c:60-70.
pub fn filter_zone(zone: &AuthZone, addr: &AllAddr) -> bool {
    if find_exclude(zone, addr) {
        return false;
    }
    // No subnets specified means no filter — allow everything.
    if zone.subnet.is_empty() {
        return true;
    }
    find_subnet(zone, addr)
}

fn addr_flag(addr: &AllAddr) -> u32 {
    match addr {
        AllAddr::Addr4(_) => F_IPV4,
        AllAddr::Addr6(_) => F_IPV6,
        _ => 0,
    }
}

fn addrlist_matches_addr(al: &Addrlist, addr: &AllAddr) -> bool {
    match (&al.addr, addr) {
        (AllAddr::Addr4(a), AllAddr::Addr4(b)) if al.flags & ADDRLIST_IPV6 == 0 => a == b,
        (AllAddr::Addr6(a), AllAddr::Addr6(b)) if al.flags & ADDRLIST_IPV6 != 0 => a == b,
        _ => false,
    }
}

/// Compute the reverse-zone apex name (`X.X.X.in-addr.arpa` / `...ip6.arpa`)
/// implied by a matched subnet entry. Port of the `authname` computation in
/// the "Add auth section" block (`auth.c:596-631`).
fn reverse_zone_name(subnet: &Addrlist) -> String {
    match &subnet.addr {
        AllAddr::Addr4(ip) => {
            let o = ip.octets();
            let mut a: u32 = ((o[0] as u32) << 16) | ((o[1] as u32) << 8) | (o[2] as u32);
            let mut s = String::new();
            if subnet.prefixlen >= 24 {
                s.push_str(&format!("{}.", a & 0xff));
            }
            a >>= 8;
            if subnet.prefixlen >= 16 {
                s.push_str(&format!("{}.", a & 0xff));
            }
            a >>= 8;
            s.push_str(&format!("{}.in-addr.arpa", a & 0xff));
            s
        }
        AllAddr::Addr6(ip) => {
            let bytes = ip.octets();
            let mut s = String::new();
            let mut i: i32 = subnet.prefixlen - 1;
            while i >= 0 {
                let byte_idx = (i >> 3) as usize;
                let dig = bytes[byte_idx];
                let nib = if (i >> 2) & 1 == 1 { dig & 0x0f } else { dig >> 4 };
                s.push_str(&format!("{:x}.", nib));
                i -= 4;
            }
            s.push_str("ip6.arpa");
            s
        }
        _ => String::new(),
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// RR builders
// ──────────────────────────────────────────────────────────────────────────────

fn char_string(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    let len = bytes.len().min(255);
    buf.push(len as u8);
    buf.extend_from_slice(&bytes[..len]);
}

fn make_soa_rr(authname: &str, config: &AuthConfig, ttl: u32) -> DnsRr {
    let mut rdata = BytesMut::new();
    write_name(&mut rdata, config.authserver);
    write_name(&mut rdata, config.hostmaster);
    for &v in &[config.soa_sn, config.soa_refresh, config.soa_retry, config.soa_expiry, config.auth_ttl] {
        rdata.extend_from_slice(&v.to_be_bytes());
    }
    DnsRr {
        name: authname.to_string(),
        rtype: RrType::SOA as u16,
        class: 1,
        ttl,
        rdata: rdata.to_vec(),
    }
}

fn make_ns_rr(owner: &str, target: &str, ttl: u32) -> DnsRr {
    let mut rdata = BytesMut::new();
    write_name(&mut rdata, target);
    DnsRr { name: owner.to_string(), rtype: RrType::NS as u16, class: 1, ttl, rdata: rdata.to_vec() }
}

fn make_ptr_rr(owner: &str, target: &str, ttl: u32) -> DnsRr {
    let mut rdata = BytesMut::new();
    write_name(&mut rdata, target);
    DnsRr { name: owner.to_string(), rtype: RrType::PTR as u16, class: 1, ttl, rdata: rdata.to_vec() }
}

fn make_cname_rr(owner: &str, target: &str, ttl: u32) -> DnsRr {
    let mut rdata = BytesMut::new();
    write_name(&mut rdata, target);
    DnsRr { name: owner.to_string(), rtype: RrType::CNAME as u16, class: 1, ttl, rdata: rdata.to_vec() }
}

fn make_mx_rr(owner: &str, rec: &MxSrvRecord, ttl: u32) -> DnsRr {
    let mut rdata = BytesMut::new();
    rdata.extend_from_slice(&(rec.priority as u16).to_be_bytes());
    write_name(&mut rdata, &rec.target);
    DnsRr { name: owner.to_string(), rtype: RrType::MX as u16, class: 1, ttl, rdata: rdata.to_vec() }
}

fn make_srv_rr(owner: &str, rec: &MxSrvRecord, ttl: u32) -> DnsRr {
    let mut rdata = BytesMut::new();
    rdata.extend_from_slice(&(rec.priority as u16).to_be_bytes());
    rdata.extend_from_slice(&(rec.weight as u16).to_be_bytes());
    rdata.extend_from_slice(&rec.srv_port.to_be_bytes());
    write_name(&mut rdata, &rec.target);
    DnsRr { name: owner.to_string(), rtype: RrType::SRV as u16, class: 1, ttl, rdata: rdata.to_vec() }
}

fn make_naptr_rr(owner: &str, na: &Naptr, ttl: u32) -> DnsRr {
    let mut rdata = Vec::new();
    rdata.extend_from_slice(&(na.order as u16).to_be_bytes());
    rdata.extend_from_slice(&(na.pref as u16).to_be_bytes());
    char_string(&mut rdata, &na.flags);
    char_string(&mut rdata, &na.services);
    char_string(&mut rdata, &na.regexp);
    let mut namebuf = BytesMut::new();
    write_name(&mut namebuf, &na.replace);
    rdata.extend_from_slice(&namebuf);
    DnsRr { name: owner.to_string(), rtype: RrType::NAPTR as u16, class: 1, ttl, rdata }
}

fn make_txt_like_rr(owner: &str, rtype: u16, data: &[u8], ttl: u32) -> DnsRr {
    let mut rdata = Vec::new();
    if data.is_empty() {
        rdata.push(0);
    } else {
        for chunk in data.chunks(255) {
            rdata.push(chunk.len() as u8);
            rdata.extend_from_slice(chunk);
        }
    }
    DnsRr { name: owner.to_string(), rtype, class: 1, ttl, rdata }
}

fn make_addr_rr(owner: &str, rtype: u16, addr: &AllAddr, ttl: u32) -> Option<DnsRr> {
    let rdata = match addr {
        AllAddr::Addr4(ip) => ip.octets().to_vec(),
        AllAddr::Addr6(ip) => ip.octets().to_vec(),
        _ => return None,
    };
    Some(DnsRr { name: owner.to_string(), rtype, class: 1, ttl, rdata })
}

fn append_domain_if_bare(mut n: String, domain: &str) -> String {
    if !n.contains('.') {
        n.push('.');
        n.push_str(domain);
    }
    n
}

// ──────────────────────────────────────────────────────────────────────────────
// answer_auth
// ──────────────────────────────────────────────────────────────────────────────

/// Build an authoritative DNS reply for `query`.
///
/// Returns `None` when nothing should be sent at all: a malformed question
/// section, or an AXFR request from a peer not authorized by `--auth-peer` /
/// `--auth-sec-servers` (both cases mirror upstream `answer_auth` returning
/// `0`, `auth.c:122,465`). Otherwise returns `Some(reply)` — including for
/// REFUSED/NOTIMP/NXDOMAIN outcomes, which are real wire replies.
///
/// Port of `answer_auth()` (`auth.c:99-913`).
pub fn answer_auth(
    query: &DnsPacket,
    config: &mut AuthConfig,
    cache: &mut DnsCache,
    peer_addr: SocketAddr,
    local_query: bool,
    now: Instant,
) -> Option<DnsPacket> {
    if query.questions.len() != 1 {
        return None;
    }
    let question: DnsQuestion = query.questions[0].clone();
    let qtype_num = question.qtype;
    let qtype = RrType::from_u16(qtype_num);

    let mut name = question.name.to_lowercase();
    if name.ends_with('.') {
        name.pop();
    }

    let mut found = false;
    let mut nxdomain = true;
    let mut auth = !local_query;
    let mut soa = false;
    let mut ns = false;
    let mut axfr = false;
    let mut out_of_zone = false;
    let mut notimp = false;
    let mut zone: Option<AuthZone> = None;
    let mut subnet: Option<Addrlist> = None;
    let mut answers: Vec<DnsRr> = Vec::new();
    let mut authority: Vec<DnsRr> = Vec::new();

    if query.header.opcode() != 0 {
        notimp = true;
    } else if question.qclass != 1 {
        // auth.c:148-153
        auth = false;
        out_of_zone = true;
    } else {
        let mut aborted = false;
        let mut flag: u32 = 0;

        // ── PTR / SOA / NS on a reverse (.arpa) name (auth.c:155-277) ──────
        if matches!(qtype, Some(RrType::PTR) | Some(RrType::SOA) | Some(RrType::NS)) {
            if let Some(addr) = in_arpa_name_2_addr(&name) {
                flag = addr_flag(&addr);

                if !local_query {
                    for z in config.auth_zones {
                        if let Some(idx) = find_addrlist(&z.subnet, &addr) {
                            subnet = Some(z.subnet[idx].clone());
                            zone = Some(z.clone());
                            break;
                        }
                    }
                    if zone.is_none() {
                        out_of_zone = true;
                        auth = false;
                        aborted = true;
                    } else if qtype == Some(RrType::SOA) {
                        soa = true;
                        found = true;
                    } else if qtype == Some(RrType::NS) {
                        ns = true;
                        found = true;
                    }
                }

                if !aborted && qtype == Some(RrType::PTR) {
                    if let Some(intr) = config.int_names.iter().find(|intr| {
                        intr.addrs.iter().any(|al| addrlist_matches_addr(al, &addr))
                    }) {
                        if local_query || zone.as_ref().is_some_and(|z| in_zone(&intr.name, &z.domain).is_some()) {
                            found = true;
                            answers.push(make_ptr_rr(&question.name, &intr.name, config.auth_ttl));
                        }
                    }

                    for cr in cache.lookup_all_by_addr(&addr, flag, now) {
                        if cr.flags & F_DHCP != 0 && !config.dhcp_fqdn {
                            let bare = cr.name.split('.').next().unwrap_or(&cr.name).to_string();
                            let full = if let Some(z) = &zone {
                                append_domain_if_bare(bare, &z.domain)
                            } else {
                                bare
                            };
                            found = true;
                            answers.push(make_ptr_rr(&question.name, &full, config.auth_ttl));
                        } else if cr.flags & (F_DHCP | F_HOSTS) != 0
                            && (local_query || zone.as_ref().is_some_and(|z| in_zone(&cr.name, &z.domain).is_some()))
                        {
                            found = true;
                            answers.push(make_ptr_rr(&question.name, &cr.name, config.auth_ttl));
                        }
                    }

                    // `is_rev_synth` (`--synth-domain` reverse synthesis) is
                    // not wired here — `daemon->cond_domain` (the plain
                    // `--domain` subnet form) is not yet populated anywhere
                    // in this port; see tasks.md.

                    if found {
                        nxdomain = false;
                    }
                    aborted = true;
                }
            }
        }

        // ── Forward-zone answering, with CNAME-restart (auth.c:279-586) ────
        if !aborted {
            'restart: loop {
                let cut: Option<usize> = if found {
                    None
                } else {
                    let mut sel = None;
                    for z in config.auth_zones {
                        if let Some(c) = in_zone(&name, &z.domain) {
                            sel = Some((z.clone(), c));
                            break;
                        }
                    }
                    match sel {
                        Some((z, c)) => {
                            zone = Some(z);
                            c
                        }
                        None => {
                            out_of_zone = true;
                            auth = false;
                            break 'restart;
                        }
                    }
                };
                // `zone` is always populated by this point: either from the
                // reverse-lookup branch above (when `found` was already
                // true), or from the zone-selection loop just above.
                let zone_domain = zone.as_ref().unwrap().domain.clone();

                // MX
                for rec in config.mxnames.iter() {
                    if rec.is_srv { continue; }
                    let rc = issubdomain_rc(&name, &rec.name);
                    if rc == 0 { continue; }
                    nxdomain = false;
                    if rc == 2 && qtype == Some(RrType::MX) {
                        found = true;
                        answers.push(make_mx_rr(&name, rec, config.auth_ttl));
                    }
                }

                // SRV, with first-match rotation to the end of the list
                // (auth.c:312-345).
                let mut first_srv_idx: Option<usize> = None;
                for (i, rec) in config.mxnames.iter().enumerate() {
                    if !rec.is_srv { continue; }
                    let rc = issubdomain_rc(&name, &rec.name);
                    if rc == 0 { continue; }
                    nxdomain = false;
                    if rc == 2 && qtype == Some(RrType::SRV) {
                        found = true;
                        answers.push(make_srv_rr(&name, rec, config.auth_ttl));
                    }
                    if first_srv_idx.is_none() {
                        first_srv_idx = Some(i);
                    }
                }
                if let Some(idx) = first_srv_idx {
                    let rec = config.mxnames.remove(idx);
                    config.mxnames.push(rec);
                }

                // Arbitrary cached RR types (`daemon->rr`).
                for txt in config.rr {
                    let rc = issubdomain_rc(&name, &txt.name);
                    if rc == 0 { continue; }
                    nxdomain = false;
                    if rc == 2 && txt.class == qtype_num {
                        found = true;
                        answers.push(make_txt_like_rr(&name, txt.class, &txt.txt, config.auth_ttl));
                    }
                }

                // TXT
                for txt in config.txt {
                    if txt.class != 1 { continue; }
                    let rc = issubdomain_rc(&name, &txt.name);
                    if rc == 0 { continue; }
                    nxdomain = false;
                    if rc == 2 && qtype == Some(RrType::TXT) {
                        found = true;
                        answers.push(make_txt_like_rr(&name, RrType::TXT as u16, &txt.txt, config.auth_ttl));
                    }
                }

                // NAPTR
                for na in config.naptr {
                    let rc = issubdomain_rc(&name, &na.name);
                    if rc == 0 { continue; }
                    nxdomain = false;
                    if rc == 2 && qtype == Some(RrType::NAPTR) {
                        found = true;
                        answers.push(make_naptr_rr(&name, na, config.auth_ttl));
                    }
                }

                // A / AAAA via `--interface-name` (auth.c:390-418).
                if qtype == Some(RrType::A) { flag = F_IPV4; }
                if qtype == Some(RrType::AAAA) { flag = F_IPV6; }
                for intr in config.int_names {
                    let rc = issubdomain_rc(&name, &intr.name);
                    if rc == 0 { continue; }
                    nxdomain = false;
                    if rc == 2 && flag != 0 {
                        for al in &intr.addrs {
                            let is6 = al.flags & ADDRLIST_IPV6 != 0;
                            let want = if is6 { RrType::AAAA } else { RrType::A };
                            if want as u16 != qtype_num { continue; }
                            if al.flags & ADDRLIST_REVONLY != 0 { continue; }
                            if !(local_query || filter_zone(zone.as_ref().unwrap(), &al.addr)) { continue; }
                            found = true;
                            if let Some(rr) = make_addr_rr(&name, qtype_num, &al.addr, config.auth_ttl) {
                                answers.push(rr);
                            }
                        }
                    }
                }
                // `is_name_synthetic` (`--synth-domain` forward synthesis)
                // is not wired here for the same reason noted above.

                if cut.is_none() {
                    nxdomain = false;
                    if qtype == Some(RrType::SOA) {
                        auth = true;
                        soa = true;
                    } else if qtype == Some(RrType::AXFR) {
                        let peer_ip = peer_addr.ip();
                        let peer_listed = config
                            .auth_peers
                            .iter()
                            .any(|p| p.addr.as_ref().map(|a| a.ip()) == Some(peer_ip));
                        let authorized = if config.auth_peers.is_empty() {
                            !config.secondary_forward_servers.is_empty()
                        } else {
                            peer_listed
                        };
                        if !authorized {
                            // auth.c:456-466 — silently drop.
                            return None;
                        }
                        auth = true;
                        soa = true;
                        ns = true;
                        axfr = true;
                    } else if qtype == Some(RrType::NS) {
                        auth = true;
                        ns = true;
                    }
                }

                // DHCP-sourced, bare-name cache lookup when the name is cut
                // to its local part and DHCP entries aren't stored as FQDNs
                // (auth.c:483-508).
                if let Some(c) = cut {
                    if !config.dhcp_fqdn {
                        let stripped = name[..c].to_string();
                        if !stripped.contains('.') {
                            for cr in cache.lookup_all_by_name(&stripped, F_IPV4 | F_IPV6, now) {
                                if cr.flags & F_DHCP == 0 { continue; }
                                nxdomain = false;
                                if cr.flags & flag != 0 {
                                    let Some(addr) = &cr.addr else { continue };
                                    if local_query || filter_zone(zone.as_ref().unwrap(), addr) {
                                        found = true;
                                        if let Some(rr) = make_addr_rr(&stripped, qtype_num, addr, config.auth_ttl) {
                                            answers.push(rr);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // HOSTS records, or DHCP-sourced FQDNs (auth.c:510-525).
                for cr in cache.lookup_all_by_name(&name, F_IPV4 | F_IPV6, now) {
                    if !(cr.flags & F_HOSTS != 0 || (cr.flags & F_DHCP != 0 && config.dhcp_fqdn)) {
                        continue;
                    }
                    nxdomain = false;
                    if cr.flags & flag != 0 {
                        let Some(addr) = &cr.addr else { continue };
                        if local_query || filter_zone(zone.as_ref().unwrap(), addr) {
                            found = true;
                            if let Some(rr) = make_addr_rr(&name, qtype_num, addr, config.auth_ttl) {
                                answers.push(rr);
                            }
                        }
                    }
                }

                // Only look for a CNAME if nothing of any type was found
                // (auth.c:527-584).
                if nxdomain {
                    let mut wclen = 0usize;
                    let mut cname_wildcard = false;
                    let mut candidate: Option<&Cname> = None;
                    for c in config.cnames.iter() {
                        if let Some(suffix) = c.alias.strip_prefix('*') {
                            // Find the longest dot-anchored suffix of `name`
                            // matching `suffix` (`*.foo` matches `b.foo` via
                            // suffix `.foo`, tried at every dot position).
                            let bytes = name.as_bytes();
                            for (i, b) in bytes.iter().enumerate() {
                                if *b != b'.' { continue; }
                                let test = &name[i..];
                                if test.eq_ignore_ascii_case(suffix) {
                                    if test.len() > wclen && !cname_wildcard {
                                        wclen = test.len();
                                        candidate = Some(c);
                                        cname_wildcard = true;
                                    }
                                    break;
                                }
                            }
                        } else if c.alias.eq_ignore_ascii_case(&name) && c.alias.len() > wclen {
                            wclen = c.alias.len();
                            candidate = Some(c);
                        }
                    }

                    if let Some(c) = candidate {
                        let target = append_domain_if_bare(c.target.clone(), &zone_domain);
                        found = true;
                        answers.push(make_cname_rr(&name, &target, config.auth_ttl));
                        name = target;
                        continue 'restart;
                    } else if cache_find_non_terminal(&name, now, cache) {
                        nxdomain = false;
                    }
                }

                break;
            }
        }
    }

    // ── done: build the auth (NS/SOA) section (auth.c:590-849) ─────────────
    if auth {
        if let Some(zref) = &zone {
            build_auth_section(
                zref, subnet.as_ref(), config, cache, now, local_query, axfr, soa, ns,
                &mut answers, &mut authority,
            );
        }
    }

    // ── Header / flags / rcode (auth.c:851-912) ─────────────────────────────
    let mut hdr = DnsHeader::default();
    hdr.id = query.header.id;
    hdr.hb3 = (query.header.hb3 & !(HB3_AA | HB3_TC)) | HB3_QR;
    hdr.hb4 = if local_query { query.header.hb4 | HB4_RA } else { query.header.hb4 & !HB4_RA };
    hdr.hb4 &= !HB4_AD;
    if auth {
        hdr.hb3 |= HB3_AA;
    }
    hdr.qdcount = 1;

    // Coarse (all-or-nothing) UDP truncation: build the candidate reply and
    // check its wire size against the packet-size budget. Multi-message TCP
    // AXFR framing is not implemented — see tasks.md.
    let limit = if query.additional.iter().any(|rr| rr.rtype == 41) {
        config.edns_pktsz as usize
    } else {
        PACKETSZ
    };
    let mut candidate = DnsPacket {
        header: hdr,
        questions: vec![question.clone()],
        answers: answers.clone(),
        authority: authority.clone(),
        additional: vec![],
    };
    if candidate.write().len() > limit {
        candidate.header.hb3 |= HB3_TC;
        candidate.answers.clear();
        candidate.authority.clear();
        answers.clear();
        authority.clear();
    }
    hdr = candidate.header;

    let rcode: u8 = if (auth || local_query) && nxdomain { 3 } else { 0 };
    hdr.set_rcode(rcode);
    hdr.ancount = answers.len() as u16;
    hdr.nscount = authority.len() as u16;
    hdr.arcount = 0;

    if (!local_query && out_of_zone) || notimp {
        let final_rcode: u8 = if out_of_zone { 5 } else { 4 }; // REFUSED : NOTIMP
        hdr.set_rcode(final_rcode);
        hdr.ancount = 0;
        hdr.nscount = 0;
        return Some(DnsPacket {
            header: hdr,
            questions: vec![question],
            answers: vec![],
            authority: vec![],
            additional: vec![],
        });
    }

    Some(DnsPacket {
        header: hdr,
        questions: vec![question],
        answers,
        authority,
        additional: vec![],
    })
}

/// Build the NS/SOA authority section, and for AXFR the full zone dump.
///
/// Port of the "Add auth section" block (`auth.c:590-849`).
#[allow(clippy::too_many_arguments)]
fn build_auth_section(
    zone: &AuthZone,
    subnet: Option<&Addrlist>,
    config: &AuthConfig,
    cache: &DnsCache,
    now: Instant,
    local_query: bool,
    axfr: bool,
    soa: bool,
    ns: bool,
    answers: &mut Vec<DnsRr>,
    authority: &mut Vec<DnsRr>,
) {
    let authname = match subnet {
        Some(s) => reverse_zone_name(s),
        None => zone.domain.clone(),
    };

    if (answers.is_empty() && !ns) || soa {
        let rr = make_soa_rr(&authname, config, config.auth_ttl);
        if soa { answers.push(rr); } else { authority.push(rr); }
    }

    if !answers.is_empty() || ns {
        if config.auth_interface {
            let rr = make_ns_rr(&authname, config.authserver, config.auth_ttl);
            if ns { answers.push(rr); } else { authority.push(rr); }
        }
        if subnet.is_none() {
            for secondary in config.secondary_forward_servers {
                let rr = make_ns_rr(&authname, secondary, config.auth_ttl);
                if ns { answers.push(rr); } else { authority.push(rr); }
            }
        }
    }

    if axfr {
        for rec in config.mxnames.iter() {
            if in_zone(&rec.name, &zone.domain).is_none() { continue; }
            let rr = if rec.is_srv { make_srv_rr(&rec.name, rec, config.auth_ttl) } else { make_mx_rr(&rec.name, rec, config.auth_ttl) };
            answers.push(rr);
        }
        for txt in config.rr {
            if in_zone(&txt.name, &zone.domain).is_none() { continue; }
            answers.push(make_txt_like_rr(&txt.name, txt.class, &txt.txt, config.auth_ttl));
        }
        for txt in config.txt {
            if txt.class != 1 { continue; }
            if in_zone(&txt.name, &zone.domain).is_none() { continue; }
            answers.push(make_txt_like_rr(&txt.name, RrType::TXT as u16, &txt.txt, config.auth_ttl));
        }
        for na in config.naptr {
            if in_zone(&na.name, &zone.domain).is_none() { continue; }
            answers.push(make_naptr_rr(&na.name, na, config.auth_ttl));
        }
        for intr in config.int_names {
            if in_zone(&intr.name, &zone.domain).is_none() { continue; }
            for al in &intr.addrs {
                let is6 = al.flags & ADDRLIST_IPV6 != 0;
                if !is6 && (local_query || filter_zone(zone, &al.addr)) {
                    if let Some(rr) = make_addr_rr(&intr.name, RrType::A as u16, &al.addr, config.auth_ttl) {
                        answers.push(rr);
                    }
                }
            }
            for al in &intr.addrs {
                let is6 = al.flags & ADDRLIST_IPV6 != 0;
                if is6 && (local_query || filter_zone(zone, &al.addr)) {
                    if let Some(rr) = make_addr_rr(&intr.name, RrType::AAAA as u16, &al.addr, config.auth_ttl) {
                        answers.push(rr);
                    }
                }
            }
        }
        for c in config.cnames {
            if in_zone(&c.alias, &zone.domain).is_none() { continue; }
            let target = append_domain_if_bare(c.target.clone(), &zone.domain);
            answers.push(make_cname_rr(&c.alias, &target, config.auth_ttl));
        }

        for cr in cache.iter_live(now) {
            if cr.flags & (F_IPV4 | F_IPV6) == 0 { continue; }
            if cr.flags & (F_NEG | F_NXDOMAIN) != 0 { continue; }
            if cr.flags & F_FORWARD == 0 { continue; }
            let Some(addr) = &cr.addr else { continue };
            let rtype = if cr.flags & F_IPV6 != 0 { RrType::AAAA as u16 } else { RrType::A as u16 };

            if cr.flags & F_DHCP != 0 && !config.dhcp_fqdn {
                if !cr.name.contains('.') && (local_query || filter_zone(zone, addr)) {
                    let owner = append_domain_if_bare(cr.name.clone(), &zone.domain);
                    if let Some(rr) = make_addr_rr(&owner, rtype, addr, config.auth_ttl) {
                        answers.push(rr);
                    }
                }
            }

            if cr.flags & F_HOSTS != 0 || (cr.flags & F_DHCP != 0 && config.dhcp_fqdn) {
                if in_zone(&cr.name, &zone.domain).is_some() && (local_query || filter_zone(zone, addr)) {
                    if let Some(rr) = make_addr_rr(&cr.name, rtype, addr, config.auth_ttl) {
                        answers.push(rr);
                    }
                }
            }
        }

        // Repeat the SOA as the closing record of the zone transfer.
        answers.push(make_soa_rr(&authname, config, config.auth_ttl));
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::{new_shared_cache, CacheRecord};
    use crate::dns_protocol::RrType;
    use crate::types::addr::MySockAddr;
    use crate::types::constants::UID_NONE;
    use std::net::{Ipv4Addr, SocketAddrV4, SocketAddrV6};

    fn test_zone() -> AuthZone {
        AuthZone {
            domain: "example.com".into(),
            interface_names: vec![],
            subnet: vec![],
            exclude: vec![],
        }
    }

    struct Fixture {
        auth_zones: Vec<AuthZone>,
        mxnames: Vec<MxSrvRecord>,
        naptr: Vec<Naptr>,
        rr: Vec<TxtRecord>,
        txt: Vec<TxtRecord>,
        int_names: Vec<InterfaceName>,
        cnames: Vec<Cname>,
        auth_peers: Vec<Iname>,
        secondary_forward_servers: Vec<String>,
    }

    impl Fixture {
        fn new() -> Self {
            Fixture {
                auth_zones: vec![test_zone()],
                mxnames: vec![],
                naptr: vec![],
                rr: vec![],
                txt: vec![],
                int_names: vec![],
                cnames: vec![],
                auth_peers: vec![],
                secondary_forward_servers: vec![],
            }
        }

        fn config(&mut self) -> AuthConfig<'_> {
            AuthConfig {
                auth_zones: &self.auth_zones,
                mxnames: &mut self.mxnames,
                naptr: &self.naptr,
                rr: &self.rr,
                txt: &self.txt,
                int_names: &self.int_names,
                cnames: &self.cnames,
                auth_peers: &self.auth_peers,
                auth_interface: false,
                authserver: "ns1.example.com",
                hostmaster: "hostmaster.example.com",
                secondary_forward_servers: &self.secondary_forward_servers,
                soa_sn: 2024010101,
                soa_refresh: 3600,
                soa_retry: 900,
                soa_expiry: 604800,
                auth_ttl: 300,
                dhcp_fqdn: false,
                edns_pktsz: 4096,
            }
        }
    }

    fn make_query(name: &str, qtype: RrType) -> DnsPacket {
        let mut hdr = DnsHeader::default();
        hdr.id = 0x1234;
        hdr.qdcount = 1;
        DnsPacket {
            header: hdr,
            questions: vec![DnsQuestion { name: name.into(), qtype: qtype as u16, qclass: 1 }],
            answers: vec![],
            authority: vec![],
            additional: vec![],
        }
    }

    fn peer() -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 1), 12345))
    }

    fn int_names_with_addr(zone_domain: &str, host: &str, addr: Ipv4Addr) -> InterfaceName {
        InterfaceName {
            name: format!("{host}.{zone_domain}"),
            intr: "eth0".into(),
            flags: 0,
            proto4: None,
            proto6: None,
            addrs: vec![Addrlist { addr: AllAddr::Addr4(addr), flags: 0, prefixlen: 32, decline_time: None }],
        }
    }

    // ── in_zone ───────────────────────────────────────────────────────────────

    #[test]
    fn in_zone_exact_match_no_cut() {
        assert_eq!(in_zone("example.com", "example.com"), Some(None));
    }

    #[test]
    fn in_zone_subdomain_has_cut() {
        let cut = in_zone("www.example.com", "example.com").expect("in zone");
        let idx = cut.expect("cut point");
        assert_eq!(&"www.example.com"[..idx], "www");
        assert_eq!(&"www.example.com"[idx..], ".example.com");
    }

    #[test]
    fn in_zone_different_zone_is_none() {
        assert_eq!(in_zone("example.org", "example.com"), None);
        assert_eq!(in_zone("notexample.com", "example.com"), None);
    }

    #[test]
    fn in_zone_case_insensitive() {
        assert_eq!(in_zone("WWW.EXAMPLE.COM", "example.com").map(|c| c.is_some()), Some(true));
    }

    // ── OPCODE / QCLASS gating (auth.c:130-153) ─────────────────────────────

    #[test]
    fn non_query_opcode_is_notimp() {
        let mut fx = Fixture::new();
        let mut q = make_query("example.com", RrType::SOA);
        q.header.set_opcode(4); // NOTIFY
        let mut config = fx.config();
        let mut cache = DnsCache::with_ttl_limits(150, 0, 0);
        let reply = answer_auth(&q, &mut config, &mut cache, peer(), false, Instant::now()).expect("a reply");
        assert_eq!(reply.header.rcode(), 4); // NOTIMP
        assert!(reply.answers.is_empty());
        assert!(reply.authority.is_empty());
    }

    #[test]
    fn non_in_qclass_is_refused() {
        let mut fx = Fixture::new();
        let mut q = make_query("example.com", RrType::SOA);
        q.questions[0].qclass = 3; // CH
        let mut config = fx.config();
        let mut cache = DnsCache::with_ttl_limits(150, 0, 0);
        let reply = answer_auth(&q, &mut config, &mut cache, peer(), false, Instant::now()).expect("a reply");
        assert_eq!(reply.header.rcode(), 5); // REFUSED
    }

    // ── A record via --interface-name, filtered through find_subnet/filter_zone ─

    #[test]
    fn a_record_from_int_names_filtered_by_subnet() {
        let mut fx = Fixture::new();
        fx.auth_zones[0].subnet = vec![Addrlist {
            addr: AllAddr::Addr4(Ipv4Addr::new(10, 0, 0, 0)),
            flags: 0,
            prefixlen: 8,
            decline_time: None,
        }];
        fx.int_names.push(int_names_with_addr("example.com", "www", Ipv4Addr::new(10, 1, 2, 3)));
        let q = make_query("www.example.com", RrType::A);
        let mut config = fx.config();
        let mut cache = DnsCache::with_ttl_limits(150, 0, 0);
        let reply = answer_auth(&q, &mut config, &mut cache, peer(), false, Instant::now()).expect("a reply");
        assert_eq!(reply.header.rcode(), 0);
        assert_eq!(reply.answers.len(), 1);
        assert_eq!(reply.answers[0].rdata, [10, 1, 2, 3]);
    }

    #[test]
    fn a_record_excluded_by_zone_subnet() {
        let mut fx = Fixture::new();
        // Only 10.0.0.0/8 is in-zone; the interface address is outside it.
        fx.auth_zones[0].subnet = vec![Addrlist {
            addr: AllAddr::Addr4(Ipv4Addr::new(10, 0, 0, 0)),
            flags: 0,
            prefixlen: 8,
            decline_time: None,
        }];
        fx.int_names.push(int_names_with_addr("example.com", "www", Ipv4Addr::new(192, 168, 1, 1)));
        let q = make_query("www.example.com", RrType::A);
        let mut config = fx.config();
        let mut cache = DnsCache::with_ttl_limits(150, 0, 0);
        let reply = answer_auth(&q, &mut config, &mut cache, peer(), false, Instant::now()).expect("a reply");
        assert!(reply.answers.is_empty());
    }

    // ── PTR against real cache (DHCP lease), FQDN stripped ──────────────────

    #[test]
    fn ptr_from_cache_dhcp_record_strips_fqdn() {
        let mut fx = Fixture::new();
        fx.auth_zones[0].subnet = vec![Addrlist {
            addr: AllAddr::Addr4(Ipv4Addr::new(192, 168, 1, 0)),
            flags: 0,
            prefixlen: 24,
            decline_time: None,
        }];
        let mut cache = DnsCache::with_ttl_limits(150, 0, 0);
        let now = Instant::now();
        cache.really_insert(
            CacheRecord {
                name: "myhost.lan".into(),
                flags: F_DHCP | F_FORWARD | crate::types::constants::F_REVERSE | crate::types::constants::F_IPV4,
                ttl: 3600,
                expires: now + std::time::Duration::from_secs(3600),
                addr: Some(AllAddr::Addr4(Ipv4Addr::new(192, 168, 1, 42))),
                rdata: None,
                uid: UID_NONE,
            },
            now,
        );
        let q = make_query("42.1.168.192.in-addr.arpa", RrType::PTR);
        let mut config = fx.config();
        let reply = answer_auth(&q, &mut config, &mut cache, peer(), false, now).expect("a reply");
        assert_eq!(reply.header.rcode(), 0);
        assert_eq!(reply.answers.len(), 1);
        assert_eq!(reply.answers[0].rtype, RrType::PTR as u16);
        // Bare "myhost" (no dot) gets the zone domain reattached.
        let mut off = 0;
        let target = crate::rfc1035::extract_name(&reply.answers[0].rdata, &mut off).unwrap();
        assert_eq!(target, "myhost.example.com");
    }

    #[test]
    fn ptr_out_of_zone_when_no_subnet_matches() {
        let mut fx = Fixture::new();
        fx.auth_zones[0].subnet = vec![Addrlist {
            addr: AllAddr::Addr4(Ipv4Addr::new(10, 0, 0, 0)),
            flags: 0,
            prefixlen: 8,
            decline_time: None,
        }];
        let q = make_query("42.1.168.192.in-addr.arpa", RrType::PTR);
        let mut config = fx.config();
        let mut cache = DnsCache::with_ttl_limits(150, 0, 0);
        let reply = answer_auth(&q, &mut config, &mut cache, peer(), false, Instant::now()).expect("a reply");
        assert_eq!(reply.header.rcode(), 5); // REFUSED (out of zone)
    }

    // ── CNAME chain + wildcard ───────────────────────────────────────────────

    #[test]
    fn cname_chain_resolves_target() {
        let mut fx = Fixture::new();
        fx.cnames.push(Cname { ttl: 0, flag: 0, alias: "alias.example.com".into(), target: "www.example.com".into() });
        fx.int_names.push(int_names_with_addr("example.com", "www", Ipv4Addr::new(1, 2, 3, 4)));
        let q = make_query("alias.example.com", RrType::A);
        let mut config = fx.config();
        let mut cache = DnsCache::with_ttl_limits(150, 0, 0);
        let reply = answer_auth(&q, &mut config, &mut cache, peer(), false, Instant::now()).expect("a reply");
        assert_eq!(reply.answers.len(), 2); // CNAME + A
        assert_eq!(reply.answers[0].rtype, RrType::CNAME as u16);
        assert_eq!(reply.answers[1].rtype, RrType::A as u16);
        assert_eq!(reply.answers[1].rdata, [1, 2, 3, 4]);
    }

    #[test]
    fn wildcard_cname_matches_and_appends_zone_domain() {
        let mut fx = Fixture::new();
        fx.cnames.push(Cname { ttl: 0, flag: 0, alias: "*.example.com".into(), target: "target".into() });
        fx.int_names.push(int_names_with_addr("example.com", "target", Ipv4Addr::new(5, 6, 7, 8)));
        let q = make_query("anything.example.com", RrType::A);
        let mut config = fx.config();
        let mut cache = DnsCache::with_ttl_limits(150, 0, 0);
        let reply = answer_auth(&q, &mut config, &mut cache, peer(), false, Instant::now()).expect("a reply");
        assert_eq!(reply.answers.len(), 2);
        assert_eq!(reply.answers[0].rtype, RrType::CNAME as u16);
        let mut off = 0;
        let target = crate::rfc1035::extract_name(&reply.answers[0].rdata, &mut off).unwrap();
        assert_eq!(target, "target.example.com");
    }

    // ── SRV + rotation ────────────────────────────────────────────────────

    #[test]
    fn srv_record_served_and_first_match_rotates_to_end() {
        let mut fx = Fixture::new();
        fx.mxnames.push(MxSrvRecord {
            name: "_sip._tcp.example.com".into(), target: "sip1.example.com".into(),
            is_srv: true, srv_port: 5060, priority: 10, weight: 5, offset: 0,
        });
        fx.mxnames.push(MxSrvRecord {
            name: "other.example.com".into(), target: "x.example.com".into(),
            is_srv: false, srv_port: 0, priority: 1, weight: 0, offset: 0,
        });
        let q = make_query("_sip._tcp.example.com", RrType::SRV);
        let mut config = fx.config();
        let mut cache = DnsCache::with_ttl_limits(150, 0, 0);
        let reply = answer_auth(&q, &mut config, &mut cache, peer(), false, Instant::now()).expect("a reply");
        assert_eq!(reply.answers.len(), 1);
        assert_eq!(reply.answers[0].rtype, RrType::SRV as u16);
        // The SRV record moved to the end of mxnames.
        assert!(fx.mxnames[1].is_srv);
    }

    // ── NAPTR ─────────────────────────────────────────────────────────────

    #[test]
    fn naptr_record_served() {
        let mut fx = Fixture::new();
        fx.naptr.push(Naptr {
            name: "example.com".into(), replace: "replacement.example.com".into(),
            regexp: String::new(), services: "E2U+sip".into(), flags: "u".into(),
            order: 100, pref: 10,
        });
        let q = make_query("example.com", RrType::NAPTR);
        let mut config = fx.config();
        let mut cache = DnsCache::with_ttl_limits(150, 0, 0);
        let reply = answer_auth(&q, &mut config, &mut cache, peer(), false, Instant::now()).expect("a reply");
        assert_eq!(reply.answers.len(), 1);
        assert_eq!(reply.answers[0].rtype, RrType::NAPTR as u16);
    }

    // ── AXFR authorization ───────────────────────────────────────────────

    #[test]
    fn axfr_refused_with_no_peers_configured() {
        let mut fx = Fixture::new();
        let q = make_query("example.com", RrType::AXFR);
        let mut config = fx.config();
        let mut cache = DnsCache::with_ttl_limits(150, 0, 0);
        let reply = answer_auth(&q, &mut config, &mut cache, peer(), false, Instant::now());
        assert!(reply.is_none(), "unauthorized AXFR must be dropped, not answered");
    }

    #[test]
    fn axfr_allowed_for_listed_auth_peer() {
        let mut fx = Fixture::new();
        fx.auth_peers.push(Iname { name: None, addr: Some(MySockAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 1), 0))), flags: 0 });
        fx.int_names.push(int_names_with_addr("example.com", "www", Ipv4Addr::new(9, 9, 9, 9)));
        let q = make_query("example.com", RrType::AXFR);
        let mut config = fx.config();
        let mut cache = DnsCache::with_ttl_limits(150, 0, 0);
        let reply = answer_auth(&q, &mut config, &mut cache, peer(), false, Instant::now()).expect("authorized AXFR");
        assert_eq!(reply.header.rcode(), 0);
        assert!(reply.answers.len() >= 3);
        assert_eq!(reply.answers.first().unwrap().rtype, RrType::SOA as u16);
        assert_eq!(reply.answers.last().unwrap().rtype, RrType::SOA as u16);
    }

    #[test]
    fn axfr_allowed_via_secondary_forward_server_with_no_peer_list() {
        let mut fx = Fixture::new();
        fx.secondary_forward_servers.push("secondary.example.net".into());
        let q = make_query("example.com", RrType::AXFR);
        let mut config = fx.config();
        let mut cache = DnsCache::with_ttl_limits(150, 0, 0);
        let reply = answer_auth(&q, &mut config, &mut cache, peer(), false, Instant::now()).expect("authorized AXFR");
        assert_eq!(reply.header.rcode(), 0);
    }

    #[test]
    fn axfr_refused_for_unlisted_peer() {
        let mut fx = Fixture::new();
        fx.auth_peers.push(Iname {
            name: None,
            addr: Some(MySockAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 0, 0, 0))),
            flags: 0,
        });
        let q = make_query("example.com", RrType::AXFR);
        let mut config = fx.config();
        let mut cache = DnsCache::with_ttl_limits(150, 0, 0);
        let reply = answer_auth(&q, &mut config, &mut cache, peer(), false, Instant::now());
        assert!(reply.is_none());
    }

    // ── NXDOMAIN / NODATA / SOA at apex ─────────────────────────────────────

    #[test]
    fn nxdomain_for_unknown_name() {
        let mut fx = Fixture::new();
        let q = make_query("nosuchname.example.com", RrType::A);
        let mut config = fx.config();
        let mut cache = DnsCache::with_ttl_limits(150, 0, 0);
        let reply = answer_auth(&q, &mut config, &mut cache, peer(), false, Instant::now()).expect("a reply");
        assert!(reply.answers.is_empty());
        assert_eq!(reply.header.rcode(), 3); // NXDOMAIN
        assert!(reply.header.hb3 & HB3_AA != 0);
    }

    #[test]
    fn nodata_when_name_exists_but_wrong_type() {
        let mut fx = Fixture::new();
        fx.int_names.push(int_names_with_addr("example.com", "www", Ipv4Addr::new(1, 1, 1, 1)));
        let q = make_query("www.example.com", RrType::MX);
        let mut config = fx.config();
        let mut cache = DnsCache::with_ttl_limits(150, 0, 0);
        let reply = answer_auth(&q, &mut config, &mut cache, peer(), false, Instant::now()).expect("a reply");
        assert!(reply.answers.is_empty());
        assert_eq!(reply.header.rcode(), 0); // NOERROR (NODATA)
    }

    #[test]
    fn soa_at_zone_apex() {
        let mut fx = Fixture::new();
        let q = make_query("example.com", RrType::SOA);
        let mut config = fx.config();
        let mut cache = DnsCache::with_ttl_limits(150, 0, 0);
        let reply = answer_auth(&q, &mut config, &mut cache, peer(), false, Instant::now()).expect("a reply");
        assert_eq!(reply.answers.len(), 1);
        assert_eq!(reply.answers[0].rtype, RrType::SOA as u16);
        assert_eq!(reply.header.rcode(), 0);
    }

    #[test]
    fn out_of_zone_query_is_refused() {
        let mut fx = Fixture::new();
        let q = make_query("example.org", RrType::A);
        let mut config = fx.config();
        let mut cache = DnsCache::with_ttl_limits(150, 0, 0);
        let reply = answer_auth(&q, &mut config, &mut cache, peer(), false, Instant::now()).expect("a reply");
        assert_eq!(reply.header.rcode(), 5); // REFUSED
        assert!(reply.answers.is_empty());
    }

    // ── find_addrlist / find_subnet / find_exclude / filter_zone ─────────────

    fn make_auth_zone(subnet: Vec<Addrlist>, exclude: Vec<Addrlist>) -> AuthZone {
        AuthZone { domain: "example.com".into(), interface_names: vec![], subnet, exclude }
    }

    fn addrlist_v4(addr: Ipv4Addr, prefix: i32) -> Addrlist {
        Addrlist { addr: AllAddr::Addr4(addr), flags: 0, prefixlen: prefix, decline_time: None }
    }

    fn addrlist_v6(addr: Ipv6Addr, prefix: i32) -> Addrlist {
        Addrlist { addr: AllAddr::Addr6(addr), flags: ADDRLIST_IPV6, prefixlen: prefix, decline_time: None }
    }

    #[test]
    fn find_addrlist_v4_match() {
        let list = vec![addrlist_v4("10.0.0.0".parse().unwrap(), 24)];
        let addr = AllAddr::Addr4("10.0.0.42".parse().unwrap());
        assert!(find_addrlist(&list, &addr).is_some());
    }

    #[test]
    fn find_addrlist_v4_no_match() {
        let list = vec![addrlist_v4("10.0.0.0".parse().unwrap(), 24)];
        let addr = AllAddr::Addr4("10.0.1.1".parse().unwrap());
        assert!(find_addrlist(&list, &addr).is_none());
    }

    #[test]
    fn find_addrlist_v6_match() {
        let list = vec![addrlist_v6("2001:db8::".parse().unwrap(), 48)];
        let addr = AllAddr::Addr6("2001:db8::1".parse().unwrap());
        assert!(find_addrlist(&list, &addr).is_some());
    }

    #[test]
    fn find_addrlist_v6_no_match() {
        let list = vec![addrlist_v6("2001:db8:1::".parse().unwrap(), 48)];
        let addr = AllAddr::Addr6("2001:db8:2::1".parse().unwrap());
        assert!(find_addrlist(&list, &addr).is_none());
    }

    #[test]
    fn find_addrlist_empty() {
        let addr = AllAddr::Addr4("10.0.0.1".parse().unwrap());
        assert!(find_addrlist(&[], &addr).is_none());
    }

    #[test]
    fn find_subnet_returns_false_when_empty() {
        let zone = make_auth_zone(vec![], vec![]);
        let addr = AllAddr::Addr4("10.0.0.1".parse().unwrap());
        assert!(!find_subnet(&zone, &addr));
    }

    #[test]
    fn find_subnet_matches() {
        let zone = make_auth_zone(vec![addrlist_v4("10.0.0.0".parse().unwrap(), 24)], vec![]);
        let addr = AllAddr::Addr4("10.0.0.42".parse().unwrap());
        assert!(find_subnet(&zone, &addr));
    }

    #[test]
    fn find_exclude_matches() {
        let zone = make_auth_zone(vec![], vec![addrlist_v4("10.0.0.0".parse().unwrap(), 24)]);
        let addr = AllAddr::Addr4("10.0.0.42".parse().unwrap());
        assert!(find_exclude(&zone, &addr));
    }

    #[test]
    fn filter_zone_no_subnet_allows_all() {
        let zone = make_auth_zone(vec![], vec![]);
        let addr = AllAddr::Addr4("192.168.1.1".parse().unwrap());
        assert!(filter_zone(&zone, &addr));
    }

    #[test]
    fn filter_zone_excludes_matching_addr() {
        let zone = make_auth_zone(
            vec![addrlist_v4("10.0.0.0".parse().unwrap(), 8)],
            vec![addrlist_v4("10.0.1.0".parse().unwrap(), 24)],
        );
        let addr = AllAddr::Addr4("10.0.1.5".parse().unwrap());
        assert!(!filter_zone(&zone, &addr));
    }

    #[test]
    fn filter_zone_allows_non_excluded() {
        let zone = make_auth_zone(
            vec![addrlist_v4("10.0.0.0".parse().unwrap(), 8)],
            vec![addrlist_v4("10.0.1.0".parse().unwrap(), 24)],
        );
        let addr = AllAddr::Addr4("10.0.2.5".parse().unwrap());
        assert!(filter_zone(&zone, &addr));
    }

    #[test]
    fn filter_zone_rejects_not_in_subnet() {
        let zone = make_auth_zone(vec![addrlist_v4("10.0.0.0".parse().unwrap(), 24)], vec![]);
        let addr = AllAddr::Addr4("192.168.1.1".parse().unwrap());
        assert!(!filter_zone(&zone, &addr));
    }

    #[test]
    fn reverse_zone_name_v4_slash24() {
        let s = Addrlist { addr: AllAddr::Addr4(Ipv4Addr::new(192, 168, 1, 0)), flags: 0, prefixlen: 24, decline_time: None };
        assert_eq!(reverse_zone_name(&s), "1.168.192.in-addr.arpa");
    }

    #[test]
    fn unused_shared_cache_helper_compiles() {
        // Sanity check that the shared-cache constructor used elsewhere in the
        // crate is still reachable from this module's test imports.
        let _ = new_shared_cache(1, 0, 0);
    }
}
