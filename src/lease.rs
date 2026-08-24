//! In-memory DHCP lease database with text-format serialisation.
//! Ported from `lease.c`.

#[cfg(feature = "dhcp")]
use std::collections::HashMap;
#[cfg(feature = "dhcp")]
use std::net::Ipv4Addr;
#[cfg(feature = "dhcp")]
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(feature = "dhcp")]
use crate::dhcp_protocol::DHCP_CHADDR_MAX;
#[cfg(feature = "dhcp")]
use crate::helper::{run_script_child, ScriptData};
#[cfg(feature = "dhcp")]
use crate::types::dhcp::{DhcpLease, LeaseFlags, ACTION_ADD, ACTION_DEL, ACTION_OLD};

/// Errors that can occur during lease deserialisation.
#[cfg(feature = "dhcp")]
#[derive(Debug, thiserror::Error)]
pub enum LeaseError {
    #[error("parse error at line {0}: {1}")]
    ParseError(usize, String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Pad or truncate a byte slice to a fixed-length 16-byte key.
#[cfg(feature = "dhcp")]
fn to_key(id: &[u8]) -> [u8; 16] {
    let mut key = [0u8; 16];
    let n = id.len().min(16);
    key[..n].copy_from_slice(&id[..n]);
    key
}

/// Build a client-id key from a `DhcpLease`, preferring the explicit client-id
/// and falling back to the hardware address bytes.
#[cfg(feature = "dhcp")]
fn lease_key(lease: &DhcpLease) -> [u8; 16] {
    if let Some(clid) = &lease.clid {
        if !clid.is_empty() {
            return to_key(clid);
        }
    }
    to_key(&lease.hwaddr[..lease.hwaddr_len.min(DHCP_CHADDR_MAX)])
}

/// In-memory DHCP lease database.
#[cfg(feature = "dhcp")]
pub struct LeaseDb {
    leases: HashMap<[u8; 16], DhcpLease>,
    /// Maximum number of leases allowed.
    pub max_leases: usize,
    /// Set to `true` when the lease file needs rewriting.
    pub file_dirty: bool,
    /// Set to `true` when DNS records derived from leases need updating.
    pub dns_dirty: bool,
    /// Leases removed from `leases` (by expiry or explicit release/decline)
    /// that are still awaiting their `del`/`old` dhcp-script notification.
    /// Port of the `old_leases` list in lease.c.
    old_leases: Vec<DhcpLease>,
}

#[cfg(feature = "dhcp")]
impl LeaseDb {
    /// Create an empty lease database.
    pub fn new() -> Self {
        Self {
            leases: HashMap::new(),
            max_leases: 1000,
            file_dirty: false,
            dns_dirty: false,
            old_leases: Vec::new(),
        }
    }

    /// Add or renew a lease (identified by its client-id / hardware address).
    pub fn insert(&mut self, lease: DhcpLease) {
        let key = lease_key(&lease);
        self.leases.insert(key, lease);
    }

    /// Find a lease by its assigned IPv4 address.
    pub fn find_by_addr(&self, addr: Ipv4Addr) -> Option<&DhcpLease> {
        self.leases.values().find(|l| l.addr == addr)
    }

    /// Find a lease by client identifier (hardware address or option 61 bytes).
    pub fn find_by_client_id(&self, client_id: &[u8]) -> Option<&DhcpLease> {
        let key = to_key(client_id);
        self.leases.get(&key)
    }

    /// Remove leases that expired before `now_secs` (seconds since UNIX epoch).
    /// Returns the removed leases.
    pub fn prune(&mut self, now_secs: u64) -> Vec<DhcpLease> {
        let now = UNIX_EPOCH + Duration::from_secs(now_secs);
        let mut pruned = Vec::new();
        self.leases.retain(|_, lease| {
            if let Some(exp) = lease.expires {
                if exp < now {
                    pruned.push(lease.clone());
                    return false;
                }
            }
            true
        });
        self.old_leases.extend(pruned.iter().cloned());
        pruned
    }

    /// Serialise all leases to a simple text format (one per line).
    ///
    /// Format: `<expires_unix_secs> <ip> <hwaddr_hex> <hostname|*> <clid_hex|*>`
    pub fn serialize(&self) -> String {
        let mut out = String::new();
        for lease in self.leases.values() {
            let expires = match lease.expires {
                Some(t) => t
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
                None => 0,
            };
            let ip = lease.addr;
            let hw: String = lease.hwaddr[..lease.hwaddr_len.min(DHCP_CHADDR_MAX)]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(":");
            let hostname = lease
                .hostname
                .as_deref()
                .unwrap_or("*")
                .to_string();
            let clid = match &lease.clid {
                Some(c) if !c.is_empty() => c
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(":"),
                _ => "*".to_string(),
            };
            out.push_str(&format!(
                "{expires} {ip} {hw} {hostname} {clid}\n"
            ));
        }
        out
    }

    /// Deserialise a lease database from the text produced by [`serialize`].
    pub fn deserialize(text: &str) -> Result<Self, LeaseError> {
        let mut db = Self::new();
        for (line_no, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.splitn(5, ' ').collect();
            if parts.len() != 5 {
                return Err(LeaseError::ParseError(
                    line_no + 1,
                    format!("expected 5 fields, got {}", parts.len()),
                ));
            }
            let expires_secs: u64 = parts[0].parse().map_err(|_| {
                LeaseError::ParseError(line_no + 1, "invalid expires".into())
            })?;
            let ip: Ipv4Addr = parts[1].parse().map_err(|_| {
                LeaseError::ParseError(line_no + 1, "invalid IP address".into())
            })?;
            let hw_bytes = parse_hex_colon(parts[2]).ok_or_else(|| {
                LeaseError::ParseError(line_no + 1, "invalid hwaddr".into())
            })?;
            let hostname = if parts[3] == "*" {
                None
            } else {
                Some(parts[3].to_string())
            };
            let clid = if parts[4] == "*" {
                None
            } else {
                Some(parse_hex_colon(parts[4]).ok_or_else(|| {
                    LeaseError::ParseError(line_no + 1, "invalid client-id".into())
                })?)
            };

            let expires = if expires_secs == 0 {
                None
            } else {
                Some(UNIX_EPOCH + Duration::from_secs(expires_secs))
            };

            let hwaddr_len = hw_bytes.len().min(DHCP_CHADDR_MAX);
            let mut hwaddr = [0u8; DHCP_CHADDR_MAX];
            hwaddr[..hwaddr_len].copy_from_slice(&hw_bytes[..hwaddr_len]);

            let lease = DhcpLease {
                clid,
                hostname,
                fqdn: None,
                old_hostname: None,
                flags: LeaseFlags::empty(),
                expires,
                hwaddr,
                hwaddr_len,
                hwaddr_type: 1,
                addr: ip,
                giaddr: Ipv4Addr::UNSPECIFIED,
                extradata: Vec::new(),
                last_interface: 0,
                new_interface: 0,
                new_prefixlen: 0,
                agent_id: None,
                vendorclass: None,
                #[cfg(feature = "dhcp6")]
                addr6: std::net::Ipv6Addr::UNSPECIFIED,
                #[cfg(feature = "dhcp6")]
                iaid: 0,
                #[cfg(feature = "dhcp6")]
                slaac_address: Vec::new(),
                #[cfg(feature = "dhcp6")]
                vendorclass_count: 0,
            };
            db.insert(lease);
        }
        Ok(db)
    }

    /// Allocate a new IPv4 lease. Returns `None` if `max_leases` would be exceeded.
    pub fn allocate_v4(&mut self, addr: Ipv4Addr) -> Option<&mut DhcpLease> {
        use crate::types::dhcp::LeaseFlags;

        if self.leases.len() >= self.max_leases {
            return None;
        }

        let lease = DhcpLease {
            clid: None,
            hostname: None,
            fqdn: None,
            old_hostname: None,
            flags: LeaseFlags::NEW,
            expires: None,
            hwaddr: [0u8; DHCP_CHADDR_MAX],
            hwaddr_len: 0,
            hwaddr_type: 0,
            addr,
            giaddr: Ipv4Addr::UNSPECIFIED,
            extradata: Vec::new(),
            last_interface: 0,
            new_interface: 0,
            new_prefixlen: 0,
            agent_id: None,
            vendorclass: None,
            #[cfg(feature = "dhcp6")]
            addr6: std::net::Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            iaid: 0,
            #[cfg(feature = "dhcp6")]
            slaac_address: Vec::new(),
            #[cfg(feature = "dhcp6")]
            vendorclass_count: 0,
        };

        let key = lease_key(&lease);
        self.leases.insert(key, lease);
        self.file_dirty = true;
        self.dns_dirty = true;
        self.leases.get_mut(&key)
    }

    /// Set the expiry time for a lease. `0xFFFFFFFF` means infinite (no expiry).
    /// Otherwise the lease expires at `now + duration_secs`.
    pub fn set_expires(&mut self, addr: Ipv4Addr, duration_secs: u32) {
        use crate::types::dhcp::LeaseFlags;

        if let Some(lease) = self.leases.values_mut().find(|l| l.addr == addr) {
            let new_expires = if duration_secs == 0xFFFF_FFFF {
                None
            } else {
                Some(SystemTime::now() + Duration::from_secs(duration_secs as u64))
            };

            if lease.expires != new_expires {
                lease.expires = new_expires;
                lease.flags.insert(LeaseFlags::AUX_CHANGED | LeaseFlags::EXP_CHANGED);
                self.file_dirty = true;
            }
        }
    }

    /// Update hardware address and optional client-id on a lease.
    ///
    /// `force` mirrors upstream `lease_set_hwaddr()`'s own `force` parameter
    /// (lease.c:940) — the init-reboot-without-prior-record case passes
    /// `true` (rfc2131.c:679); this port's DHCPv4 path does not yet track
    /// that distinction and always passes `false` (see `tasks.md`).
    ///
    /// Returns whether a SLAAC-relevant change occurred (upstream's local
    /// `change` — lease.c:944,975,984 — true when `force` is set or the
    /// client-id changed; a hwaddr-only change does *not* set it, matching
    /// upstream exactly). Callers that also track `daemon->dhcp6` contexts
    /// should feed this into [`crate::slaac::slaac_add_addrs`] the way
    /// `lease_set_hwaddr()` calls `slaac_add_addrs()` inline (lease.c:992-993).
    pub fn set_hwaddr(
        &mut self,
        addr: Ipv4Addr,
        hwaddr: &[u8],
        hw_type: i32,
        clid: Option<&[u8]>,
        force: bool,
    ) -> bool {
        // We need to find the lease, potentially remove/re-key it if clid changes.
        let key = {
            let lease = match self.leases.values().find(|l| l.addr == addr) {
                Some(l) => l,
                None => return false,
            };
            lease_key(lease)
        };

        let lease = match self.leases.get_mut(&key) {
            Some(l) if l.addr == addr => l,
            _ => return false,
        };

        #[cfg(feature = "dhcp6")]
        {
            lease.flags.insert(LeaseFlags::HAVE_HWADDR);
        }

        let mut change = force;

        // Check if hwaddr changed
        let hw_len = hwaddr.len().min(DHCP_CHADDR_MAX);
        let hw_changed = lease.hwaddr_len != hw_len
            || lease.hwaddr_type != hw_type
            || lease.hwaddr[..hw_len] != hwaddr[..hw_len];

        if hw_changed {
            lease.hwaddr = [0u8; DHCP_CHADDR_MAX];
            lease.hwaddr[..hw_len].copy_from_slice(&hwaddr[..hw_len]);
            lease.hwaddr_len = hw_len;
            lease.hwaddr_type = hw_type;
            lease.flags.insert(LeaseFlags::CHANGED);
            self.file_dirty = true;
        }

        // Check if clid changed. Only ever considered when a clid is
        // actually supplied — a packet with no clid must not clear or
        // "un-set" an existing one (lease.c:963-965).
        if let Some(clid) = clid {
            let clid_changed = lease.clid.as_deref() != Some(clid);
            if clid_changed {
                change = true;
                // Need to re-key: remove with old key, update clid, insert with new key
                let mut lease = self.leases.remove(&key).unwrap();
                lease.clid = Some(clid.to_vec());
                lease.flags.insert(LeaseFlags::AUX_CHANGED);
                self.file_dirty = true;
                let new_key = lease_key(&lease);
                self.leases.insert(new_key, lease);
            }
        }

        change
    }

    /// Set the hostname on a lease. If `auth` is true, the `LEASE_AUTH_NAME` flag
    /// is set. If another lease already has this name, the name is removed from
    /// that lease first.
    pub fn set_hostname(&mut self, addr: Ipv4Addr, name: Option<&str>, auth: bool) {
        use crate::types::dhcp::LeaseFlags;

        // If a name is being set, check for duplicates and remove from other leases.
        if let Some(new_name) = name {
            // Collect addrs of leases that have the same hostname (but different addr).
            let duplicates: Vec<Ipv4Addr> = self
                .leases
                .values()
                .filter(|l| l.addr != addr)
                .filter(|l| {
                    l.hostname
                        .as_deref()
                        .map(|h| crate::util::hostname_isequal(h, new_name))
                        .unwrap_or(false)
                })
                .map(|l| l.addr)
                .collect();

            for dup_addr in duplicates {
                if let Some(dup) = self.leases.values_mut().find(|l| l.addr == dup_addr) {
                    dup.old_hostname = dup.hostname.take();
                    dup.flags.insert(LeaseFlags::CHANGED);
                }
            }
        }

        // Now set the hostname on the target lease.
        if let Some(lease) = self.leases.values_mut().find(|l| l.addr == addr) {
            let name_changed = match (&lease.hostname, name) {
                (Some(old), Some(new)) => !crate::util::hostname_isequal(old, new),
                (None, None) => false,
                _ => true,
            };

            if name_changed {
                lease.old_hostname = lease.hostname.take();
                lease.hostname = name.map(|n| n.to_string());
                lease.flags.insert(LeaseFlags::CHANGED);
                self.file_dirty = true;
                self.dns_dirty = true;
            }

            if auth {
                lease.flags.insert(LeaseFlags::AUTH_NAME);
            } else {
                lease.flags.remove(LeaseFlags::AUTH_NAME);
            }
        }
    }

    /// Record the interface a lease is bound to.
    pub fn set_interface(&mut self, addr: Ipv4Addr, interface: i32) {
        if let Some(lease) = self.leases.values_mut().find(|l| l.addr == addr) {
            lease.last_interface = interface;
        }
    }

    /// Set the DHCP relay agent information on a lease.
    pub fn set_agent_id(&mut self, addr: Ipv4Addr, agent_id: Option<&[u8]>) {
        use crate::types::dhcp::LeaseFlags;

        if let Some(lease) = self.leases.values_mut().find(|l| l.addr == addr) {
            let new_val = agent_id.map(|a| a.to_vec());
            if lease.agent_id != new_val {
                lease.agent_id = new_val;
                lease.flags.insert(LeaseFlags::AUX_CHANGED);
                self.file_dirty = true;
            }
        }
    }

    /// Set the vendor class information on a lease.
    pub fn set_vendorclass(&mut self, addr: Ipv4Addr, vendorclass: Option<&[u8]>) {
        use crate::types::dhcp::LeaseFlags;

        if let Some(lease) = self.leases.values_mut().find(|l| l.addr == addr) {
            let new_val = vendorclass.map(|v| v.to_vec());
            if lease.vendorclass != new_val {
                lease.vendorclass = new_val;
                lease.flags.insert(LeaseFlags::AUX_CHANGED);
                self.file_dirty = true;
            }
        }
    }

    /// Find the highest allocated IPv4 address within `[start, end]`.
    /// Returns `start` if no leases exist in the range.
    pub fn find_max_addr(&self, start: Ipv4Addr, end: Ipv4Addr) -> Ipv4Addr {
        let start_u32 = u32::from(start);
        let end_u32 = u32::from(end);

        self.leases
            .values()
            .map(|l| u32::from(l.addr))
            .filter(|&a| a >= start_u32 && a <= end_u32)
            .max()
            .map(Ipv4Addr::from)
            .unwrap_or(start)
    }

    /// Mark every lease as `LEASE_CHANGED` so that helper scripts are re-run.
    pub fn rerun_scripts(&mut self) {
        use crate::types::dhcp::LeaseFlags;

        for lease in self.leases.values_mut() {
            lease.flags.insert(LeaseFlags::CHANGED);
        }
        self.file_dirty = true;
    }

    /// Fire the configured dhcp-script hook for every lease change queued
    /// since the last call, then clear the flags/queue that generated them.
    ///
    /// Port of `do_script_run()` (lease.c:1216-1308). Upstream calls
    /// `do_script_run()` from the main loop unconditionally — even the
    /// `#else` branch compiled without `HAVE_SCRIPT` calls it, "need this
    /// for other side-effects" (dnsmasq.c) — because draining `old_leases`
    /// and clearing per-lease flags is not itself gated on a script being
    /// configured; only the `queue_script()` spawn is. `command` being
    /// `None` mirrors that: every event queued on `old_leases` (from
    /// `prune`/`remove_by_addr`) and every `LEASE_NEW`/`LEASE_CHANGED` lease
    /// still has its flags/queue entry cleared, just without spawning a
    /// script. Callers must invoke this every dispatch regardless of
    /// whether `command` is set, or `old_leases` grows without bound.
    ///
    /// Upstream fires one event per call and relies on the main loop
    /// invoking it repeatedly (its return value signals "more work
    /// pending"); this port drains every pending event in a single call
    /// since the caller here is a single `run_dhcp_loop` iteration rather
    /// than a busy-poll main loop. The ordering and action semantics are
    /// preserved: leases queued on `old_leases` fire `old` (for a leftover
    /// `old_hostname`) then `del`; live leases with a pending
    /// `old_hostname` fire `old` first so a lost name is announced before
    /// any new one; then leases flagged `LEASE_NEW`/`LEASE_CHANGED` fire
    /// `add`/`old` and have those flags (plus `LEASE_AUX_CHANGED` /
    /// `LEASE_EXP_CHANGED`) cleared.
    /// `leasefile_ro`/`script_on_renewal` mirror `--leasefile-ro`
    /// (`OPT_LEASE_RO`) / `--script-on-renewal` (`OPT_LEASE_RENEW`).
    ///
    /// Port of `do_script_run()`'s trigger condition (lease.c:1286-1288):
    /// `(LEASE_NEW|LEASE_CHANGED) || (LEASE_AUX_CHANGED && OPT_LEASE_RO) ||
    /// (LEASE_EXP_CHANGED && OPT_LEASE_RENEW)`. Without the latter two
    /// disjuncts, a pure lease renewal (no name/major change, only
    /// `LEASE_AUX_CHANGED`/`LEASE_EXP_CHANGED` set by [`Self::set_expires`])
    /// never fires the `old` notification `--leasefile-ro`/
    /// `--script-on-renewal` promise, and — since the clear is gated inside
    /// the same `if` — those flags are never cleared either.
    pub fn run_lease_scripts(&mut self, command: Option<&str>, leasefile_ro: bool, script_on_renewal: bool) {
        use crate::types::dhcp::LeaseFlags;

        // `run_script_child` runs the script synchronously and in-process —
        // this port has no live caller of `helper::create_helper`'s
        // fork+privilege-drop child yet (see tasks.md), so there is no
        // persistent helper to hand events to. `log_dhcp` (OPT_LOG_OPTS)
        // isn't threaded through from `Daemon` for the same reason; `false`
        // matches this function's previous behavior, which never set a
        // DNSMASQ_LOG_DHCP-style var either.
        const LOG_DHCP: bool = false;

        for mut lease in self.old_leases.drain(..) {
            if let Some(old_hostname) = lease.old_hostname.take() {
                if let Some(command) = command {
                    let ev = build_script_event(&lease, ACTION_OLD, Some(&old_hostname));
                    run_script_child(command, "old", &ev, LOG_DHCP);
                }
            }
            if let Some(command) = command {
                let ev = build_script_event(&lease, ACTION_DEL, None);
                run_script_child(command, "del", &ev, LOG_DHCP);
            }
        }

        for lease in self.leases.values_mut() {
            if let Some(old_hostname) = lease.old_hostname.take() {
                if let Some(command) = command {
                    let ev = build_script_event(lease, ACTION_OLD, Some(&old_hostname));
                    run_script_child(command, "old", &ev, LOG_DHCP);
                }
            }
        }

        for lease in self.leases.values_mut() {
            if lease.flags.intersects(LeaseFlags::NEW | LeaseFlags::CHANGED)
                || (lease.flags.contains(LeaseFlags::AUX_CHANGED) && leasefile_ro)
                || (lease.flags.contains(LeaseFlags::EXP_CHANGED) && script_on_renewal)
            {
                if let Some(command) = command {
                    let (action, action_str) = if lease.flags.contains(LeaseFlags::NEW) {
                        (ACTION_ADD, "add")
                    } else {
                        (ACTION_OLD, "old")
                    };
                    let ev = build_script_event(lease, action, None);
                    run_script_child(command, action_str, &ev, LOG_DHCP);
                }
                lease.flags.remove(LeaseFlags::NEW | LeaseFlags::CHANGED | LeaseFlags::AUX_CHANGED | LeaseFlags::EXP_CHANGED);
            }
        }
    }

    /// Write all leases to the given file path (using [`serialize`]).
    ///
    /// Writes to a temp file in the same directory, `fsync`s it, `rename`s
    /// it over `path`, then (on Unix) `fsync`s the containing directory so
    /// the rename entry itself is durable. The rename is atomic on the same
    /// filesystem, so a crash or write failure part-way through never
    /// leaves `path` truncated or half-written — readers always see either
    /// the old complete file or the new one. This is stronger than
    /// upstream's `lease_update_file` (lease.c:278-446), which truncates
    /// and rewrites a single long-lived fd in place and relies on `fsync`
    /// alone; the observable guarantee upstream cares about — durable data
    /// survives a clean write, and a failed write doesn't corrupt the file
    /// — is preserved here.
    pub fn write_to_file(&self, path: &str) -> Result<(), LeaseError> {
        use std::io::Write;

        let data = self.serialize();
        let target = std::path::Path::new(path);
        let dir = target.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| std::path::Path::new("."));
        let file_name = target.file_name().and_then(|n| n.to_str()).unwrap_or("leases");
        let tmp_path = dir.join(format!(".{file_name}.tmp"));

        let mut f = std::fs::File::create(&tmp_path)?;
        f.write_all(data.as_bytes())?;
        f.sync_all()?;
        drop(f);

        std::fs::rename(&tmp_path, target)?;

        // fsync the containing directory so the rename itself is durable
        // across a crash/power loss, not just the temp file's contents —
        // without this, ext4/xfs may still lose the rename (leaving the old
        // file, or nothing) even though the temp file's data was flushed.
        #[cfg(unix)]
        {
            if let Ok(dir_file) = std::fs::File::open(dir) {
                let _ = dir_file.sync_all();
            }
        }

        Ok(())
    }

    /// Load a lease database from a file (using [`deserialize`]).
    pub fn load_from_file(path: &str) -> Result<Self, LeaseError> {
        let data = std::fs::read_to_string(path)?;
        Self::deserialize(&data)
    }

    /// Remove and return the lease at `addr`, if any.
    ///
    /// Port of `lease_prune()`'s free-the-matching-lease behaviour from
    /// lease.c, restricted to the by-address case used by RELEASE/DECLINE.
    pub fn remove_by_addr(&mut self, addr: Ipv4Addr) -> Option<DhcpLease> {
        let key = self
            .leases
            .iter()
            .find(|(_, l)| l.addr == addr)
            .map(|(k, _)| *k)?;
        self.file_dirty = true;
        self.dns_dirty = true;
        let removed = self.leases.remove(&key)?;
        self.old_leases.push(removed.clone());
        Some(removed)
    }

    /// Return the number of active leases.
    pub fn count(&self) -> usize {
        self.leases.len()
    }

    /// Iterate over all leases.
    pub fn iter(&self) -> impl Iterator<Item = &DhcpLease> {
        self.leases.values()
    }

    /// Mutably iterate over all leases.
    #[cfg(feature = "dhcp6")]
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut DhcpLease> {
        self.leases.values_mut()
    }

    /// Recompute SLAAC addresses for every lease against `contexts` (the
    /// current `daemon->dhcp6` RA-name chain), matching upstream's per-lease
    /// call to `slaac_add_addrs()` at lease commit/load time (lease.c:514,
    /// 998, 1159), applied here across the whole database at once. Sets
    /// `dns_dirty` when any lease's SLAAC address set changed.
    #[cfg(feature = "dhcp6")]
    pub fn refresh_slaac(
        &mut self,
        now: SystemTime,
        contexts: &[crate::types::dhcp::DhcpContext],
        force: bool,
        mut ra_start_unsolicited: impl FnMut(&crate::types::dhcp::DhcpContext),
    ) {
        let mut dirty = false;
        for lease in self.leases.values_mut() {
            if crate::slaac::slaac_add_addrs(lease, now, force, contexts, &mut ra_start_unsolicited) {
                dirty = true;
            }
        }
        if dirty {
            self.dns_dirty = true;
        }
    }

    /// Run one tick of SLAAC DAD probing across every lease
    /// (`periodic_slaac`, slaac.c:119-190). Returns the next wake time, or
    /// `None` if nothing is configured or outstanding.
    #[cfg(feature = "dhcp6")]
    pub fn tick_slaac(
        &mut self,
        now: SystemTime,
        contexts: &[crate::types::dhcp::DhcpContext],
        ping_id: u16,
        send: impl FnMut(std::net::Ipv6Addr, &[u8]) -> std::io::Result<()>,
    ) -> Option<SystemTime> {
        crate::slaac::periodic_slaac(now, contexts, self.leases.values_mut(), ping_id, send)
    }

    /// Handle an inbound ICMPv6 echo reply for SLAAC DAD confirmation
    /// (`slaac_ping_reply`, slaac.c:191-213). Sets `dns_dirty` if any lease's
    /// SLAAC address was confirmed.
    #[cfg(feature = "dhcp6")]
    pub fn confirm_slaac_ping(
        &mut self,
        sender: std::net::Ipv6Addr,
        packet: &[u8],
        ping_id: u16,
        interface: &str,
        quiet: bool,
    ) {
        let gotone = crate::slaac::slaac_ping_reply(
            sender, packet, ping_id, interface, quiet, self.leases.values_mut(),
        );
        if gotone {
            self.dns_dirty = true;
        }
    }

    /// Compute FQDNs for all leases with hostnames.
    ///
    /// Sets `lease.fqdn = hostname + "." + domain` for each lease.
    /// Port of `lease_calc_fqdns()` from lease.c:1024-1052.
    pub fn calc_fqdns(&mut self, domain: &str) {
        for lease in self.leases.values_mut() {
            if let Some(ref hostname) = lease.hostname {
                if !domain.is_empty() {
                    lease.fqdn = Some(format!("{}.{}", hostname, domain));
                } else {
                    lease.fqdn = None;
                }
            }
        }
    }

    /// Find a DHCPv6 lease by CLID, IAID, and address.
    ///
    /// Port of `lease6_find()` from lease.c:696-718.
    #[cfg(feature = "dhcp6")]
    pub fn find_v6_by_clid_iaid(
        &self,
        clid: &[u8],
        iaid: u32,
        addr: &std::net::Ipv6Addr,
    ) -> Option<&DhcpLease> {
        use crate::types::dhcp::LeaseFlags;
        self.leases.values().find(|l| {
            (l.flags.intersects(LeaseFlags::TA | LeaseFlags::NA))
                && l.iaid == iaid
                && l.addr6 == *addr
                && l.clid.as_deref() == Some(clid)
        })
    }

    /// Find a DHCPv6 lease by CLID and IAID alone, regardless of address.
    ///
    /// Used to recall a client's existing address across a fresh Solicit
    /// (upstream's `lease6_find_by_client()`, lease.c:730-750) without
    /// requiring the client to have echoed it back in the request.
    #[cfg(feature = "dhcp6")]
    pub fn find_v6_by_client_iaid(&self, clid: &[u8], iaid: u32) -> Option<&DhcpLease> {
        use crate::types::dhcp::LeaseFlags;
        self.leases.values().find(|l| {
            (l.flags.intersects(LeaseFlags::TA | LeaseFlags::NA))
                && l.iaid == iaid
                && l.clid.as_deref() == Some(clid)
        })
    }

    /// Find a DHCPv6 lease by exact IPv6 address.
    ///
    /// Port of `lease6_find_by_plain_addr()` from lease.c:776-790.
    #[cfg(feature = "dhcp6")]
    pub fn find_v6_by_addr(&self, addr: &std::net::Ipv6Addr) -> Option<&DhcpLease> {
        use crate::types::dhcp::LeaseFlags;
        self.leases.values().find(|l| {
            (l.flags.intersects(LeaseFlags::TA | LeaseFlags::NA)) && l.addr6 == *addr
        })
    }

    /// Allocate a new DHCPv6 lease.
    ///
    /// Port of `lease6_allocate()` from lease.c:873-887.
    #[cfg(feature = "dhcp6")]
    pub fn allocate_v6(
        &mut self,
        addr: std::net::Ipv6Addr,
        lease_type: LeaseFlags,
    ) -> Option<&mut DhcpLease> {
        use crate::types::dhcp::LeaseFlags;

        if self.leases.len() >= self.max_leases {
            return None;
        }

        let lease = DhcpLease {
            clid: None,
            hostname: None,
            fqdn: None,
            old_hostname: None,
            flags: LeaseFlags::NEW | lease_type,
            expires: None,
            hwaddr: [0u8; DHCP_CHADDR_MAX],
            hwaddr_len: 0,
            hwaddr_type: 0,
            addr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            extradata: Vec::new(),
            last_interface: 0,
            new_interface: 0,
            new_prefixlen: 0,
            agent_id: None,
            vendorclass: None,
            addr6: addr,
            iaid: 0,
            slaac_address: Vec::new(),
            vendorclass_count: 0,
        };

        let key = lease_key(&lease);
        self.leases.insert(key, lease);
        self.file_dirty = true;
        self.dns_dirty = true;
        self.leases.get_mut(&key)
    }

    /// Clear LEASE_USED flags on all DHCPv6 leases.
    ///
    /// Port of `lease6_reset()` from lease.c:721-727.
    #[cfg(feature = "dhcp6")]
    pub fn reset_v6_used(&mut self) {
        use crate::types::dhcp::LeaseFlags;
        for lease in self.leases.values_mut() {
            if lease.flags.intersects(LeaseFlags::TA | LeaseFlags::NA) {
                lease.flags.remove(LeaseFlags::USED);
            }
        }
    }

    /// Allocate-or-renew a DHCPv6 lease bound to a specific client/IAID.
    ///
    /// Unlike [`allocate_v6`], which inserts under a placeholder all-zero key
    /// until the caller separately sets `clid`/`iaid` on the returned
    /// reference (never re-keying the map entry, so a second such call before
    /// the first lease's `clid` is set collides on the same key and silently
    /// evicts it), this looks the lease up by `addr` first, removes it if
    /// present, stamps `clid`/`iaid`/`expires`, and re-inserts under the
    /// correct client key in one step — always leaving exactly one map entry
    /// per bound address. Returns `None` only when this would be a genuinely
    /// new lease and `max_leases` is already reached.
    ///
    /// Roughly combines `lease6_allocate()` (lease.c:873-887) with the
    /// `lease_set_iaid()`/binding step callers otherwise do separately.
    #[cfg(feature = "dhcp6")]
    pub fn bind_v6(
        &mut self,
        addr: std::net::Ipv6Addr,
        clid: &[u8],
        iaid: u32,
        lease_type: LeaseFlags,
        expires: Option<SystemTime>,
    ) -> Option<&mut DhcpLease> {
        use crate::types::dhcp::LeaseFlags;

        let existing_key = self.leases.iter().find_map(|(k, l)| {
            (l.flags.intersects(LeaseFlags::TA | LeaseFlags::NA) && l.addr6 == addr).then_some(*k)
        });

        let mut lease = if let Some(k) = existing_key {
            self.leases.remove(&k).unwrap()
        } else {
            if self.leases.len() >= self.max_leases {
                return None;
            }
            DhcpLease {
                clid: None,
                hostname: None,
                fqdn: None,
                old_hostname: None,
                flags: LeaseFlags::NEW | lease_type,
                expires: None,
                hwaddr: [0u8; DHCP_CHADDR_MAX],
                hwaddr_len: 0,
                hwaddr_type: 0,
                addr: Ipv4Addr::UNSPECIFIED,
                giaddr: Ipv4Addr::UNSPECIFIED,
                extradata: Vec::new(),
                last_interface: 0,
                new_interface: 0,
                new_prefixlen: 0,
                agent_id: None,
                vendorclass: None,
                addr6: addr,
                iaid: 0,
                slaac_address: Vec::new(),
                vendorclass_count: 0,
            }
        };

        lease.clid = Some(clid.to_vec());
        lease.iaid = iaid;
        lease.expires = expires;

        let key = lease_key(&lease);
        self.leases.insert(key, lease);
        self.file_dirty = true;
        self.dns_dirty = true;
        self.leases.get_mut(&key)
    }

    /// Remove a DHCPv6 lease matching `clid`/`iaid`/`addr` exactly.
    ///
    /// Returns `true` if a matching lease was found and removed. Port of the
    /// `lease6_find()` + `lease_prune()` pairing used by
    /// `DHCP6RELEASE`/`DHCP6DECLINE` (rfc3315.c:1160-1162, 1241-1243).
    #[cfg(feature = "dhcp6")]
    pub fn remove_v6_by_clid_iaid_addr(
        &mut self,
        clid: &[u8],
        iaid: u32,
        addr: &std::net::Ipv6Addr,
    ) -> bool {
        use crate::types::dhcp::LeaseFlags;
        let key = self.leases.iter().find_map(|(k, l)| {
            (l.flags.intersects(LeaseFlags::TA | LeaseFlags::NA)
                && l.iaid == iaid
                && l.addr6 == *addr
                && l.clid.as_deref() == Some(clid))
            .then_some(*k)
        });
        if let Some(k) = key {
            self.leases.remove(&k);
            self.file_dirty = true;
            true
        } else {
            false
        }
    }
}

/// Build a [`LeaseScriptEvent`] for `lease`.
///
/// `hostname_override`, when set, is used in place of the lease's own
/// `fqdn`/`hostname` — this is how the `old`-for-lost-hostname notification
/// (`ACTION_OLD_HOSTNAME` in lease.c) reports the name that was just
/// removed rather than the lease's current (possibly absent) name.
/// Mirrors the `lease->fqdn ? lease->fqdn : lease->hostname` selection at
/// lease.c:1292 and the `DNSMASQ_LEASE_EXPIRES`/`DNSMASQ_CLIENT_ID` extras
/// `helper::run_script` looks up.
#[cfg(feature = "dhcp")]
fn build_script_event(lease: &DhcpLease, action: u32, hostname_override: Option<&str>) -> ScriptData {
    // Upstream's DEL call site (`lease.c:1255`) always passes NULL for
    // hostname: `do_script_run`'s DEL branch calls `queue_script(ACTION_DEL,
    // lease, lease->old_hostname, now)`, and by that point in the control
    // flow `lease->old_hostname` is always NULL (either never set, or
    // already consumed and freed by the prior ACTION_OLD_HOSTNAME event).
    // Falling through to `fqdn`/`hostname` here for DEL — as ADD/OLD do —
    // would report a deleted lease's hostname on an event upstream always
    // sends with an empty one.
    let hostname = if action == ACTION_DEL {
        None
    } else {
        hostname_override
            .map(|s| s.to_string())
            .or_else(|| lease.fqdn.clone())
            .or_else(|| lease.hostname.clone())
    };
    ScriptData::for_lease(action, lease, hostname.as_deref(), SystemTime::now())
}

/// Parse a colon-separated hex string (e.g. `"de:ad:be:ef"`) into bytes.
#[cfg(feature = "dhcp")]
fn parse_hex_colon(s: &str) -> Option<Vec<u8>> {
    s.split(':')
        .map(|h| u8::from_str_radix(h, 16).ok())
        .collect()
}

#[cfg(feature = "dhcp")]
impl Default for LeaseDb {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(test, feature = "dhcp"))]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    fn make_lease(addr: Ipv4Addr, hw: [u8; 6], expires_secs: Option<u64>) -> DhcpLease {
        let mut hwaddr = [0u8; DHCP_CHADDR_MAX];
        hwaddr[..6].copy_from_slice(&hw);
        DhcpLease {
            clid: None,
            hostname: Some("host1".into()),
            fqdn: None,
            old_hostname: None,
            flags: LeaseFlags::empty(),
            expires: expires_secs.map(|s| UNIX_EPOCH + Duration::from_secs(s)),
            hwaddr,
            hwaddr_len: 6,
            hwaddr_type: 1,
            addr,
            giaddr: Ipv4Addr::UNSPECIFIED,
            extradata: Vec::new(),
            last_interface: 0,
            new_interface: 0,
            new_prefixlen: 0,
            agent_id: None,
            vendorclass: None,
            #[cfg(feature = "dhcp6")]
            addr6: std::net::Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            iaid: 0,
            #[cfg(feature = "dhcp6")]
            slaac_address: Vec::new(),
            #[cfg(feature = "dhcp6")]
            vendorclass_count: 0,
        }
    }

    #[test]
    fn insert_and_find_by_addr() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 5);
        db.insert(make_lease(addr, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], None));
        let found = db.find_by_addr(addr);
        assert!(found.is_some());
        assert_eq!(found.unwrap().addr, addr);
    }

    #[test]
    fn insert_and_find_by_client_id() {
        let mut db = LeaseDb::new();
        let hw = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66];
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 7), hw, None));
        let found = db.find_by_client_id(&hw);
        assert!(found.is_some());
    }

    #[test]
    fn prune_removes_expired_leaves_fresh() {
        let mut db = LeaseDb::new();
        let expired_addr = Ipv4Addr::new(10, 0, 0, 1);
        let fresh_addr = Ipv4Addr::new(10, 0, 0, 2);
        // Expired at epoch+100
        db.insert(make_lease(expired_addr, [0x01, 0, 0, 0, 0, 0], Some(100)));
        // Expires far in the future
        db.insert(make_lease(fresh_addr, [0x02, 0, 0, 0, 0, 0], Some(9_999_999_999)));

        let pruned = db.prune(200);
        assert_eq!(pruned.len(), 1);
        assert_eq!(pruned[0].addr, expired_addr);
        assert!(db.find_by_addr(fresh_addr).is_some());
        assert!(db.find_by_addr(expired_addr).is_none());
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(192, 168, 1, 50);
        db.insert(make_lease(addr, [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01], Some(1_700_000_000)));

        let text = db.serialize();
        let db2 = LeaseDb::deserialize(&text).expect("deserialize failed");
        let found = db2.find_by_addr(addr);
        assert!(found.is_some());
        assert_eq!(found.unwrap().addr, addr);
    }

    #[test]
    fn find_by_addr_nonexistent() {
        let db = LeaseDb::new();
        assert!(db.find_by_addr(Ipv4Addr::new(10, 0, 0, 99)).is_none());
    }

    #[test]
    fn find_by_client_id_nonexistent() {
        let db = LeaseDb::new();
        assert!(db.find_by_client_id(&[0xaa, 0xbb]).is_none());
    }

    #[test]
    fn prune_empty_db() {
        let mut db = LeaseDb::new();
        let pruned = db.prune(1_000_000);
        assert!(pruned.is_empty());
    }

    #[test]
    fn prune_all_expired() {
        let mut db = LeaseDb::new();
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 1), [0x01, 0, 0, 0, 0, 0], Some(100)));
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 2), [0x02, 0, 0, 0, 0, 0], Some(200)));
        let pruned = db.prune(300);
        assert_eq!(pruned.len(), 2);
        assert!(db.find_by_addr(Ipv4Addr::new(10, 0, 0, 1)).is_none());
        assert!(db.find_by_addr(Ipv4Addr::new(10, 0, 0, 2)).is_none());
    }

    #[test]
    fn prune_keeps_no_expiry_leases() {
        let mut db = LeaseDb::new();
        // Lease with no expiry (permanent)
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 1), [0x01, 0, 0, 0, 0, 0], None));
        let pruned = db.prune(9_999_999_999);
        assert!(pruned.is_empty());
        assert!(db.find_by_addr(Ipv4Addr::new(10, 0, 0, 1)).is_some());
    }

    #[test]
    fn deserialize_malformed_too_few_fields() {
        let result = LeaseDb::deserialize("100 10.0.0.1 aa:bb");
        assert!(result.is_err());
    }

    #[test]
    fn deserialize_malformed_invalid_ip() {
        let result = LeaseDb::deserialize("100 not.an.ip aa:bb:cc:dd:ee:ff host1 *");
        assert!(result.is_err());
    }

    #[test]
    fn deserialize_malformed_invalid_expires() {
        let result = LeaseDb::deserialize("notanumber 10.0.0.1 aa:bb:cc:dd:ee:ff host1 *");
        assert!(result.is_err());
    }

    #[test]
    fn deserialize_empty_string() {
        let db = LeaseDb::deserialize("").expect("empty should be ok");
        assert!(db.find_by_addr(Ipv4Addr::new(10, 0, 0, 1)).is_none());
    }

    #[test]
    fn insert_replaces_existing_lease() {
        let mut db = LeaseDb::new();
        let hw = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 1), hw, Some(100)));
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 2), hw, Some(200)));
        // Same hwaddr => same key => replaced
        assert!(db.find_by_addr(Ipv4Addr::new(10, 0, 0, 1)).is_none());
        assert!(db.find_by_addr(Ipv4Addr::new(10, 0, 0, 2)).is_some());
    }

    #[test]
    fn serialize_no_expiry_produces_zero() {
        let mut db = LeaseDb::new();
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 1), [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], None));
        let text = db.serialize();
        assert!(text.starts_with("0 "));
    }

    // ── allocate_v4 tests ──

    #[test]
    fn allocate_v4_creates_lease() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 100);
        let lease = db.allocate_v4(addr);
        assert!(lease.is_some());
        let lease = lease.unwrap();
        assert_eq!(lease.addr, addr);
        assert_eq!(lease.flags, crate::types::dhcp::LeaseFlags::NEW);
    }

    #[test]
    fn allocate_v4_sets_dirty_flags() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 100);
        db.allocate_v4(addr);
        assert!(db.file_dirty);
        assert!(db.dns_dirty);
    }

    #[test]
    fn allocate_v4_enforces_max_leases() {
        let mut db = LeaseDb::new();
        db.max_leases = 2;
        // Use insert with distinct hwaddrs to fill the db to capacity.
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 1), [0x01, 0, 0, 0, 0, 0], None));
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 2), [0x02, 0, 0, 0, 0, 0], None));
        assert_eq!(db.count(), 2);
        let result = db.allocate_v4(Ipv4Addr::new(10, 0, 0, 3));
        assert!(result.is_none());
        assert_eq!(db.count(), 2);
    }

    #[test]
    fn allocate_v4_findable_by_addr() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 50);
        db.allocate_v4(addr);
        assert!(db.find_by_addr(addr).is_some());
    }

    // ── set_expires tests ──

    #[test]
    fn set_expires_infinite() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        db.insert(make_lease(addr, [0x01, 0, 0, 0, 0, 0], Some(100)));
        db.set_expires(addr, 0xFFFF_FFFF);
        let lease = db.find_by_addr(addr).unwrap();
        assert!(lease.expires.is_none());
    }

    #[test]
    fn set_expires_finite() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        db.insert(make_lease(addr, [0x01, 0, 0, 0, 0, 0], None));
        db.set_expires(addr, 3600);
        let lease = db.find_by_addr(addr).unwrap();
        assert!(lease.expires.is_some());
        // Should expire roughly 3600s from now
        let exp = lease.expires.unwrap();
        let diff = exp.duration_since(SystemTime::now()).unwrap();
        assert!(diff.as_secs() <= 3600 && diff.as_secs() >= 3598);
    }

    #[test]
    fn set_expires_sets_flags() {
        use crate::types::dhcp::LeaseFlags;
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        db.insert(make_lease(addr, [0x01, 0, 0, 0, 0, 0], Some(100)));
        db.set_expires(addr, 7200);
        let lease = db.find_by_addr(addr).unwrap();
        assert!(lease.flags.contains(LeaseFlags::AUX_CHANGED));
        assert!(lease.flags.contains(LeaseFlags::EXP_CHANGED));
        assert!(db.file_dirty);
    }

    #[test]
    fn set_expires_nonexistent_no_panic() {
        let mut db = LeaseDb::new();
        db.set_expires(Ipv4Addr::new(10, 0, 0, 99), 100);
        // Should not panic
    }

    // ── set_hwaddr tests ──

    #[test]
    fn set_hwaddr_updates_hardware_address() {
        use crate::types::dhcp::LeaseFlags;
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        db.insert(make_lease(addr, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06], None));

        let new_hw = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        db.set_hwaddr(addr, &new_hw, 1, None, false);

        let lease = db.find_by_addr(addr).unwrap();
        assert_eq!(&lease.hwaddr[..6], &new_hw);
        assert!(lease.flags.contains(LeaseFlags::CHANGED));
        assert!(db.file_dirty);
    }

    #[test]
    fn set_hwaddr_same_address_no_change_flag() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        let hw = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        db.insert(make_lease(addr, hw, None));
        db.file_dirty = false;

        db.set_hwaddr(addr, &hw, 1, None, false);
        // hwaddr didn't change, clid didn't change
        assert!(!db.file_dirty);
    }

    #[test]
    fn set_hwaddr_with_clid_rekeys() {
        use crate::types::dhcp::LeaseFlags;
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        db.insert(make_lease(addr, [0x01, 0, 0, 0, 0, 0], None));

        let clid = vec![0xDE, 0xAD, 0xBE, 0xEF];
        db.set_hwaddr(addr, &[0x01, 0, 0, 0, 0, 0], 1, Some(&clid), false);

        let lease = db.find_by_addr(addr).unwrap();
        assert_eq!(lease.clid, Some(clid));
        assert!(lease.flags.contains(LeaseFlags::AUX_CHANGED));
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn set_hwaddr_sets_lease_have_hwaddr_flag() {
        use crate::types::dhcp::LeaseFlags;
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        db.insert(make_lease(addr, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06], None));
        assert!(!db.find_by_addr(addr).unwrap().flags.contains(LeaseFlags::HAVE_HWADDR));

        db.set_hwaddr(addr, &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], 1, None, false);
        assert!(db.find_by_addr(addr).unwrap().flags.contains(LeaseFlags::HAVE_HWADDR));
    }

    #[test]
    fn set_hwaddr_returns_false_when_no_slaac_relevant_change() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        let hw = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        db.insert(make_lease(addr, hw, None));

        // hwaddr-only change does not report a SLAAC-relevant change,
        // matching upstream's `change` variable (lease.c:944-975).
        let changed = db.set_hwaddr(addr, &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], 1, None, false);
        assert!(!changed);
    }

    #[test]
    fn set_hwaddr_returns_true_when_clid_changes() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        let hw = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        db.insert(make_lease(addr, hw, None));

        let clid = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let changed = db.set_hwaddr(addr, &hw, 1, Some(&clid), false);
        assert!(changed);
    }

    #[test]
    fn set_hwaddr_returns_true_when_forced() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        let hw = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        db.insert(make_lease(addr, hw, None));

        let changed = db.set_hwaddr(addr, &hw, 1, None, true);
        assert!(changed);
    }

    #[test]
    fn set_hwaddr_missing_clid_does_not_clear_existing_one() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        let hw = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        db.insert(make_lease(addr, hw, None));
        let clid = vec![0xDE, 0xAD, 0xBE, 0xEF];
        db.set_hwaddr(addr, &hw, 1, Some(&clid), false);

        // A subsequent packet with no client-id must not wipe the recorded one.
        let changed = db.set_hwaddr(addr, &hw, 1, None, false);
        assert!(!changed);
        assert_eq!(db.find_by_addr(addr).unwrap().clid, Some(clid));
    }

    #[test]
    fn set_hwaddr_nonexistent_no_panic() {
        let mut db = LeaseDb::new();
        db.set_hwaddr(Ipv4Addr::new(10, 0, 0, 99), &[0x01, 0, 0, 0, 0, 0], 1, None, false);
    }

    #[test]
    fn set_hwaddr_changes_hw_type() {
        use crate::types::dhcp::LeaseFlags;
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        let hw = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        db.insert(make_lease(addr, hw, None));

        // Same hw bytes, different type
        db.set_hwaddr(addr, &hw, 6, None, false);
        let lease = db.find_by_addr(addr).unwrap();
        assert_eq!(lease.hwaddr_type, 6);
        assert!(lease.flags.contains(LeaseFlags::CHANGED));
    }

    // ── set_hostname tests ──

    #[test]
    fn set_hostname_basic() {
        use crate::types::dhcp::LeaseFlags;
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        db.insert(make_lease(addr, [0x01, 0, 0, 0, 0, 0], None));

        db.set_hostname(addr, Some("myhost"), false);
        let lease = db.find_by_addr(addr).unwrap();
        assert_eq!(lease.hostname.as_deref(), Some("myhost"));
        assert!(lease.flags.contains(LeaseFlags::CHANGED));
        assert!(db.dns_dirty);
    }

    #[test]
    fn set_hostname_auth_flag() {
        use crate::types::dhcp::LeaseFlags;
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        db.insert(make_lease(addr, [0x01, 0, 0, 0, 0, 0], None));

        db.set_hostname(addr, Some("authhost"), true);
        let lease = db.find_by_addr(addr).unwrap();
        assert!(lease.flags.contains(LeaseFlags::AUTH_NAME));

        // Remove auth
        db.set_hostname(addr, Some("authhost"), false);
        let lease = db.find_by_addr(addr).unwrap();
        assert!(!lease.flags.contains(LeaseFlags::AUTH_NAME));
    }

    #[test]
    fn set_hostname_removes_duplicate_from_other_lease() {
        use crate::types::dhcp::LeaseFlags;
        let mut db = LeaseDb::new();
        let addr1 = Ipv4Addr::new(10, 0, 0, 1);
        let addr2 = Ipv4Addr::new(10, 0, 0, 2);

        let mut lease1 = make_lease(addr1, [0x01, 0, 0, 0, 0, 0], None);
        lease1.hostname = Some("shared-name".into());
        db.insert(lease1);

        let mut lease2 = make_lease(addr2, [0x02, 0, 0, 0, 0, 0], None);
        lease2.hostname = None;
        db.insert(lease2);

        // Set the same hostname on lease2 => should remove from lease1
        db.set_hostname(addr2, Some("shared-name"), false);

        let l1 = db.find_by_addr(addr1).unwrap();
        assert!(l1.hostname.is_none());
        assert_eq!(l1.old_hostname.as_deref(), Some("shared-name"));
        assert!(l1.flags.contains(LeaseFlags::CHANGED));

        let l2 = db.find_by_addr(addr2).unwrap();
        assert_eq!(l2.hostname.as_deref(), Some("shared-name"));
    }

    #[test]
    fn set_hostname_case_insensitive_duplicate() {
        let mut db = LeaseDb::new();
        let addr1 = Ipv4Addr::new(10, 0, 0, 1);
        let addr2 = Ipv4Addr::new(10, 0, 0, 2);

        let mut lease1 = make_lease(addr1, [0x01, 0, 0, 0, 0, 0], None);
        lease1.hostname = Some("MyHost".into());
        db.insert(lease1);

        let mut lease2 = make_lease(addr2, [0x02, 0, 0, 0, 0, 0], None);
        lease2.hostname = None;
        db.insert(lease2);

        db.set_hostname(addr2, Some("myhost"), false);

        let l1 = db.find_by_addr(addr1).unwrap();
        assert!(l1.hostname.is_none(), "duplicate should have been removed");
    }

    #[test]
    fn set_hostname_clear() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        db.insert(make_lease(addr, [0x01, 0, 0, 0, 0, 0], None));

        db.set_hostname(addr, None, false);
        let lease = db.find_by_addr(addr).unwrap();
        assert!(lease.hostname.is_none());
        assert_eq!(lease.old_hostname.as_deref(), Some("host1")); // original was "host1"
    }

    #[test]
    fn set_hostname_same_name_no_change() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        db.insert(make_lease(addr, [0x01, 0, 0, 0, 0, 0], None));
        db.file_dirty = false;
        db.dns_dirty = false;

        // hostname from make_lease is "host1"
        db.set_hostname(addr, Some("host1"), false);
        assert!(!db.file_dirty);
        assert!(!db.dns_dirty);
    }

    // ── set_interface tests ──

    #[test]
    fn set_interface_basic() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        db.insert(make_lease(addr, [0x01, 0, 0, 0, 0, 0], None));

        db.set_interface(addr, 42);
        let lease = db.find_by_addr(addr).unwrap();
        assert_eq!(lease.last_interface, 42);
    }

    #[test]
    fn set_interface_nonexistent_no_panic() {
        let mut db = LeaseDb::new();
        db.set_interface(Ipv4Addr::new(10, 0, 0, 99), 5);
    }

    // ── set_agent_id tests ──

    #[test]
    fn set_agent_id_basic() {
        use crate::types::dhcp::LeaseFlags;
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        db.insert(make_lease(addr, [0x01, 0, 0, 0, 0, 0], None));

        let agent = vec![0x01, 0x02, 0x03];
        db.set_agent_id(addr, Some(&agent));

        let lease = db.find_by_addr(addr).unwrap();
        assert_eq!(lease.agent_id, Some(agent));
        assert!(lease.flags.contains(LeaseFlags::AUX_CHANGED));
        assert!(db.file_dirty);
    }

    #[test]
    fn set_agent_id_clear() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        let mut lease = make_lease(addr, [0x01, 0, 0, 0, 0, 0], None);
        lease.agent_id = Some(vec![0x01, 0x02]);
        db.insert(lease);

        db.set_agent_id(addr, None);
        let lease = db.find_by_addr(addr).unwrap();
        assert!(lease.agent_id.is_none());
    }

    #[test]
    fn set_agent_id_same_value_no_dirty() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        let mut lease = make_lease(addr, [0x01, 0, 0, 0, 0, 0], None);
        lease.agent_id = Some(vec![0x01, 0x02]);
        db.insert(lease);
        db.file_dirty = false;

        db.set_agent_id(addr, Some(&[0x01, 0x02]));
        assert!(!db.file_dirty);
    }

    // ── set_vendorclass tests ──

    #[test]
    fn set_vendorclass_basic() {
        use crate::types::dhcp::LeaseFlags;
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        db.insert(make_lease(addr, [0x01, 0, 0, 0, 0, 0], None));

        let vc = vec![0xAA, 0xBB];
        db.set_vendorclass(addr, Some(&vc));

        let lease = db.find_by_addr(addr).unwrap();
        assert_eq!(lease.vendorclass, Some(vc));
        assert!(lease.flags.contains(LeaseFlags::AUX_CHANGED));
    }

    #[test]
    fn set_vendorclass_clear() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        let mut lease = make_lease(addr, [0x01, 0, 0, 0, 0, 0], None);
        lease.vendorclass = Some(vec![0xCC]);
        db.insert(lease);

        db.set_vendorclass(addr, None);
        let lease = db.find_by_addr(addr).unwrap();
        assert!(lease.vendorclass.is_none());
    }

    #[test]
    fn set_vendorclass_same_value_no_dirty() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        let mut lease = make_lease(addr, [0x01, 0, 0, 0, 0, 0], None);
        lease.vendorclass = Some(vec![0xCC]);
        db.insert(lease);
        db.file_dirty = false;

        db.set_vendorclass(addr, Some(&[0xCC]));
        assert!(!db.file_dirty);
    }

    // ── find_max_addr tests ──

    #[test]
    fn find_max_addr_no_leases_returns_start() {
        let db = LeaseDb::new();
        let start = Ipv4Addr::new(10, 0, 0, 100);
        let end = Ipv4Addr::new(10, 0, 0, 200);
        assert_eq!(db.find_max_addr(start, end), start);
    }

    #[test]
    fn find_max_addr_single_lease() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 150);
        db.insert(make_lease(addr, [0x01, 0, 0, 0, 0, 0], None));

        let result = db.find_max_addr(Ipv4Addr::new(10, 0, 0, 100), Ipv4Addr::new(10, 0, 0, 200));
        assert_eq!(result, addr);
    }

    #[test]
    fn find_max_addr_multiple_leases() {
        let mut db = LeaseDb::new();
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 110), [0x01, 0, 0, 0, 0, 0], None));
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 180), [0x02, 0, 0, 0, 0, 0], None));
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 150), [0x03, 0, 0, 0, 0, 0], None));

        let result = db.find_max_addr(Ipv4Addr::new(10, 0, 0, 100), Ipv4Addr::new(10, 0, 0, 200));
        assert_eq!(result, Ipv4Addr::new(10, 0, 0, 180));
    }

    #[test]
    fn find_max_addr_excludes_out_of_range() {
        let mut db = LeaseDb::new();
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 50), [0x01, 0, 0, 0, 0, 0], None));
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 250), [0x02, 0, 0, 0, 0, 0], None));
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 120), [0x03, 0, 0, 0, 0, 0], None));

        let result = db.find_max_addr(Ipv4Addr::new(10, 0, 0, 100), Ipv4Addr::new(10, 0, 0, 200));
        assert_eq!(result, Ipv4Addr::new(10, 0, 0, 120));
    }

    // ── rerun_scripts tests ──

    #[test]
    fn rerun_scripts_marks_all_changed() {
        use crate::types::dhcp::LeaseFlags;
        let mut db = LeaseDb::new();
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 1), [0x01, 0, 0, 0, 0, 0], None));
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 2), [0x02, 0, 0, 0, 0, 0], None));

        db.rerun_scripts();

        for lease in db.iter() {
            assert!(lease.flags.contains(LeaseFlags::CHANGED));
        }
        assert!(db.file_dirty);
    }

    #[test]
    fn rerun_scripts_empty_db() {
        let mut db = LeaseDb::new();
        db.rerun_scripts(); // Should not panic
        assert!(db.file_dirty);
    }

    // ── run_lease_scripts tests ──

    #[cfg(unix)]
    fn write_marker_script(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt;

        let marker = dir.join("marker.log");
        let script_path = dir.join("hook.sh");
        // Positional args only ($1=action, $2=mac, $3=addr, $4=hostname if
        // present) — upstream never sets DNSMASQ_ACTION/DNSMASQ_IP as env
        // vars (helper.c:587-667 has no such names), and DNSMASQ_SUPPLIED_HOSTNAME
        // is a distinct thing sourced from the DHCP request's extradata, not
        // from this event's hostname field. $2 (mac) is skipped so existing
        // "{action} {addr} {hostname}"-shaped assertions stay readable.
        std::fs::write(
            &script_path,
            format!("#!/bin/sh\necho \"$1 $3 $4\" >> {}\n", marker.to_str().unwrap()),
        )
        .unwrap();
        let mut perms = std::fs::metadata(&script_path).unwrap().permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(&script_path, perms).unwrap();
        (script_path, marker)
    }

    /// Runs `attempt` (which builds a fresh [`LeaseDb`], mutates it, and
    /// calls [`LeaseDb::run_lease_scripts`]) until the marker script has
    /// actually written to `marker`, retrying a few times.
    ///
    /// Under `cargo test`'s default full parallelism this repo's test suite
    /// runs many test binaries at once, each spawning its own threads; the
    /// subprocess `fork`/`exec` behind `run_script` has been observed to
    /// fail transiently under that contention even though the same test is
    /// 100% reliable with `--test-threads=1`. A failed spawn still clears
    /// the lease's pending-script flags (matching upstream's `do_script_run`,
    /// which also doesn't retry), so a retry must redo the whole setup, not
    /// just re-read the marker.
    #[cfg(unix)]
    fn run_scripts_until_marker_written(
        marker: &std::path::Path,
        mut attempt: impl FnMut() -> LeaseDb,
    ) -> (String, LeaseDb) {
        for _ in 0..5 {
            let _ = std::fs::remove_file(marker);
            let db = attempt();
            if let Ok(contents) = std::fs::read_to_string(marker) {
                if !contents.is_empty() {
                    return (contents, db);
                }
            }
        }
        panic!("dhcp-script hook never fired after retries (possible resource contention)");
    }

    #[cfg(unix)]
    #[test]
    fn run_lease_scripts_fires_add_for_new_lease() {
        let dir = tempfile::tempdir().unwrap();
        let (script_path, marker) = write_marker_script(dir.path());
        let addr = Ipv4Addr::new(10, 0, 0, 5);

        let (contents, _db) = run_scripts_until_marker_written(&marker, || {
            let mut db = LeaseDb::new();
            db.allocate_v4(addr);
            db.run_lease_scripts(Some(script_path.to_str().unwrap()), false, false);
            db
        });

        let first_line = contents.lines().next().unwrap();
        // No hostname is set, so the supplied-hostname field is empty.
        assert_eq!(first_line, format!("add {addr} "));
    }

    #[cfg(unix)]
    #[test]
    fn run_lease_scripts_clears_new_and_changed_flags() {
        use crate::types::dhcp::LeaseFlags;
        let dir = tempfile::tempdir().unwrap();
        let (script_path, marker) = write_marker_script(dir.path());
        let addr = Ipv4Addr::new(10, 0, 0, 5);

        let (_contents, db) = run_scripts_until_marker_written(&marker, || {
            let mut db = LeaseDb::new();
            db.allocate_v4(addr);
            db.run_lease_scripts(Some(script_path.to_str().unwrap()), false, false);
            db
        });

        let lease = db.find_by_addr(addr).unwrap();
        assert!(!lease.flags.intersects(LeaseFlags::NEW | LeaseFlags::CHANGED));
    }

    #[cfg(unix)]
    #[test]
    fn run_lease_scripts_fires_old_for_changed_lease() {
        let dir = tempfile::tempdir().unwrap();
        let (script_path, marker) = write_marker_script(dir.path());
        let addr = Ipv4Addr::new(10, 0, 0, 5);

        let (contents, _db) = run_scripts_until_marker_written(&marker, || {
            let mut db = LeaseDb::new();
            db.insert(make_lease(addr, [0x01, 0, 0, 0, 0, 0], None)); // hostname "host1"
            db.set_hostname(addr, Some("renamed"), false); // LEASE_CHANGED + old_hostname="host1"
            db.run_lease_scripts(Some(script_path.to_str().unwrap()), false, false);
            db
        });

        let lines: Vec<&str> = contents.lines().collect();
        // Renaming a lease first announces the loss of the old name (an
        // `old`-hostname event reporting "host1"), then the `old` change
        // event itself carries the new name ("renamed") — matching
        // lease.c:1274-1305's two-pass "announce loss before gain" order.
        assert_eq!(lines, vec![format!("old {addr} host1"), format!("old {addr} renamed")]);
    }

    #[cfg(unix)]
    #[test]
    fn run_lease_scripts_fires_del_for_removed_lease() {
        let dir = tempfile::tempdir().unwrap();
        let (script_path, marker) = write_marker_script(dir.path());
        let addr = Ipv4Addr::new(10, 0, 0, 9);

        let (contents, _db) = run_scripts_until_marker_written(&marker, || {
            let mut db = LeaseDb::new();
            db.insert(make_lease(addr, [0x01, 0, 0, 0, 0, 0], None));
            db.remove_by_addr(addr);
            db.run_lease_scripts(Some(script_path.to_str().unwrap()), false, false);
            db
        });

        let first_line = contents.lines().next().unwrap();
        // Upstream's DEL call site always passes NULL for hostname
        // (lease.c:1255) — a deleted lease must not report its hostname on
        // the del event, unlike add/old.
        assert_eq!(first_line, format!("del {addr} "));
    }

    #[cfg(unix)]
    #[test]
    fn run_lease_scripts_announces_lost_hostname_before_del() {
        let dir = tempfile::tempdir().unwrap();
        let (script_path, marker) = write_marker_script(dir.path());
        let addr = Ipv4Addr::new(10, 0, 0, 9);

        let (contents, _db) = run_scripts_until_marker_written(&marker, || {
            let mut db = LeaseDb::new();
            db.insert(make_lease(addr, [0x01, 0, 0, 0, 0, 0], None)); // hostname "host1"
            db.set_hostname(addr, None, false); // clears hostname, sets old_hostname = "host1"
            db.remove_by_addr(addr);
            db.run_lease_scripts(Some(script_path.to_str().unwrap()), false, false);
            db
        });

        let lines: Vec<&str> = contents.lines().collect();
        // The lost name ("host1") is announced via the supplied-hostname
        // field of an `old` event before the `del` event fires (with no
        // hostname left to report), matching lease.c:1274-1283's ordering.
        assert_eq!(lines, vec![format!("old {addr} host1"), format!("del {addr} ")]);
    }

    #[cfg(unix)]
    #[test]
    fn run_lease_scripts_drains_old_leases_queue() {
        let dir = tempfile::tempdir().unwrap();
        let (script_path, marker) = write_marker_script(dir.path());
        let addr = Ipv4Addr::new(10, 0, 0, 9);

        let (contents_before, mut db) = run_scripts_until_marker_written(&marker, || {
            let mut db = LeaseDb::new();
            db.insert(make_lease(addr, [0x01, 0, 0, 0, 0, 0], None));
            db.remove_by_addr(addr);
            db.run_lease_scripts(Some(script_path.to_str().unwrap()), false, false);
            db
        });

        // A second call should be a no-op: the old_leases queue was drained
        // and no lease is left with pending flags, so nothing is spawned.
        db.run_lease_scripts(Some(script_path.to_str().unwrap()), false, false);
        let contents_after = std::fs::read_to_string(&marker).unwrap();
        assert_eq!(contents_before, contents_after);
    }

    /// Upstream calls `do_script_run()` unconditionally from the main loop
    /// (dnsmasq.c: even the `#else` branch without `HAVE_SCRIPT` calls it,
    /// "need this for other side-effects") because draining `old_leases` and
    /// clearing per-lease flags happens regardless of whether a script is
    /// configured; only the `queue_script()` spawn itself is conditional.
    /// With no `dhcp-script` set, `old_leases` must still drain here or it
    /// grows without bound for the life of the process.
    #[test]
    fn run_lease_scripts_drains_old_leases_without_command_configured() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 9);
        db.insert(make_lease(addr, [0x01, 0, 0, 0, 0, 0], None));
        db.remove_by_addr(addr);
        assert_eq!(db.old_leases.len(), 1);

        db.run_lease_scripts(None, false, false);

        assert!(
            db.old_leases.is_empty(),
            "old_leases must drain even when no dhcp-script command is configured"
        );
    }

    #[test]
    fn run_lease_scripts_clears_lease_flags_without_command_configured() {
        use crate::types::dhcp::LeaseFlags;
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 5);
        db.allocate_v4(addr);

        db.run_lease_scripts(None, false, false);

        let lease = db.find_by_addr(addr).unwrap();
        assert!(!lease.flags.intersects(LeaseFlags::NEW | LeaseFlags::CHANGED));
    }

    /// Upstream's trigger condition (lease.c:1286-1288) fires on a pure
    /// aux/expiry renewal too when `--leasefile-ro`/`--script-on-renewal`
    /// are set, not just add/old/del. Without this, both the notification
    /// and the flag-clearing it gates never happen for a lease that only
    /// ever renews.
    #[cfg(unix)]
    #[test]
    fn run_lease_scripts_fires_on_pure_renewal_only_when_enabled() {
        use crate::types::dhcp::LeaseFlags;

        let dir = tempfile::tempdir().unwrap();
        let (script_path, marker) = write_marker_script(dir.path());
        let addr = Ipv4Addr::new(10, 0, 0, 5);
        let command = script_path.to_str().unwrap();

        let mut db = LeaseDb::new();
        db.insert(make_lease(addr, [0x01, 0, 0, 0, 0, 0], None));
        // Clear LEASE_NEW/CHANGED first so only the renewal path is exercised.
        db.run_lease_scripts(Some(command), false, false);
        let _ = std::fs::remove_file(&marker);

        // A pure renewal (LEASE_AUX_CHANGED | LEASE_EXP_CHANGED only) with
        // both options off must not fire the script, and must not clear the
        // renewal flags either — upstream gates the clear inside the same
        // `if` as the fire.
        db.set_expires(addr, 3600);
        {
            let lease = db.find_by_addr(addr).unwrap();
            assert!(lease.flags.intersects(LeaseFlags::AUX_CHANGED | LeaseFlags::EXP_CHANGED));
        }
        db.run_lease_scripts(Some(command), false, false);
        assert!(
            std::fs::read_to_string(&marker).unwrap_or_default().is_empty(),
            "a pure renewal must not fire the script when leasefile-ro/script-on-renewal are both off"
        );
        {
            let lease = db.find_by_addr(addr).unwrap();
            assert!(
                lease.flags.intersects(LeaseFlags::AUX_CHANGED | LeaseFlags::EXP_CHANGED),
                "renewal flags must stay set until a run that's actually allowed to fire clears them"
            );
        }

        // The same renewal, with leasefile_ro on this time, must fire and
        // clear the flags. `run_script_child` runs the script synchronously,
        // so its write is complete by the time this call returns.
        db.run_lease_scripts(Some(command), true, false);
        let contents = std::fs::read_to_string(&marker).unwrap();
        let first_line = contents.lines().next().unwrap();
        assert_eq!(first_line, format!("old {addr} host1"));
        let lease = db.find_by_addr(addr).unwrap();
        assert!(!lease.flags.intersects(LeaseFlags::AUX_CHANGED | LeaseFlags::EXP_CHANGED));
    }

    // ── write_to_file / load_from_file tests ──

    #[test]
    fn write_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("leases.dat");
        let path_str = path.to_str().unwrap();

        let mut db = LeaseDb::new();
        let addr1 = Ipv4Addr::new(10, 0, 0, 1);
        let addr2 = Ipv4Addr::new(10, 0, 0, 2);
        db.insert(make_lease(addr1, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06], Some(1_700_000_000)));
        db.insert(make_lease(addr2, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66], None));

        db.write_to_file(path_str).unwrap();
        let loaded = LeaseDb::load_from_file(path_str).unwrap();

        assert!(loaded.find_by_addr(addr1).is_some());
        assert!(loaded.find_by_addr(addr2).is_some());
        assert_eq!(loaded.count(), 2);
    }

    #[test]
    fn load_from_file_nonexistent() {
        let result = LeaseDb::load_from_file("/tmp/nonexistent_lease_file_dnsmasq_test.dat");
        assert!(result.is_err());
    }

    #[test]
    fn write_to_file_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("new_leases.dat");
        let path_str = path.to_str().unwrap();

        let db = LeaseDb::new();
        db.write_to_file(path_str).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn write_to_file_uses_tmp_file_and_rename() {
        // The atomic-write implementation must never write straight to the
        // target path; a crash between opening and finishing the write
        // should leave `path` absent (create) or unchanged (overwrite),
        // never truncated. We can't literally kill the process mid-write in
        // a unit test, so instead we assert the file only appears at the
        // very end (rename), which is the property that makes a real crash
        // safe: whichever file is durable at the crash point is complete.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("leases.dat");
        let path_str = path.to_str().unwrap();

        let mut db = LeaseDb::new();
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 1), [1, 0, 0, 0, 0, 0], None));
        db.write_to_file(path_str).unwrap();

        // No stray temp file should remain after a successful write.
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(entries, vec!["leases.dat".to_string()]);
    }

    #[cfg(unix)]
    #[test]
    fn write_to_file_failed_write_leaves_original_untouched() {
        // Skip under root: permission bits don't block root's writes, so the
        // injected failure below wouldn't actually occur and the assertion
        // that follows would be spuriously wrong, not confirming anything.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }

        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("leases.dat");
        let path_str = path.to_str().unwrap();

        let mut original_db = LeaseDb::new();
        original_db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 1), [1, 0, 0, 0, 0, 0], Some(1_700_000_000)));
        original_db.write_to_file(path_str).unwrap();
        let original_contents = std::fs::read_to_string(&path).unwrap();

        // Make the directory read-only so creating the temp file fails,
        // simulating a write that dies before the atomic rename.
        let mut perms = std::fs::metadata(dir.path()).unwrap().permissions();
        perms.set_mode(0o500);
        std::fs::set_permissions(dir.path(), perms).unwrap();

        let mut new_db = LeaseDb::new();
        new_db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 2), [2, 0, 0, 0, 0, 0], None));
        let result = new_db.write_to_file(path_str);

        // Restore permissions so the tempdir can be cleaned up.
        let mut restore = std::fs::metadata(dir.path()).unwrap().permissions();
        restore.set_mode(0o700);
        std::fs::set_permissions(dir.path(), restore).unwrap();

        assert!(result.is_err(), "write should fail when the directory is read-only");
        let after = std::fs::read_to_string(&path).unwrap();
        assert_eq!(after, original_contents, "a failed write must not corrupt the existing lease file");
    }

    // ── remove_by_addr tests ──

    #[test]
    fn remove_by_addr_removes_matching_lease() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 5);
        db.insert(make_lease(addr, [0x01, 0, 0, 0, 0, 0], None));
        db.file_dirty = false;

        let removed = db.remove_by_addr(addr);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().addr, addr);
        assert!(db.find_by_addr(addr).is_none());
        assert!(db.file_dirty);
    }

    #[test]
    fn remove_by_addr_nonexistent_returns_none() {
        let mut db = LeaseDb::new();
        assert!(db.remove_by_addr(Ipv4Addr::new(10, 0, 0, 99)).is_none());
    }

    #[test]
    fn remove_by_addr_leaves_other_leases_intact() {
        let mut db = LeaseDb::new();
        let addr1 = Ipv4Addr::new(10, 0, 0, 1);
        let addr2 = Ipv4Addr::new(10, 0, 0, 2);
        db.insert(make_lease(addr1, [0x01, 0, 0, 0, 0, 0], None));
        db.insert(make_lease(addr2, [0x02, 0, 0, 0, 0, 0], None));

        db.remove_by_addr(addr1);
        assert!(db.find_by_addr(addr1).is_none());
        assert!(db.find_by_addr(addr2).is_some());
    }

    // ── count tests ──

    #[test]
    fn count_empty() {
        let db = LeaseDb::new();
        assert_eq!(db.count(), 0);
    }

    #[test]
    fn count_after_inserts() {
        let mut db = LeaseDb::new();
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 1), [0x01, 0, 0, 0, 0, 0], None));
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 2), [0x02, 0, 0, 0, 0, 0], None));
        assert_eq!(db.count(), 2);
    }

    #[test]
    fn count_after_prune() {
        let mut db = LeaseDb::new();
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 1), [0x01, 0, 0, 0, 0, 0], Some(100)));
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 2), [0x02, 0, 0, 0, 0, 0], Some(9_999_999_999)));
        db.prune(200);
        assert_eq!(db.count(), 1);
    }

    // ── iter tests ──

    #[test]
    fn iter_empty() {
        let db = LeaseDb::new();
        assert_eq!(db.iter().count(), 0);
    }

    #[test]
    fn iter_returns_all_leases() {
        let mut db = LeaseDb::new();
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 1), [0x01, 0, 0, 0, 0, 0], None));
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 2), [0x02, 0, 0, 0, 0, 0], None));
        db.insert(make_lease(Ipv4Addr::new(10, 0, 0, 3), [0x03, 0, 0, 0, 0, 0], None));

        let addrs: Vec<Ipv4Addr> = db.iter().map(|l| l.addr).collect();
        assert_eq!(addrs.len(), 3);
        assert!(addrs.contains(&Ipv4Addr::new(10, 0, 0, 1)));
        assert!(addrs.contains(&Ipv4Addr::new(10, 0, 0, 2)));
        assert!(addrs.contains(&Ipv4Addr::new(10, 0, 0, 3)));
    }

    // ── default tests ──

    #[test]
    fn default_max_leases() {
        let db = LeaseDb::new();
        assert_eq!(db.max_leases, 1000);
        assert!(!db.file_dirty);
        assert!(!db.dns_dirty);
    }

    #[test]
    fn default_trait() {
        let db = LeaseDb::default();
        assert_eq!(db.count(), 0);
        assert_eq!(db.max_leases, 1000);
    }

    // ── combined / integration-style tests ──

    #[test]
    fn allocate_then_configure_lease() {
        use crate::types::dhcp::LeaseFlags;
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(192, 168, 1, 100);

        db.allocate_v4(addr);
        db.set_hwaddr(addr, &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF], 1, None, false);
        db.set_hostname(addr, Some("workstation"), true);
        db.set_expires(addr, 86400);
        db.set_interface(addr, 3);
        db.set_agent_id(addr, Some(&[0x01, 0x06, 0x00, 0x04]));
        db.set_vendorclass(addr, Some(b"MSFT 5.0"));

        let lease = db.find_by_addr(addr).unwrap();
        assert_eq!(lease.hostname.as_deref(), Some("workstation"));
        assert_eq!(&lease.hwaddr[..6], &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert!(lease.expires.is_some());
        assert_eq!(lease.last_interface, 3);
        assert!(lease.agent_id.is_some());
        assert_eq!(lease.vendorclass.as_deref(), Some(b"MSFT 5.0".as_ref()));
        assert!(lease.flags.contains(LeaseFlags::NEW));
    }

    #[test]
    fn allocate_write_load_verify() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("full_test.dat");
        let path_str = path.to_str().unwrap();

        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(192, 168, 1, 50);
        db.allocate_v4(addr);
        db.set_hwaddr(addr, &[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01], 1, None, false);
        db.set_hostname(addr, Some("testbox"), false);

        db.write_to_file(path_str).unwrap();
        let loaded = LeaseDb::load_from_file(path_str).unwrap();

        let lease = loaded.find_by_addr(addr).unwrap();
        assert_eq!(lease.hostname.as_deref(), Some("testbox"));
        assert_eq!(&lease.hwaddr[..6], &[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
    }

    // ── calc_fqdns ───────────────────────────────────────────────────────────

    #[test]
    fn calc_fqdns_sets_fqdn() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        db.allocate_v4(addr);
        db.set_hostname(addr, Some("myhost"), true);
        db.calc_fqdns("example.com");
        let lease = db.find_by_addr(addr).unwrap();
        assert_eq!(lease.fqdn.as_deref(), Some("myhost.example.com"));
    }

    #[test]
    fn calc_fqdns_no_hostname_no_fqdn() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 2);
        db.allocate_v4(addr);
        db.calc_fqdns("example.com");
        let lease = db.find_by_addr(addr).unwrap();
        assert!(lease.fqdn.is_none());
    }

    #[test]
    fn calc_fqdns_empty_domain_no_fqdn() {
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 3);
        db.allocate_v4(addr);
        db.set_hostname(addr, Some("host"), true);
        db.calc_fqdns("");
        let lease = db.find_by_addr(addr).unwrap();
        assert!(lease.fqdn.is_none());
    }

    // ── DHCPv6 lease functions ───────────────────────────────────────────────

    #[cfg(feature = "dhcp6")]
    #[test]
    fn allocate_v6_basic() {
        use crate::types::dhcp::LeaseFlags;
        let mut db = LeaseDb::new();
        let addr: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let lease = db.allocate_v6(addr, LeaseFlags::NA);
        assert!(lease.is_some());
        assert_eq!(db.count(), 1);
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn find_v6_by_addr_found() {
        use crate::types::dhcp::LeaseFlags;
        let mut db = LeaseDb::new();
        let addr: std::net::Ipv6Addr = "2001:db8::42".parse().unwrap();
        db.allocate_v6(addr, LeaseFlags::NA);
        assert!(db.find_v6_by_addr(&addr).is_some());
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn find_v6_by_addr_not_found() {
        let db = LeaseDb::new();
        let addr: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(db.find_v6_by_addr(&addr).is_none());
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn find_v6_by_clid_iaid() {
        use crate::types::dhcp::LeaseFlags;
        let mut db = LeaseDb::new();
        let addr: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let clid = vec![0x00, 0x01, 0xAA, 0xBB];
        {
            let lease = db.allocate_v6(addr, LeaseFlags::NA).unwrap();
            lease.clid = Some(clid.clone());
            lease.iaid = 42;
        }
        assert!(db.find_v6_by_clid_iaid(&clid, 42, &addr).is_some());
        assert!(db.find_v6_by_clid_iaid(&clid, 99, &addr).is_none()); // wrong iaid
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn reset_v6_used_clears_flag() {
        use crate::types::dhcp::LeaseFlags;
        let mut db = LeaseDb::new();
        let addr: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        {
            let lease = db.allocate_v6(addr, LeaseFlags::NA).unwrap();
            lease.flags.insert(LeaseFlags::USED);
        }
        db.reset_v6_used();
        let lease = db.find_v6_by_addr(&addr).unwrap();
        assert!(!lease.flags.contains(LeaseFlags::USED));
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn allocate_v6_respects_max() {
        use crate::types::dhcp::LeaseFlags;
        let mut db = LeaseDb::new();
        db.max_leases = 1;
        let a1: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let a2: std::net::Ipv6Addr = "2001:db8::2".parse().unwrap();
        assert!(db.allocate_v6(a1, LeaseFlags::NA).is_some());
        assert!(db.allocate_v6(a2, LeaseFlags::NA).is_none());
    }

    // ── bind_v6 ──────────────────────────────────────────────────────────────

    #[cfg(feature = "dhcp6")]
    #[test]
    fn bind_v6_creates_new_lease_with_clid_and_iaid() {
        use crate::types::dhcp::LeaseFlags;
        let mut db = LeaseDb::new();
        let addr: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let clid = vec![0xAA, 0xBB];
        let lease = db.bind_v6(addr, &clid, 7, LeaseFlags::NA, None).unwrap();
        assert_eq!(lease.addr6, addr);
        assert_eq!(lease.clid, Some(clid.clone()));
        assert_eq!(lease.iaid, 7);
        // Findable by clid/iaid afterwards.
        assert!(db.find_v6_by_clid_iaid(&clid, 7, &addr).is_some());
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn bind_v6_does_not_clobber_other_clients() {
        // Regression: binding a second client's address used to collide on the
        // same all-zero lookup key as the first (both keyed off an empty
        // clid/hwaddr at insert time), silently evicting the first lease.
        use crate::types::dhcp::LeaseFlags;
        let mut db = LeaseDb::new();
        let a1: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let a2: std::net::Ipv6Addr = "2001:db8::2".parse().unwrap();
        let c1 = vec![0x01];
        let c2 = vec![0x02];
        db.bind_v6(a1, &c1, 1, LeaseFlags::NA, None);
        db.bind_v6(a2, &c2, 2, LeaseFlags::NA, None);
        assert!(db.find_v6_by_clid_iaid(&c1, 1, &a1).is_some());
        assert!(db.find_v6_by_clid_iaid(&c2, 2, &a2).is_some());
        assert_eq!(db.count(), 2);
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn bind_v6_updates_existing_lease_in_place() {
        use crate::types::dhcp::LeaseFlags;
        use std::time::{Duration, SystemTime};
        let mut db = LeaseDb::new();
        let addr: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let clid = vec![0xAA];
        db.bind_v6(addr, &clid, 1, LeaseFlags::NA, None);
        let later = SystemTime::UNIX_EPOCH + Duration::from_secs(1000);
        db.bind_v6(addr, &clid, 1, LeaseFlags::NA, Some(later));
        assert_eq!(db.count(), 1);
        let lease = db.find_v6_by_addr(&addr).unwrap();
        assert_eq!(lease.expires, Some(later));
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn bind_v6_respects_max_leases_for_new_addr() {
        use crate::types::dhcp::LeaseFlags;
        let mut db = LeaseDb::new();
        db.max_leases = 1;
        let a1: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let a2: std::net::Ipv6Addr = "2001:db8::2".parse().unwrap();
        assert!(db.bind_v6(a1, &[0x01], 1, LeaseFlags::NA, None).is_some());
        assert!(db.bind_v6(a2, &[0x02], 2, LeaseFlags::NA, None).is_none());
    }

    // ── remove_v6_by_clid_iaid_addr ─────────────────────────────────────────

    #[cfg(feature = "dhcp6")]
    #[test]
    fn remove_v6_by_clid_iaid_addr_removes_match() {
        use crate::types::dhcp::LeaseFlags;
        let mut db = LeaseDb::new();
        let addr: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        let clid = vec![0xAA];
        db.bind_v6(addr, &clid, 1, LeaseFlags::NA, None);
        assert!(db.remove_v6_by_clid_iaid_addr(&clid, 1, &addr));
        assert!(db.find_v6_by_addr(&addr).is_none());
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn remove_v6_by_clid_iaid_addr_no_match_returns_false() {
        let mut db = LeaseDb::new();
        let addr: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(!db.remove_v6_by_clid_iaid_addr(&[0xAA], 1, &addr));
    }

    // ── find_v6_by_client_iaid ───────────────────────────────────────────────

    #[cfg(feature = "dhcp6")]
    #[test]
    fn find_v6_by_client_iaid_finds_regardless_of_address() {
        use crate::types::dhcp::LeaseFlags;
        let mut db = LeaseDb::new();
        let addr: std::net::Ipv6Addr = "2001:db8::99".parse().unwrap();
        let clid = vec![0xAA];
        db.bind_v6(addr, &clid, 5, LeaseFlags::NA, None);
        let found = db.find_v6_by_client_iaid(&clid, 5).unwrap();
        assert_eq!(found.addr6, addr);
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn find_v6_by_client_iaid_wrong_iaid_not_found() {
        use crate::types::dhcp::LeaseFlags;
        let mut db = LeaseDb::new();
        let addr: std::net::Ipv6Addr = "2001:db8::99".parse().unwrap();
        let clid = vec![0xAA];
        db.bind_v6(addr, &clid, 5, LeaseFlags::NA, None);
        assert!(db.find_v6_by_client_iaid(&clid, 6).is_none());
    }

    // ── SLAAC integration (refresh_slaac / tick_slaac / confirm_slaac_ping) ──

    #[cfg(feature = "dhcp6")]
    fn make_ra_ctx(start6: std::net::Ipv6Addr, if_index: i32) -> crate::types::dhcp::DhcpContext {
        use crate::types::dhcp::{ContextFlags, DhcpNetid};
        crate::types::dhcp::DhcpContext {
            start: Ipv4Addr::UNSPECIFIED,
            end: Ipv4Addr::UNSPECIFIED,
            router: Ipv4Addr::UNSPECIFIED,
            flags: ContextFlags::RA_NAME,
            netmask: Ipv4Addr::UNSPECIFIED,
            broadcast: Ipv4Addr::UNSPECIFIED,
            local: Ipv4Addr::UNSPECIFIED,
            lease_time: 0,
            addr_epoch: 0,
            netid: DhcpNetid { net: String::new() },
            filter: vec![],
            start6,
            end6: std::net::Ipv6Addr::UNSPECIFIED,
            local6: std::net::Ipv6Addr::UNSPECIFIED,
            prefix: 64,
            if_index,
            valid: 0,
            preferred: 0,
            ra_time: 0,
            ra_short_period_start: 0,
            saved_valid: 0,
            address_lost_time: 0,
        }
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn refresh_slaac_populates_matching_lease_and_marks_no_dirty_on_first_add() {
        use crate::types::dhcp::LeaseFlags;
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        db.insert(make_lease(addr, [0x00, 0x60, 0x97, 0x00, 0x28, 0x4C], None));
        {
            let lease = db.leases.values_mut().next().unwrap();
            lease.flags.insert(LeaseFlags::HAVE_HWADDR);
            lease.hostname = Some("host".to_string());
            lease.last_interface = 1;
        }

        let ctx = make_ra_ctx("2001:db8::".parse().unwrap(), 1);
        db.dns_dirty = false;
        db.refresh_slaac(SystemTime::now(), &[ctx], false, |_| {});

        let lease = db.find_by_addr(addr).unwrap();
        assert_eq!(lease.slaac_address.len(), 1);
        // Matches slaac_add_addrs's own semantics: no dirty flag on first population.
        assert!(!db.dns_dirty);
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn refresh_slaac_force_marks_dns_dirty() {
        use crate::types::dhcp::LeaseFlags;
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        db.insert(make_lease(addr, [0x00, 0x60, 0x97, 0x00, 0x28, 0x4C], None));
        {
            let lease = db.leases.values_mut().next().unwrap();
            lease.flags.insert(LeaseFlags::HAVE_HWADDR);
            lease.hostname = Some("host".to_string());
            lease.last_interface = 1;
        }

        let ctx = make_ra_ctx("2001:db8::".parse().unwrap(), 1);
        db.refresh_slaac(SystemTime::now(), &[ctx.clone()], false, |_| {});
        db.dns_dirty = false;
        db.refresh_slaac(SystemTime::now(), &[ctx], true, |_| {});
        assert!(db.dns_dirty);
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn tick_slaac_sends_due_probe_and_confirm_ping_clears_it() {
        use crate::types::dhcp::LeaseFlags;
        let mut db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 1);
        db.insert(make_lease(addr, [0x00, 0x60, 0x97, 0x00, 0x28, 0x4C], None));
        let now = SystemTime::now();
        {
            let lease = db.leases.values_mut().next().unwrap();
            lease.flags.insert(LeaseFlags::HAVE_HWADDR);
            lease.hostname = Some("host".to_string());
            lease.last_interface = 1;
        }

        let ctx = make_ra_ctx("2001:db8::".parse().unwrap(), 1);
        db.refresh_slaac(now, &[ctx.clone()], false, |_| {});
        let slaac_addr = db.find_by_addr(addr).unwrap().slaac_address[0].addr;

        let mut sent = Vec::new();
        let next = db.tick_slaac(now, &[ctx], 42, |a, pkt| {
            sent.push((a, pkt.to_vec()));
            Ok(())
        });
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, slaac_addr);
        assert!(next.is_some());

        let packet = crate::slaac::build_ping_packet(42, 1);
        db.dns_dirty = false;
        db.confirm_slaac_ping(slaac_addr, &packet, 42, "eth0", true);
        assert!(db.dns_dirty);
        assert_eq!(db.find_by_addr(addr).unwrap().slaac_address[0].backoff, 0);
    }
}
