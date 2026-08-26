/// Global constants and option bit definitions.
/// Ported from `dnsmasq.h`.

// ── Compiled-in defaults (config.h) ───────────────────────────────────────────
/// User the daemon changes to after startup unless `user=` says otherwise
/// (`CHUSER`, config.h:53).
pub const CHUSER: &str = "nobody";
/// Group the daemon prefers when `group=` is not given (`CHGRP`, config.h:54).
/// If it does not exist, upstream falls back to the run user's primary group.
pub const CHGRP: &str = "dip";
/// Pid file written when `pid-file=` is not given (`RUNFILE`, config.h:243).
/// An explicit empty `pid-file=` suppresses the file entirely.
pub const RUNFILE: &str = "/var/run/dnsmasq.pid";

// ── Exit codes ────────────────────────────────────────────────────────────────
pub const EC_GOOD:        i32 = 0;
pub const EC_BADCONF:     i32 = 1;
pub const EC_BADNET:      i32 = 2;
pub const EC_FILE:        i32 = 3;
pub const EC_NOMEM:       i32 = 4;
pub const EC_MISC:        i32 = 5;
pub const EC_INIT_OFFSET: i32 = 10;

// ── Async event codes ─────────────────────────────────────────────────────────
pub const EVENT_RELOAD:     u32 = 1;
pub const EVENT_DUMP:       u32 = 2;
pub const EVENT_ALARM:      u32 = 3;
pub const EVENT_TERM:       u32 = 4;
pub const EVENT_CHILD:      u32 = 5;
pub const EVENT_REOPEN:     u32 = 6;
pub const EVENT_EXITED:     u32 = 7;
pub const EVENT_KILLED:     u32 = 8;
pub const EVENT_EXEC_ERR:   u32 = 9;
pub const EVENT_PIPE_ERR:   u32 = 10;
pub const EVENT_USER_ERR:   u32 = 11;
pub const EVENT_CAP_ERR:    u32 = 12;
pub const EVENT_PIDFILE:    u32 = 13;
pub const EVENT_HUSER_ERR:  u32 = 14;
pub const EVENT_GROUP_ERR:  u32 = 15;
pub const EVENT_DIE:        u32 = 16;
pub const EVENT_LOG_ERR:    u32 = 17;
pub const EVENT_FORK_ERR:   u32 = 18;
pub const EVENT_LUA_ERR:    u32 = 19;
pub const EVENT_TFTP_ERR:   u32 = 20;
pub const EVENT_INIT:       u32 = 21;
pub const EVENT_NEWADDR:    u32 = 22;
pub const EVENT_NEWROUTE:   u32 = 23;
pub const EVENT_TIME_ERR:   u32 = 24;
pub const EVENT_SCRIPT_LOG: u32 = 25;
pub const EVENT_TIME:       u32 = 26;

// ── OPT_* option bit indices ──────────────────────────────────────────────────
/// One bit in `Daemon::options` — a checked replacement for the raw `usize`
/// index this port used before, so an out-of-range/mistyped option can no
/// longer compile as a valid argument to `option_bool`/`set_option`/
/// `clear_option`. Each named `OPT_*` constant below is this enum's
/// corresponding variant, kept so every existing call site
/// (`daemon.option_bool(OPT_RA)`, etc.) needs no change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum DaemonOption {
    Boguspriv = 0,
    Filter = 1,
    Log = 2,
    Selfmx = 3,
    NoHosts = 4,
    NoPoll = 5,
    Debug = 6,
    Order = 7,
    NoResolv = 8,
    Expand = 9,
    Localmx = 10,
    NoNeg = 11,
    NodotsLocal = 12,
    Nowild = 13,
    Ethers = 14,
    ResolvDomain = 15,
    NoFork = 16,
    Authoritative = 17,
    Localise = 18,
    Dbus = 19,
    DhcpFqdn = 20,
    NoPing = 21,
    LeaseRo = 22,
    AllServers = 23,
    Reload = 24,
    LocalRebind = 25,
    TftpSecure = 26,
    TftpNoblock = 27,
    LogOpts = 28,
    TftpAprefIp = 29,
    NoOverride = 30,
    NoRebind = 31,
    AddMac = 32,
    DnssecProxy = 33,
    ConsecAddr = 34,
    Conntrack = 35,
    FqdnUpdate = 36,
    Ra = 37,
    TftpLc = 38,
    Cleverbind = 39,
    Tftp = 40,
    ClientSubnet = 41,
    QuietDhcp = 42,
    QuietDhcp6 = 43,
    QuietRa = 44,
    DnssecValid = 45,
    DnssecTime = 46,
    DnssecDebug = 47,
    DnssecIgnNs = 48,
    LocalService = 49,
    LoopDetect = 50,
    Extralog = 51,
    TftpNoFail = 52,
    ScriptArp = 53,
    MacB64 = 54,
    MacHex = 55,
    TftpAprefMac = 56,
    RapidCommit = 57,
    Ubus = 58,
    IgnoreClid = 59,
    SinglePort = 60,
    LeaseRenew = 61,
    LogDebug = 62,
    Umbrella = 63,
    UmbrellaDevid = 64,
    CmarkAlstEn = 65,
    QuietTftp = 66,
    StripEcs = 67,
    StripMac = 68,
    Norr = 69,
    NoIdent = 70,
    CacheRr = 71,
    LocalhostService = 72,
    LogProto = 73,
    No0x20 = 74,
    Do0x20 = 75,
    AuthLog = 76,
    Leasequery = 77,
    LogOnlyFailed = 78,
    LogMalloc = 79,
}

pub const OPT_BOGUSPRIV: DaemonOption = DaemonOption::Boguspriv;
pub const OPT_FILTER: DaemonOption = DaemonOption::Filter;
pub const OPT_LOG: DaemonOption = DaemonOption::Log;
pub const OPT_SELFMX: DaemonOption = DaemonOption::Selfmx;
pub const OPT_NO_HOSTS: DaemonOption = DaemonOption::NoHosts;
pub const OPT_NO_POLL: DaemonOption = DaemonOption::NoPoll;
pub const OPT_DEBUG: DaemonOption = DaemonOption::Debug;
pub const OPT_ORDER: DaemonOption = DaemonOption::Order;
pub const OPT_NO_RESOLV: DaemonOption = DaemonOption::NoResolv;
pub const OPT_EXPAND: DaemonOption = DaemonOption::Expand;
pub const OPT_LOCALMX: DaemonOption = DaemonOption::Localmx;
pub const OPT_NO_NEG: DaemonOption = DaemonOption::NoNeg;
pub const OPT_NODOTS_LOCAL: DaemonOption = DaemonOption::NodotsLocal;
pub const OPT_NOWILD: DaemonOption = DaemonOption::Nowild;
pub const OPT_ETHERS: DaemonOption = DaemonOption::Ethers;
pub const OPT_RESOLV_DOMAIN: DaemonOption = DaemonOption::ResolvDomain;
pub const OPT_NO_FORK: DaemonOption = DaemonOption::NoFork;
pub const OPT_AUTHORITATIVE: DaemonOption = DaemonOption::Authoritative;
pub const OPT_LOCALISE: DaemonOption = DaemonOption::Localise;
pub const OPT_DBUS: DaemonOption = DaemonOption::Dbus;
pub const OPT_DHCP_FQDN: DaemonOption = DaemonOption::DhcpFqdn;
pub const OPT_NO_PING: DaemonOption = DaemonOption::NoPing;
pub const OPT_LEASE_RO: DaemonOption = DaemonOption::LeaseRo;
pub const OPT_ALL_SERVERS: DaemonOption = DaemonOption::AllServers;
pub const OPT_RELOAD: DaemonOption = DaemonOption::Reload;
pub const OPT_LOCAL_REBIND: DaemonOption = DaemonOption::LocalRebind;
pub const OPT_TFTP_SECURE: DaemonOption = DaemonOption::TftpSecure;
pub const OPT_TFTP_NOBLOCK: DaemonOption = DaemonOption::TftpNoblock;
pub const OPT_LOG_OPTS: DaemonOption = DaemonOption::LogOpts;
pub const OPT_TFTP_APREF_IP: DaemonOption = DaemonOption::TftpAprefIp;
pub const OPT_NO_OVERRIDE: DaemonOption = DaemonOption::NoOverride;
pub const OPT_NO_REBIND: DaemonOption = DaemonOption::NoRebind;
pub const OPT_ADD_MAC: DaemonOption = DaemonOption::AddMac;
pub const OPT_DNSSEC_PROXY: DaemonOption = DaemonOption::DnssecProxy;
pub const OPT_CONSEC_ADDR: DaemonOption = DaemonOption::ConsecAddr;
pub const OPT_CONNTRACK: DaemonOption = DaemonOption::Conntrack;
pub const OPT_FQDN_UPDATE: DaemonOption = DaemonOption::FqdnUpdate;
pub const OPT_RA: DaemonOption = DaemonOption::Ra;
pub const OPT_TFTP_LC: DaemonOption = DaemonOption::TftpLc;
pub const OPT_CLEVERBIND: DaemonOption = DaemonOption::Cleverbind;
pub const OPT_TFTP: DaemonOption = DaemonOption::Tftp;
pub const OPT_CLIENT_SUBNET: DaemonOption = DaemonOption::ClientSubnet;
pub const OPT_QUIET_DHCP: DaemonOption = DaemonOption::QuietDhcp;
pub const OPT_QUIET_DHCP6: DaemonOption = DaemonOption::QuietDhcp6;
pub const OPT_QUIET_RA: DaemonOption = DaemonOption::QuietRa;
pub const OPT_DNSSEC_VALID: DaemonOption = DaemonOption::DnssecValid;
pub const OPT_DNSSEC_TIME: DaemonOption = DaemonOption::DnssecTime;
pub const OPT_DNSSEC_DEBUG: DaemonOption = DaemonOption::DnssecDebug;
pub const OPT_DNSSEC_IGN_NS: DaemonOption = DaemonOption::DnssecIgnNs;
pub const OPT_LOCAL_SERVICE: DaemonOption = DaemonOption::LocalService;
pub const OPT_LOOP_DETECT: DaemonOption = DaemonOption::LoopDetect;
pub const OPT_EXTRALOG: DaemonOption = DaemonOption::Extralog;
pub const OPT_TFTP_NO_FAIL: DaemonOption = DaemonOption::TftpNoFail;
pub const OPT_SCRIPT_ARP: DaemonOption = DaemonOption::ScriptArp;
pub const OPT_MAC_B64: DaemonOption = DaemonOption::MacB64;
pub const OPT_MAC_HEX: DaemonOption = DaemonOption::MacHex;
pub const OPT_TFTP_APREF_MAC: DaemonOption = DaemonOption::TftpAprefMac;
pub const OPT_RAPID_COMMIT: DaemonOption = DaemonOption::RapidCommit;
pub const OPT_UBUS: DaemonOption = DaemonOption::Ubus;
pub const OPT_IGNORE_CLID: DaemonOption = DaemonOption::IgnoreClid;
pub const OPT_SINGLE_PORT: DaemonOption = DaemonOption::SinglePort;
pub const OPT_LEASE_RENEW: DaemonOption = DaemonOption::LeaseRenew;
pub const OPT_LOG_DEBUG: DaemonOption = DaemonOption::LogDebug;
pub const OPT_UMBRELLA: DaemonOption = DaemonOption::Umbrella;
pub const OPT_UMBRELLA_DEVID: DaemonOption = DaemonOption::UmbrellaDevid;
pub const OPT_CMARK_ALST_EN: DaemonOption = DaemonOption::CmarkAlstEn;
pub const OPT_QUIET_TFTP: DaemonOption = DaemonOption::QuietTftp;
pub const OPT_STRIP_ECS: DaemonOption = DaemonOption::StripEcs;
pub const OPT_STRIP_MAC: DaemonOption = DaemonOption::StripMac;
pub const OPT_NORR: DaemonOption = DaemonOption::Norr;
pub const OPT_NO_IDENT: DaemonOption = DaemonOption::NoIdent;
pub const OPT_CACHE_RR: DaemonOption = DaemonOption::CacheRr;
pub const OPT_LOCALHOST_SERVICE: DaemonOption = DaemonOption::LocalhostService;
pub const OPT_LOG_PROTO: DaemonOption = DaemonOption::LogProto;
pub const OPT_NO_0X20: DaemonOption = DaemonOption::No0x20;
pub const OPT_DO_0X20: DaemonOption = DaemonOption::Do0x20;
pub const OPT_AUTH_LOG: DaemonOption = DaemonOption::AuthLog;
pub const OPT_LEASEQUERY: DaemonOption = DaemonOption::Leasequery;
pub const OPT_LOG_ONLY_FAILED: DaemonOption = DaemonOption::LogOnlyFailed;
pub const OPT_LOG_MALLOC: DaemonOption = DaemonOption::LogMalloc;
/// Not a real option bit — the count of variants in [`DaemonOption`], used to
/// size `Daemon::options`.
pub const OPT_LAST: usize = 80;

const OPTION_BITS: usize = u32::BITS as usize;
pub const OPTION_SIZE: usize = (OPT_LAST / OPTION_BITS) + ((OPT_LAST % OPTION_BITS != 0) as usize);

/// DNSSEC validation resource limit indexes.
pub const LIMIT_SIG_FAIL: usize = 0;
pub const LIMIT_CRYPTO: usize = 1;
pub const LIMIT_WORK: usize = 2;
pub const LIMIT_NSEC3_ITERS: usize = 3;
pub const LIMIT_MAX: usize = 4;

pub const DNSSEC_LIMIT_SIG_FAIL: i32 = 20;
pub const DNSSEC_LIMIT_CRYPTO: i32 = 200;
pub const DNSSEC_LIMIT_WORK: i32 = 40;
pub const DNSSEC_LIMIT_NSEC3_ITERS: i32 = 150;

/// Cache record flags (F_* constants).
pub const F_IMMORTAL:  u32 = 1 << 0;
pub const F_NAMEP:     u32 = 1 << 1;
pub const F_REVERSE:   u32 = 1 << 2;
pub const F_FORWARD:   u32 = 1 << 3;
pub const F_DHCP:      u32 = 1 << 4;
pub const F_NEG:       u32 = 1 << 5;
pub const F_HOSTS:     u32 = 1 << 6;
pub const F_IPV4:      u32 = 1 << 7;
pub const F_IPV6:      u32 = 1 << 8;
pub const F_BIGNAME:   u32 = 1 << 9;
pub const F_NXDOMAIN:  u32 = 1 << 10;
pub const F_CNAME:     u32 = 1 << 11;
pub const F_DNSKEY:    u32 = 1 << 12;
pub const F_CONFIG:    u32 = 1 << 13;
pub const F_DS:        u32 = 1 << 14;
pub const F_DNSSECOK:  u32 = 1 << 15;
pub const F_UPSTREAM:  u32 = 1 << 16;
pub const F_RRNAME:    u32 = 1 << 17;
pub const F_SERVER:    u32 = 1 << 18;
pub const F_QUERY:     u32 = 1 << 19;
pub const F_NOERR:     u32 = 1 << 20;
pub const F_AUTH:      u32 = 1 << 21;
pub const F_DNSSEC:    u32 = 1 << 22;
pub const F_KEYTAG:    u32 = 1 << 23;
pub const F_SECSTAT:   u32 = 1 << 24;
pub const F_NO_RR:     u32 = 1 << 25;
pub const F_IPSET:     u32 = 1 << 26;
pub const F_NOEXTRA:   u32 = 1 << 27;
pub const F_DOMAINSRV: u32 = 1 << 28;
pub const F_RCODE:     u32 = 1 << 29;
pub const F_RR:        u32 = 1 << 30;
pub const F_STALE:     u32 = 1 << 31;

pub const UID_NONE:   u32 = 0;
pub const SRC_CONFIG: u32 = 1;
pub const SRC_HOSTS:  u32 = 2;
pub const SRC_AH:     u32 = 3;

// DNSSEC status values
pub const STAT_SECURE:    u32 = 0x10000;
pub const STAT_INSECURE:  u32 = 0x20000;
pub const STAT_BOGUS:     u32 = 0x30000;
pub const STAT_NEED_DS:   u32 = 0x40000;
pub const STAT_NEED_KEY:  u32 = 0x50000;
pub const STAT_TRUNCATED: u32 = 0x60000;
pub const STAT_OK:        u32 = 0x70000;
pub const STAT_ABANDONED: u32 = 0x80000;
pub const STAT_ASYNC:     u32 = 0x90000;

pub fn stat_is_equal(a: u32, b: u32) -> bool {
    (a & 0xffff_0000) == b
}

// DNSSEC failure bit flags
pub const DNSSEC_FAIL_NYV:        u32 = 0x0001;
pub const DNSSEC_FAIL_EXP:        u32 = 0x0002;
pub const DNSSEC_FAIL_INDET:      u32 = 0x0004;
pub const DNSSEC_FAIL_NOKEYSUP:   u32 = 0x0008;
pub const DNSSEC_FAIL_NOSIG:      u32 = 0x0010;
pub const DNSSEC_FAIL_NOZONE:     u32 = 0x0020;
pub const DNSSEC_FAIL_NONSEC:     u32 = 0x0040;
pub const DNSSEC_FAIL_NODSSUP:    u32 = 0x0080;
pub const DNSSEC_FAIL_NOKEY:      u32 = 0x0100;
pub const DNSSEC_FAIL_NSEC3_ITERS: u32 = 0x0200;
pub const DNSSEC_FAIL_BADPACKET:  u32 = 0x0400;
pub const DNSSEC_FAIL_WORK:       u32 = 0x0800;
pub const DNSSEC_FAIL_UPSTREAM:   u32 = 0x1000;

// Frec flags
pub const FREC_NOREBIND:          u32 = 1;
pub const FREC_CHECKING_DISABLED: u32 = 2;
pub const FREC_NO_CACHE:          u32 = 4;
pub const FREC_DNSKEY_QUERY:      u32 = 8;
pub const FREC_DS_QUERY:          u32 = 16;
pub const FREC_AD_QUESTION:       u32 = 32;
pub const FREC_DO_QUESTION:       u32 = 64;
pub const FREC_HAS_PHEADER:       u32 = 128;
pub const FREC_GONE_TO_TCP:       u32 = 256;
pub const FREC_ANSWER:            u32 = 512;

// PIPE_OP codes (child→parent pipe)
pub const PIPE_OP_INSERT: u32 = 1;
pub const PIPE_OP_RESULT: u32 = 2;
pub const PIPE_OP_STATS:  u32 = 3;
pub const PIPE_OP_IPSET:  u32 = 4;
pub const PIPE_OP_NFTSET: u32 = 5;
pub const PIPE_OP_KILLED: u32 = 6;

// Dump packet flags
pub const DUMP_QUERY:     u32 = 0x0001;
pub const DUMP_REPLY:     u32 = 0x0002;
pub const DUMP_UP_QUERY:  u32 = 0x0004;
pub const DUMP_UP_REPLY:  u32 = 0x0008;
pub const DUMP_SEC_QUERY: u32 = 0x0010;
pub const DUMP_SEC_REPLY: u32 = 0x0020;
pub const DUMP_BOGUS:     u32 = 0x0040;
pub const DUMP_SEC_BOGUS: u32 = 0x0080;
pub const DUMP_DHCP:      u32 = 0x1000;
pub const DUMP_DHCPV6:    u32 = 0x2000;
pub const DUMP_RA:        u32 = 0x4000;
pub const DUMP_TFTP:      u32 = 0x8000;

// Async event queue descriptor
#[derive(Debug, Clone, Copy)]
pub struct EventDesc {
    pub event:  i32,
    pub data:   i32,
    pub msg_sz: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn option_size_covers_all() {
        assert!(OPTION_SIZE * u32::BITS as usize >= OPT_LAST);
    }

    #[test]
    fn stat_is_equal_works() {
        assert!(stat_is_equal(STAT_BOGUS | 0x0006, STAT_BOGUS));
        assert!(!stat_is_equal(STAT_BOGUS, STAT_SECURE));
    }
}
