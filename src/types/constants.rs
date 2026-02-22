/// Global constants and option bit definitions.
/// Ported from `dnsmasq.h`.

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
pub const OPT_BOGUSPRIV:        usize = 0;
pub const OPT_FILTER:           usize = 1;
pub const OPT_LOG:              usize = 2;
pub const OPT_SELFMX:           usize = 3;
pub const OPT_NO_HOSTS:         usize = 4;
pub const OPT_NO_POLL:          usize = 5;
pub const OPT_DEBUG:            usize = 6;
pub const OPT_ORDER:            usize = 7;
pub const OPT_NO_RESOLV:        usize = 8;
pub const OPT_EXPAND:           usize = 9;
pub const OPT_LOCALMX:          usize = 10;
pub const OPT_NO_NEG:           usize = 11;
pub const OPT_NODOTS_LOCAL:     usize = 12;
pub const OPT_NOWILD:           usize = 13;
pub const OPT_ETHERS:           usize = 14;
pub const OPT_RESOLV_DOMAIN:    usize = 15;
pub const OPT_NO_FORK:          usize = 16;
pub const OPT_AUTHORITATIVE:    usize = 17;
pub const OPT_LOCALISE:         usize = 18;
pub const OPT_DBUS:             usize = 19;
pub const OPT_DHCP_FQDN:        usize = 20;
pub const OPT_NO_PING:          usize = 21;
pub const OPT_LEASE_RO:         usize = 22;
pub const OPT_ALL_SERVERS:      usize = 23;
pub const OPT_RELOAD:           usize = 24;
pub const OPT_LOCAL_REBIND:     usize = 25;
pub const OPT_TFTP_SECURE:      usize = 26;
pub const OPT_TFTP_NOBLOCK:     usize = 27;
pub const OPT_LOG_OPTS:         usize = 28;
pub const OPT_TFTP_APREF_IP:    usize = 29;
pub const OPT_NO_OVERRIDE:      usize = 30;
pub const OPT_NO_REBIND:        usize = 31;
pub const OPT_ADD_MAC:          usize = 32;
pub const OPT_DNSSEC_PROXY:     usize = 33;
pub const OPT_CONSEC_ADDR:      usize = 34;
pub const OPT_CONNTRACK:        usize = 35;
pub const OPT_FQDN_UPDATE:      usize = 36;
pub const OPT_RA:               usize = 37;
pub const OPT_TFTP_LC:          usize = 38;
pub const OPT_CLEVERBIND:       usize = 39;
pub const OPT_TFTP:             usize = 40;
pub const OPT_CLIENT_SUBNET:    usize = 41;
pub const OPT_QUIET_DHCP:       usize = 42;
pub const OPT_QUIET_DHCP6:      usize = 43;
pub const OPT_QUIET_RA:         usize = 44;
pub const OPT_DNSSEC_VALID:     usize = 45;
pub const OPT_DNSSEC_TIME:      usize = 46;
pub const OPT_DNSSEC_DEBUG:     usize = 47;
pub const OPT_DNSSEC_IGN_NS:    usize = 48;
pub const OPT_LOCAL_SERVICE:    usize = 49;
pub const OPT_LOOP_DETECT:      usize = 50;
pub const OPT_EXTRALOG:         usize = 51;
pub const OPT_TFTP_NO_FAIL:     usize = 52;
pub const OPT_SCRIPT_ARP:       usize = 53;
pub const OPT_MAC_B64:          usize = 54;
pub const OPT_MAC_HEX:          usize = 55;
pub const OPT_TFTP_APREF_MAC:   usize = 56;
pub const OPT_RAPID_COMMIT:     usize = 57;
pub const OPT_UBUS:             usize = 58;
pub const OPT_IGNORE_CLID:      usize = 59;
pub const OPT_SINGLE_PORT:      usize = 60;
pub const OPT_LEASE_RENEW:      usize = 61;
pub const OPT_LOG_DEBUG:        usize = 62;
pub const OPT_UMBRELLA:         usize = 63;
pub const OPT_UMBRELLA_DEVID:   usize = 64;
pub const OPT_CMARK_ALST_EN:    usize = 65;
pub const OPT_QUIET_TFTP:       usize = 66;
pub const OPT_STRIP_ECS:        usize = 67;
pub const OPT_STRIP_MAC:        usize = 68;
pub const OPT_NORR:             usize = 69;
pub const OPT_NO_IDENT:         usize = 70;
pub const OPT_CACHE_RR:         usize = 71;
pub const OPT_LOCALHOST_SERVICE: usize = 72;
pub const OPT_LOG_PROTO:        usize = 73;
pub const OPT_NO_0X20:          usize = 74;
pub const OPT_DO_0X20:          usize = 75;
pub const OPT_AUTH_LOG:         usize = 76;
pub const OPT_LEASEQUERY:       usize = 77;
pub const OPT_LOG_ONLY_FAILED:  usize = 78;
pub const OPT_LOG_MALLOC:       usize = 79;
pub const OPT_LAST:             usize = 80;

const OPTION_BITS: usize = usize::BITS as usize;
pub const OPTION_SIZE: usize = (OPT_LAST / OPTION_BITS) + ((OPT_LAST % OPTION_BITS != 0) as usize);

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
        assert!(OPTION_SIZE * usize::BITS as usize >= OPT_LAST);
    }

    #[test]
    fn stat_is_equal_works() {
        assert!(stat_is_equal(STAT_BOGUS | 0x0006, STAT_BOGUS));
        assert!(!stat_is_equal(STAT_BOGUS, STAT_SECURE));
    }
}
