const LINUX_CAPABILITY_VERSION_1: u32 = 0x19980330;
const LINUX_CAPABILITY_VERSION_2: u32 = 0x20071026;
const LINUX_CAPABILITY_VERSION_3: u32 = 0x20080522;

// Event constants
const EVENT_RELOAD: i32 = 1;
const EVENT_DUMP: i32 = 2;
const EVENT_ALARM: i32 = 3;
const EVENT_TERM: i32 = 4;
const EVENT_CHILD: i32 = 5;
const EVENT_REOPEN: i32 = 6;
const EVENT_EXITED: i32 = 7;
const EVENT_KILLED: i32 = 8;
const EVENT_EXEC_ERR: i32 = 9;
const EVENT_PIPE_ERR: i32 = 10;
const EVENT_USER_ERR: i32 = 11;
const EVENT_CAP_ERR: i32 = 12;
const EVENT_PIDFILE: i32 = 13;
const EVENT_HUSER_ERR: i32 = 14;
const EVENT_GROUP_ERR: i32 = 15;
const EVENT_DIE: i32 = 16;
const EVENT_LOG_ERR: i32 = 17;
const EVENT_FORK_ERR: i32 = 18;
const EVENT_LUA_ERR: i32 = 19;
const EVENT_TFTP_ERR: i32 = 20;
const EVENT_INIT: i32 = 21;
const EVENT_NEWADDR: i32 = 22;
const EVENT_NEWROUTE: i32 = 23;
const EVENT_TIME_ERR: i32 = 24;
const EVENT_SCRIPT_LOG: i32 = 25;
const EVENT_TIME: i32 = 26;

// Exit codes
const EC_GOOD: i32 = 0;
const EC_BADCONF: i32 = 1;
const EC_BADNET: i32 = 2;
const EC_FILE: i32 = 3;
const EC_NOMEM: i32 = 4;
const EC_MISC: i32 = 5;
const EC_INIT_OFFSET: i32 = 10;

// Option constants
const OPT_BOGUSPRIV: i32 = 0;
const OPT_FILTER: i32 = 1;
const OPT_LOG: i32 = 2;
const OPT_SELFMX: i32 = 3;
const OPT_NO_HOSTS: i32 = 4;
const OPT_NO_POLL: i32 = 5;
const OPT_DEBUG: i32 = 6;
const OPT_ORDER: i32 = 7;
const OPT_NO_RESOLV: i32 = 8;
const OPT_EXPAND: i32 = 9;
const OPT_LOCALMX: i32 = 10;
const OPT_NO_NEG: i32 = 11;
const OPT_NODOTS_LOCAL: i32 = 12;
const OPT_NOWILD: i32 = 13;
const OPT_ETHERS: i32 = 14;
const OPT_RESOLV_DOMAIN: i32 = 15;
const OPT_NO_FORK: i32 = 16;
const OPT_AUTHORITATIVE: i32 = 17;
const OPT_LOCALISE: i32 = 18;
const OPT_DBUS: i32 = 19;
const OPT_DHCP_FQDN: i32 = 20;
const OPT_NO_PING: i32 = 21;
const OPT_LEASE_RO: i32 = 22;
const OPT_ALL_SERVERS: i32 = 23;
const OPT_RELOAD: i32 = 24;
const OPT_LOCAL_REBIND: i32 = 25;
const OPT_TFTP_SECURE: i32 = 26;
const OPT_TFTP_NOBLOCK: i32 = 27;
const OPT_LOG_OPTS: i32 = 28;
const OPT_TFTP_APREF_IP: i32 = 29;
const OPT_NO_OVERRIDE: i32 = 30;
const OPT_NO_REBIND: i32 = 31;
const OPT_ADD_MAC: i32 = 32;
const OPT_DNSSEC_PROXY: i32 = 33;
const OPT_CONSEC_ADDR: i32 = 34;
const OPT_CONNTRACK: i32 = 35;
const OPT_FQDN_UPDATE: i32 = 36;
const OPT_RA: i32 = 37;
const OPT_TFTP_LC: i32 = 38;
const OPT_CLEVERBIND: i32 = 39;
const OPT_TFTP: i32 = 40;
const OPT_CLIENT_SUBNET: i32 = 41;
const OPT_QUIET_DHCP: i32 = 42;
const OPT_QUIET_DHCP6: i32 = 43;
const OPT_QUIET_RA: i32 = 44;
const OPT_DNSSEC_VALID: i32 = 45;
const OPT_DNSSEC_TIME: i32 = 46;
const OPT_DNSSEC_DEBUG: i32 = 47;
const OPT_DNSSEC_IGN_NS: i32 = 48;
const OPT_LOCAL_SERVICE: i32 = 49;
const OPT_LOOP_DETECT: i32 = 50;
const OPT_EXTRALOG: i32 = 51;
const OPT_TFTP_NO_FAIL: i32 = 52;
const OPT_SCRIPT_ARP: i32 = 53;
const OPT_MAC_B64: i32 = 54;
const OPT_MAC_HEX: i32 = 55;
const OPT_TFTP_APREF_MAC: i32 = 56;
const OPT_RAPID_COMMIT: i32 = 57;
const OPT_UBUS: i32 = 58;
const OPT_IGNORE_CLID: i32 = 59;
const OPT_SINGLE_PORT: i32 = 60;
const OPT_LEASE_RENEW: i32 = 61;
const OPT_LOG_DEBUG: i32 = 62;
const OPT_UMBRELLA: i32 = 63;
const OPT_UMBRELLA_DEVID: i32 = 64;
const OPT_CMARK_ALST_EN: i32 = 65;
const OPT_QUIET_TFTP: i32 = 66;
const OPT_STRIP_ECS: i32 = 67;
const OPT_STRIP_MAC: i32 = 68;
const OPT_NORR: i32 = 69;
const OPT_NO_IDENT: i32 = 70;
const OPT_CACHE_RR: i32 = 71;
const OPT_LOCALHOST_SERVICE: i32 = 72;
const OPT_LAST: i32 = 73;

// Extra flags for my_syslog, we use facilities since they are known
// not to occupy the same bits as priorities, no matter how syslog.h is set up.
// MS_DEBUG messages are suppressed unless --log-debug is set.

const MS_TFTP: i32 = libc::LOG_USER;
const MS_DHCP: i32 = libc::LOG_DAEMON;
const MS_SCRIPT: i32 = libc::LOG_MAIL;
const MS_DEBUG: i32 = libc::LOG_NEWS;

const TXT_STAT_CACHESIZE: i32 = 1;
const TXT_STAT_INSERTS: i32 = 2;
const TXT_STAT_EVICTIONS: i32 = 3;
const TXT_STAT_MISSES: i32 = 4;
const TXT_STAT_HITS: i32 = 5;
const TXT_STAT_AUTH: i32 = 6;
const TXT_STAT_SERVERS: i32 = 7;

const ADDRLIST_LITERAL: i32 = 1;
const ADDRLIST_IPV6: i32 = 2;
const ADDRLIST_REVONLY: i32 = 4;
const ADDRLIST_PREFIX: i32 = 8;
const ADDRLIST_WILDCARD: i32 = 16;
const ADDRLIST_DECLINED: i32 = 32;

const INTERVAL: u64 = 90;
pub(crate) const DHCP_CHADDR_MAX: usize = 16;
const ARP_MARK: u16 = 0;
const ARP_FOUND: u16 = 1;
const ARP_NEW: u16 = 2;
const ARP_EMPTY: u16 = 3;

const AUTH6: i32 = 1;
const AUTH4: i32 = 2;

const HR_6: i32 = 1;
const HR_4: i32 = 2;

const IN4: i32 = 1;
const IN6: i32 = 2;
const INP4: i32 = 4;
const INP6: i32 = 8;

const F_IMMORTAL: u32 = 1 << 0;
const F_NAMEP: u32 = 1 << 1;
const F_REVERSE: u32 = 1 << 2;
const F_FORWARD: u32 = 1 << 3;
const F_DHCP: u32 = 1 << 4;
const F_NEG: u32 = 1 << 5;
const F_HOSTS: u32 = 1 << 6;
const F_IPV4: u32 = 1 << 7;
const F_IPV6: u32 = 1 << 8;
const F_BIGNAME: u32 = 1 << 9;
const F_NXDOMAIN: u32 = 1 << 10;
const F_CNAME: u32 = 1 << 11;
const F_DNSKEY: u32 = 1 << 12;
const F_CONFIG: u32 = 1 << 13;
const F_DS: u32 = 1 << 14;
const F_DNSSECOK: u32 = 1 << 15;
const F_UPSTREAM: u32 = 1 << 16;
const F_RRNAME: u32 = 1 << 17;
const F_SERVER: u32 = 1 << 18;
const F_QUERY: u32 = 1 << 19;
const F_NOERR: u32 = 1 << 20;
const F_AUTH: u32 = 1 << 21;
const F_DNSSEC: u32 = 1 << 22;
const F_KEYTAG: u32 = 1 << 23;
const F_SECSTAT: u32 = 1 << 24;
const F_NO_RR: u32 = 1 << 25;
const F_IPSET: u32 = 1 << 26;
const F_NOEXTRA: u32 = 1 << 27;
const F_DOMAINSRV: u32 = 1 << 28;
const F_RCODE: u32 = 1 << 29;
const F_RR: u32 = 1 << 30;
const F_STALE: u32 = 1 << 31;

const UID_NONE: u32 = 0;
/* Values of uid in crecs with F_CONFIG bit set. */
const SRC_CONFIG: u32 = 1;
const SRC_HOSTS: u32 = 2;
const SRC_AH: u32 = 3;

const IFACE_TENTATIVE: i32 = 1;
const IFACE_DEPRECATED: i32 = 2;
const IFACE_PERMANENT: i32 = 4;

const SERV_LITERAL_ADDRESS: i32 = 1; // addr is the answer, or NoDATA is the answer, depending on the next four flags
const SERV_USE_RESOLV: i32 = 2; // forward this domain in the normal way
const SERV_ALL_ZEROS: i32 = 4; // return all zeros for A and AAAA
const SERV_4ADDR: i32 = 8; // addr is IPv4
const SERV_6ADDR: i32 = 16; // addr is IPv6
const SERV_HAS_SOURCE: i32 = 32; // source address defined
const SERV_FOR_NODOTS: i32 = 64; // server for names with no domain part only
const SERV_WARNED_RECURSIVE: i32 = 128; // avoid warning spam
const SERV_FROM_DBUS: i32 = 256; // 1 if source is DBus
const SERV_MARK: i32 = 512; // for mark-and-delete and log code
const SERV_WILDCARD: i32 = 1024; // domain has leading '*'
const SERV_FROM_RESOLV: i32 = 2048; // 1 for servers from resolv, 0 for command line
const SERV_FROM_FILE: i32 = 4096; // read from --servers-file
const SERV_LOOP: i32 = 8192; // server causes forwarding loop
const SERV_DO_DNSSEC: i32 = 16384; // Validate DNSSEC when using this server
const SERV_GOT_TCP: i32 = 32768; // Got some data from the TCP connection

const INAME_USED: i32 = 1;
const INAME_4: i32 = 2;
const INAME_6: i32 = 4;

const AH_DIR: i32 = 1;
const AH_INACTIVE: i32 = 2;
const AH_WD_DONE: i32 = 4;
const AH_HOSTS: i32 = 8;
const AH_DHCP_HST: i32 = 16;
const AH_DHCP_OPT: i32 = 32;

// Packet-dump flags
const DUMP_QUERY: u32 = 0x0001;
const DUMP_REPLY: u32 = 0x0002;
const DUMP_UP_QUERY: u32 = 0x0004;
const DUMP_UP_REPLY: u32 = 0x0008;
const DUMP_SEC_QUERY: u32 = 0x0010;
const DUMP_SEC_REPLY: u32 = 0x0020;
const DUMP_BOGUS: u32 = 0x0040;
const DUMP_SEC_BOGUS: u32 = 0x0080;
const DUMP_DHCP: u32 = 0x1000;
const DUMP_DHCPV6: u32 = 0x2000;
const DUMP_RA: u32 = 0x4000;
const DUMP_TFTP: u32 = 0x8000;

// DNSSEC status values
const STAT_SECURE: u32 = 0x10000;
const STAT_INSECURE: u32 = 0x20000;
const STAT_BOGUS: u32 = 0x30000;
const STAT_NEED_DS: u32 = 0x40000;
const STAT_NEED_KEY: u32 = 0x50000;
const STAT_TRUNCATED: u32 = 0x60000;
const STAT_SECURE_WILDCARD: u32 = 0x70000;
const STAT_OK: u32 = 0x80000;
const STAT_ABANDONED: u32 = 0x90000;

// DNSSEC failure reasons
const DNSSEC_FAIL_NYV: u32 = 0x0001; // key not yet valid
const DNSSEC_FAIL_EXP: u32 = 0x0002; // key expired
const DNSSEC_FAIL_INDET: u32 = 0x0004; // indetermined
const DNSSEC_FAIL_NOKEYSUP: u32 = 0x0008; // no supported key algo
const DNSSEC_FAIL_NOSIG: u32 = 0x0010; // No RRsigs
const DNSSEC_FAIL_NOZONE: u32 = 0x0020; // No Zone bit set
const DNSSEC_FAIL_NONSEC: u32 = 0x0040; // No NSEC
const DNSSEC_FAIL_NODSSUP: u32 = 0x0080; // no supported DS algo
const DNSSEC_FAIL_NOKEY: u32 = 0x0100; // no DNSKEY
const DNSSEC_FAIL_NSEC3_ITERS: u32 = 0x0200; // too many iterations in NSEC3
const DNSSEC_FAIL_BADPACKET: u32 = 0x0400; // bad packet
const DNSSEC_FAIL_WORK: u32 = 0x0800; // too much crypto

const FREC_NOREBIND: u32 = 1;
const FREC_CHECKING_DISABLED: u32 = 2;
const FREC_NO_CACHE: u32 = 4;
const FREC_DNSKEY_QUERY: u32 = 8;
const FREC_DS_QUERY: u32 = 16;
const FREC_AD_QUESTION: u32 = 32;
const FREC_DO_QUESTION: u32 = 64;
const FREC_ADDED_PHEADER: u32 = 128;
const FREC_TEST_PKTSZ: u32 = 256;
const FREC_HAS_EXTRADATA: u32 = 512;
const FREC_HAS_PHEADER: u32 = 1024;

const HASH_SIZE: usize = 32; // SHA-256 digest size

// Flags in top of length field for DHCP-option tables
const OT_ADDR_LIST: u16 = 0x8000;
const OT_RFC1035_NAME: u16 = 0x4000;
const OT_INTERNAL: u16 = 0x2000;
const OT_NAME: u16 = 0x1000;
const OT_CSTRING: u16 = 0x0800;
const OT_DEC: u16 = 0x0400;
const OT_TIME: u16 = 0x0200;

// Actions in the daemon->helper RPC
const ACTION_DEL: i32 = 1;
const ACTION_OLD_HOSTNAME: i32 = 2;
const ACTION_OLD: i32 = 3;
const ACTION_ADD: i32 = 4;
const ACTION_TFTP: i32 = 5;
const ACTION_ARP: i32 = 6;
const ACTION_ARP_DEL: i32 = 7;
const ACTION_RELAY_SNOOP: i32 = 8;

// Lease states
const LEASE_NEW: i32 = 1; // newly created
const LEASE_CHANGED: i32 = 2; // modified
const LEASE_AUX_CHANGED: i32 = 4; // CLID or expiry changed
const LEASE_AUTH_NAME: i32 = 8; // hostname came from config, not from client
const LEASE_USED: i32 = 16; // used this DHCPv6 transaction
const LEASE_NA: i32 = 32; // IPv6 no-temporary lease
const LEASE_TA: i32 = 64; // IPv6 temporary lease
const LEASE_HAVE_HWADDR: i32 = 128; // Have set hwaddress
const LEASE_EXP_CHANGED: i32 = 256; // Lease expiry time changed

// Limits
const LIMIT_SIG_FAIL: i32 = 0;
const LIMIT_CRYPTO: i32 = 1;
const LIMIT_WORK: i32 = 2;
const LIMIT_NSEC3_ITERS: i32 = 3;
const LIMIT_MAX: i32 = 4;

const CONFIG_DISABLE: u32 = 1;
const CONFIG_CLID: u32 = 2;
const CONFIG_TIME: u32 = 8;
const CONFIG_NAME: u32 = 16;
const CONFIG_ADDR: u32 = 32;
const CONFIG_NOCLID: u32 = 128;
const CONFIG_FROM_ETHERS: u32 = 256; // entry created by /etc/ethers
const CONFIG_ADDR_HOSTS: u32 = 512; // address added by from /etc/hosts
const CONFIG_DECLINED: u32 = 1024; // address declined by client
const CONFIG_BANK: u32 = 2048; // from dhcp hosts file
const CONFIG_ADDR6: u32 = 4096;
const CONFIG_ADDR6_HOSTS: u32 = 16384; // address added by from /etc/hosts

const DHOPT_ADDR: u32 = 1;
const DHOPT_STRING: u32 = 2;
const DHOPT_ENCAPSULATE: u32 = 4;
const DHOPT_ENCAP_MATCH: u32 = 8;
const DHOPT_FORCE: u32 = 16;
const DHOPT_BANK: u32 = 32;
const DHOPT_ENCAP_DONE: u32 = 64;
const DHOPT_MATCH: u32 = 128;
const DHOPT_VENDOR: u32 = 256;
const DHOPT_HEX: u32 = 512;
const DHOPT_VENDOR_MATCH: u32 = 1024;
const DHOPT_RFC3925: u32 = 2048;
const DHOPT_TAGOK: u32 = 4096;
const DHOPT_ADDR6: u32 = 8192;
const DHOPT_VENDOR_PXE: u32 = 16384;

const DHCP_PXE_DEF_VENDOR: &str = "PXEClient";

const MATCH_VENDOR: i32 = 1;
const MATCH_USER: i32 = 2;
const MATCH_CIRCUIT: i32 = 3;
const MATCH_REMOTE: i32 = 4;
const MATCH_SUBSCRIBER: i32 = 5;
