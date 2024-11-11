
// Constants
pub const FTABSIZ: usize = 150;
pub const MAX_PROCS: usize = 20;
pub const CHILD_LIFETIME: usize = 150;
pub const TCP_MAX_QUERIES: usize = 100;
pub const TCP_BACKLOG: usize = 32;
pub const EDNS_PKTSZ: usize = 1232;
pub const SAFE_PKTSZ: usize = 1232;
pub const KEYBLOCK_LEN: usize = 40;
pub const DNSSEC_LIMIT_WORK: usize = 40;
pub const DNSSEC_LIMIT_SIG_FAIL: usize = 20;
pub const DNSSEC_LIMIT_CRYPTO: usize = 200;
pub const DNSSEC_LIMIT_NSEC3_ITERS: usize = 150;
pub const TIMEOUT: usize = 10;
pub const SMALL_PORT_RANGE: usize = 30;
pub const FORWARD_TEST: usize = 50;
pub const FORWARD_TIME: usize = 20;
pub const UDP_TEST_TIME: usize = 60;
pub const SERVERS_LOGGED: usize = 30;
pub const LOCALS_LOGGED: usize = 8;
pub const LEASE_RETRY: usize = 60;
pub const CACHESIZ: usize = 150;
pub const TTL_FLOOR_LIMIT: usize = 3600;
pub const MAXLEASES: usize = 1000;
pub const PING_WAIT: usize = 3;
pub const PING_CACHE_TIME: usize = 30;
pub const DECLINE_BACKOFF: usize = 600;
pub const DHCP_PACKET_MAX: usize = 16384;
pub const SMALLDNAME: usize = 50;
pub const CNAME_CHAIN: usize = 10;
pub const DNSSEC_MIN_TTL: usize = 60;
pub const HOSTSFILE: &str = "/etc/hosts";
pub const ETHERSFILE: &str = "/etc/ethers";
pub const DEFLEASE: usize = 3600;
pub const DEFLEASE6: usize = 3600 * 24;
pub const CHUSER: &str = "nobody";
pub const CHGRP: &str = "dip";
pub const TFTP_MAX_CONNECTIONS: usize = 50;
pub const LOG_MAX: usize = 5;
pub const RANDFILE: &str = "/dev/urandom";
pub const DNSMASQ_SERVICE: &str = "uk.org.thekelleys.dnsmasq";
pub const DNSMASQ_PATH: &str = "/uk/org/thekelleys/dnsmasq";
pub const DNSMASQ_UBUS_NAME: &str = "dnsmasq";
pub const AUTH_TTL: usize = 600;
pub const SOA_REFRESH: usize = 1200;
pub const SOA_RETRY: usize = 180;
pub const SOA_EXPIRY: usize = 1209600;
pub const LOOP_TEST_DOMAIN: &str = "test";
pub const LOOP_TEST_TYPE: &str = "T_TXT";
pub const DEFAULT_FAST_RETRY: usize = 1000;
pub const STALE_CACHE_EXPIRY: usize = 86400;

// Compile-time options
#[cfg(feature = "broken_rtc")]
pub const HAVE_BROKEN_RTC: bool = true;

#[cfg(feature = "tftp")]
pub const HAVE_TFTP: bool = true;

#[cfg(feature = "dhcp")]
pub const HAVE_DHCP: bool = true;

#[cfg(feature = "dhcp6")]
pub const HAVE_DHCP6: bool = true;

#[cfg(feature = "script")]
pub const HAVE_SCRIPT: bool = true;

#[cfg(feature = "luascript")]
pub const HAVE_LUASCRIPT: bool = true;

#[cfg(feature = "dbus")]
pub const HAVE_DBUS: bool = true;

#[cfg(feature = "ubus")]
pub const HAVE_UBUS: bool = true;

#[cfg(feature = "idn")]
pub const HAVE_IDN: bool = true;

#[cfg(feature = "libidn2")]
pub const HAVE_LIBIDN2: bool = true;

#[cfg(feature = "conntrack")]
pub const HAVE_CONNTRACK: bool = true;

#[cfg(feature = "ipset")]
pub const HAVE_IPSET: bool = true;

#[cfg(feature = "nftset")]
pub const HAVE_NFTSET: bool = true;

#[cfg(feature = "auth")]
pub const HAVE_AUTH: bool = true;

#[cfg(feature = "cryptohash")]
pub const HAVE_CRYPTOHASH: bool = true;

#[cfg(feature = "dnssec")]
pub const HAVE_DNSSEC: bool = true;

#[cfg(feature = "dumpfile")]
pub const HAVE_DUMPFILE: bool = true;

#[cfg(feature = "loop")]
pub const HAVE_LOOP: bool = true;

#[cfg(feature = "inotify")]
pub const HAVE_INOTIFY: bool = true;

// Default locations for important system files
pub const LEASEFILE: &str = if cfg!(target_os = "freebsd") || cfg!(target_os = "openbsd") || cfg!(target_os = "dragonfly") || cfg!(target_os = "netbsd") {
    "/var/db/dnsmasq.leases"
} else if cfg!(target_os = "solaris") {
    "/var/cache/dnsmasq.leases"
} else if cfg!(target_os = "android") {
    "/data/misc/dhcp/dnsmasq.leases"
} else {
    "/var/lib/misc/dnsmasq.leases"
};

pub const CONFFILE: &str = if cfg!(target_os = "freebsd") {
    "/usr/local/etc/dnsmasq.conf"
} else {
    "/etc/dnsmasq.conf"
};

pub const RESOLVFILE: &str = if cfg!(target_os = "uclinux") {
    "/etc/config/resolv.conf"
} else {
    "/etc/resolv.conf"
};

pub const RUNFILE: &str = if cfg!(target_os = "android") {
    "/data/dnsmasq.pid"
} else {
    "/var/run/dnsmasq.pid"
};

// Platform dependent options
#[cfg(target_os = "linux")]
pub const HAVE_LINUX_NETWORK: bool = true;

#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "dragonfly", target_os = "netbsd", target_os = "macos"))]
pub const HAVE_BSD_NETWORK: bool = true;

#[cfg(target_os = "solaris")]
pub const HAVE_SOLARIS_NETWORK: bool = true;

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "openbsd", target_os = "dragonfly", target_os = "netbsd", target_os = "macos", target_os = "solaris"))]
pub const HAVE_GETOPT_LONG: bool = true;

#[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "dragonfly", target_os = "netbsd", target_os = "macos"))]
pub const HAVE_SOCKADDR_SA_LEN: bool = true;

// Compile-time option dependencies and NO_XXX flags
#[cfg(not(feature = "tftp"))]
pub const NO_TFTP: bool = true;

#[cfg(not(feature = "dhcp"))]
pub const NO_DHCP: bool = true;

#[cfg(not(feature = "dhcp6"))]
pub const NO_DHCP6: bool = true;

#[cfg(not(feature = "script"))]
pub const NO_SCRIPT: bool = true;

#[cfg(not(feature = "luascript"))]
pub const NO_LUASCRIPT: bool = true;

#[cfg(not(feature = "auth"))]
pub const NO_AUTH: bool = true;

#[cfg(not(feature = "ipset"))]
pub const NO_IPSET: bool = true;

#[cfg(not(feature = "loop"))]
pub const NO_LOOP: bool = true;

#[cfg(not(feature = "dumpfile"))]
pub const NO_DUMPFILE: bool = true;

#[cfg(all(target_os = "linux", not(feature = "inotify")))]
pub const NO_INOTIFY: bool = true;