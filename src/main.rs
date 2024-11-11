use dnsmasq::{Daemon, DAEMON};

mod arp;
mod auth;
mod blockdata;
mod bpf;
mod cache;
mod dnsmasq;
mod dnssec;
mod domain;
mod domain_match;
mod dump;
mod edns0;
mod forward;
mod hash_questions;
mod helper;
mod inotify;
mod ip6addr;
mod ipset;
mod lease;
mod log;
mod loop_impl;
mod metrics;
mod netlink;
mod network;
mod nftset;
mod option;
mod outpacket;
mod pattern;
mod poll;
mod radv;
mod radv_protocol;
mod rfc1035;
mod rfc2131;
mod rfc3315;
mod rrfilter;
mod slaac;
mod tables;
mod tftp;
mod ubus;
mod util;
mod config;
mod conntrack;
mod crypto;
mod dbus;
mod dhcp;
mod dhcp6;
mod dhcp6_protocol;
mod dhcp_common;
mod dhcp_protocol;
mod dns_protocol;


// The main function translated to Rust
fn main() {
    // Initialize daemon
    unsafe {
        DAEMON = Some(Daemon {
            edns_pktsz: 0,
            packet_buff_sz: 0,
            packet: Vec::new(),
            addrbuff2: None,
            kernel_version: None,
        });
    }

    let now = std::time::SystemTime::now();
    let mut sigact = sigaction {
        sa_handler: SIG_IGN,
        sa_flags: 0,
        sa_mask: SigSet::empty(),
    };

    unsafe {
        {
            sigact.sa_handler = dnsmasq::sig_handler as sighandler_t;
            sigaction(SIGUSR1, &sigact, std::ptr::null_mut());
            sigaction(SIGUSR2, &sigact, std::ptr::null_mut());
            sigaction(SIGHUP, &sigact, std::ptr::null_mut());
            sigaction(SIGTERM, &sigact, std::ptr::null_mut());
            sigaction(SIGALRM, &sigact, std::ptr::null_mut());
            sigaction(SIGCHLD, &sigact, std::ptr::null_mut());
            sigaction(SIGINT, &sigact, std::ptr::null_mut());

            sigact.sa_handler = SIG_IGN;
            sigaction(SIGPIPE, &sigact, std::ptr::null_mut());
        }

        libc::umask(0o22); // Set umask

        // Dummy rand_init and read_opts function calls
        dnsmasq::rand_init();
        dnsmasq::read_opts(std::env::args().len() as i32, std::ptr::null_mut(), std::ptr::null());
    }
}