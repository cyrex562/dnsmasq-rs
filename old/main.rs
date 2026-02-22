use dnsmasq::{Daemon, DAEMON};

mod addr_list;
mod all_addr;
mod allow_list;
mod arp;
mod arp_record;
mod auth;
mod auth_zone;
mod big_name;
mod block_name;
mod blockdata;
mod bogus_addr;
mod bpf;
mod cache;
mod cname;
mod cond_domain;
mod config;
mod conntrack;
mod constants;
mod context;
mod crec;
mod crypto;
mod daemon;
mod dbus;
mod dhcp;
mod dhcp6;
mod dhcp6_protocol;
mod dhcp_boot;
mod dhcp_bridge;
mod dhcp_common;
mod dhcp_lease;
mod dhcp_mac;
mod dhcp_match_name;
mod dhcp_netid;
mod dhcp_opt;
mod dhcp_protocol;
mod dhcp_pxe_vendor;
mod dhcp_vendor;
mod dns_protocol;
mod dnsmasq;
mod dnssec;
mod doctor;
mod domain;
mod domain_match;
mod ds_config;
mod dump;
mod dyn_dir;
mod edns0;
mod event_desc;
mod forward;
mod frec;
mod hash_questions;
mod helper;
mod host_record;
mod hosts_file;
mod iname;
mod inotify;
mod interface_name;
mod ip6addr;
mod ip_sets;
mod ipset;
mod irec;
mod lease;
mod listener;
mod log;
mod loop_impl;
mod metrics;
mod mx_srv_record;
mod my_sock_addr;
mod my_subnet;
mod naptr;
mod netlink;
mod network;
mod nftset;
mod option;
mod outpacket;
mod pattern;
mod poll;
mod ptr_record;
mod pxe_service;
mod radv;
mod radv_protocol;
mod rand_fd;
mod rebind_domain;
mod resolvc;
mod rfc1035;
mod rfc2131;
mod rfc3315;
mod rrfilter;
mod rrlist;
mod server;
mod server_fd;
mod slaac;
mod tables;
mod tag_if;
mod tftp;
mod txt_record;
mod ubus;
mod util;
mod ra_interface;

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
        dnsmasq::read_opts(
            std::env::args().len() as i32,
            std::ptr::null_mut(),
            std::ptr::null(),
        );
    }
}
