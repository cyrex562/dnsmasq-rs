use std::ffi::CString;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::str::FromStr;
use std::time::SystemTime;

static mut LEASES: Option<Vec<DhcpLease>> = None;
static mut DNS_DIRTY: bool = false;
static mut FILE_DIRTY: bool = false;
static mut LEASES_LEFT: usize = 0;

#[derive(Debug)]
struct DhcpLease {
    addr: IpAddr,
    expires: SystemTime,
    hw_type: Option<u8>,
    hw_addr: Option<Vec<u8>>,
    clid: Option<Vec<u8>>,
    hostname: Option<String>,
}

fn parse_hex(s: &str) -> Vec<u8> {
    s.split(':')
        .filter_map(|byte_str| u8::from_str_radix(byte_str, 16).ok())
        .collect()
}

fn lease4_allocate(addr: IpAddr) -> Option<DhcpLease> {
    // Placeholder for lease allocation logic
    Some(DhcpLease {
        addr,
        expires: SystemTime::now(),
        hw_type: None,
        hw_addr: None,
        clid: None,
        hostname: None,
    })
}

fn lease_set_hwaddr(
    lease: &mut DhcpLease,
    hw_addr: Vec<u8>,
    clid: Vec<u8>,
    hw_len: usize,
    hw_type: u8,
    clid_len: usize,
) {
    lease.hw_addr = Some(hw_addr);
    lease.clid = Some(clid);
    lease.hw_type = Some(hw_type);
}

fn lease_set_hostname(lease: &mut DhcpLease, hostname: &str) {
    lease.hostname = Some(hostname.to_string());
}

fn read_leases(filename: &str) {
    let file = File::open(filename).expect("Lease file not found");
    let reader = BufReader::new(file);

    let now = SystemTime::now();
    let mut leases: Vec<DhcpLease> = Vec::new();
    const DHCP_BUFF_SZ: usize = 255;
    const MAXDNAME: usize = 64;
    const PACKETSZ: usize = 512;

    for line in reader.lines() {
        let line = line.expect("Failed to read line");
        let parts: Vec<&str> = line.split_whitespace().collect();

        if parts.len() < 5 {
            eprintln!("Ignoring invalid line in lease database: {:?}", parts);
            continue;
        }

        let addr = parts[0];
        let hw_addr = parts[1];
        let hostname = parts[2];
        let clid = parts[3];
        let expires = parts[4];

        let ip_addr = match IpAddr::from_str(addr) {
            Ok(ip) => ip,
            Err(_) => {
                eprintln!("Ignoring invalid address in lease database: {}", addr);
                continue;
            }
        };

        let mut lease = lease4_allocate(ip_addr).unwrap();
        lease_set_hwaddr(
            &mut lease,
            parse_hex(hw_addr),
            parse_hex(clid),
            DHCP_BUFF_SZ,
            0, // hw_type
            clid.len(),
        );
        lease_set_hostname(&mut lease, hostname);

        lease.expires = SystemTime::UNIX_EPOCH
            + std::time::Duration::from_secs(expires.parse().unwrap_or(0));
        leases.push(lease);
    }

    unsafe {
        LEASES = Some(leases);
    }
}

fn main() {
    read_leases("leasefile");
    unsafe {
        println!("{:?}", LEASES);
    }
}