use std::convert::TryInto;
use std::net::Ipv4Addr;

// Constants for DNS records
const C_IN: u16 = 1;
const C_ANY: u16 = 255;
const T_OPT: u16 = 41;
const T_TSIG: u16 = 250;
const T_TKEY: u16 = 249;

// Helper macro for reading a 16-bit unsigned integer from a buffer
macro_rules! get_short {
    ($buf:expr) => {{
        let mut buf = [$buf[0], $buf[1]];
        $buf = &$buf[2..];
        u16::from_be_bytes(buf)
    }};
}

// Structure representing DNS Header
#[repr(C)]
struct DnsHeader {
    id: u16,
    flags: u16,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

// Function to find pseudoheader in DNS packet
fn find_pseudoheader(
    header: &DnsHeader,
    plen: usize,
    len: &mut usize,
    p: Option<&mut u8>,
    is_sign: Option<&mut i32>,
    is_last: &mut i32,
) -> Option<*mut u8> {
    let arcount = u16::from_be(header.arcount);
    let mut ansp = &header as *const DnsHeader as *mut u8;

    if let Some(is_sign) = is_sign {
        *is_sign = 0;

        if (u16::from_be(header.flags) & 0x7800) >> 11 == 0 {
            for _ in 0..u16::from_be(header.qdcount) {
                if skip_name(&mut ansp, header, plen, 4).is_none() {
                    return None;
                }

                let type_ = get_short!(ansp);
                let class = get_short!(ansp);

                if class == C_IN && type_ == T_TKEY {
                    *is_sign = 1;
                }
            }
        }
    } else {
        if skip_questions(header, plen).is_none() {
            return None;
        }
    }

    if arcount == 0 {
        return None;
    }

    if skip_section(ansp, (u16::from_be(header.ancount) + u16::from_be(header.nscount)).into(), header, plen).is_none() {
        return None;
    }

    for i in 0..arcount {
        let save = ansp;
        if skip_name(&mut ansp, header, plen, 10).is_none() {
            return None;
        }

        let type_ = get_short!(ansp);
        let class = get_short!(ansp);
        ansp = &mut ansp[4..]; // TTL
        let rdlen = get_short!(ansp);
        if (header as *const DnsHeader as usize + ansp as usize + rdlen as usize) > plen {
            return None;
        }

        if type_ == T_OPT {
            if len.is_some() {
                len = Some(&(ansp as usize - save as usize));
            }

            if let Some(p) = p {
                *p = class as u8;
            }

            if is_last.is_some() {
                *is_last = if i == arcount - 1 { 1 } else { 0 };
            }

            return Some(save);
        } else if let Some(is_sign) = is_sign {
            if i == arcount - 1 && class == C_ANY && type_ == T_TSIG {
                *is_sign = 1;
            }
        }
    }

    None
}

// Function to add a pseudoheader to a DNS packet
fn add_pseudoheader(
    header: &mut DnsHeader,
    plen: usize,
    limit: &mut u8,
    mut udp_sz: u16,
    optno: u16,
    opt: &[u8],
    optlen: usize,
    set_do: bool,
    replace: bool
) -> usize {
    let mut lenp: Option<&mut u8> = None;
    let mut datap: Option<&mut u8> = None;
    let mut p: *mut u8 = 0 as *mut u8;
    let mut udp_len: Option<&mut u8> = None;
    let mut is_sign = 0;
    let mut is_last = 0;
    let mut buff = [0; 512];
    let flags = if set_do { 0x8000 } else { 0 };
    let mut rcode = 0;

    p = find_pseudoheader(header as *mut _ as *mut u8, plen, None, &mut udp_len, &mut is_sign, &mut is_last).unwrap_or_else(|| header as *mut _);

    if is_sign != 0 {
        return plen;
    }

    if p != 0 as *mut u8 {
        p = udp_len.unwrap_or(p);
        udp_sz = get_short!(p);
        rcode = get_short!(p);
        let flags = get_short!(p);

        if set_do {
            *(p as *mut _ as *mut u16) |= 0x8000;
        }

        lenp = Some(p);

        udplen = get_short!(p);
        if plen >= p as usize + udplen {
            return plen;
        }

        datap = Some(p);

        if optno == 0 {
            return plen;
        }

        let mut i = 0;
        while i + 4 < udplen as usize {
            let code = get_short!(p);
            let len = get_short!(p);

            if i + 4 + len as usize > udplen as usize {
                udplen = 0;
                is_last = 0;
                break;
            }

            if code == optno {
                if !replace {
                    return plen;
                }
                
                // to be continued as per needed logic
            }

            i += 4 + len as usize;
        }

        if limit.offset_from(datap.unwrap() as *const u8) + optlen as isize <= 0 {
            return plen;
        }
        limit = limit.offset(-(p.offset_from(datap.unwrap() as *const u8) + optlen as isize) as isize);

        std::ptr::write(limit, p.add(optlen));
    } else {
        let i = is_last;
        buff[..limit.offset_from(p.offset(14)) as usize].copy_from_slice(&buff[(plen / 2) as usize..]);
        *(udp_len.unwrap() as *mut u16) = plen as u16;
    }

    plen - std::mem::size_of_val(&lenp) + optlen
}

fn main() {
    // Example usage
    let mut header = DnsHeader {
        id: 0,
        flags: 0,
        qdcount: 0,
        ancount: 0,
        nscount: 0,
        arcount: 0,
    };
    let plen = 512; 
    let mut limit: u8 = 0;
   
    let udp_sz = 512;
    let optno = 41;
    let opt = [0];
    let optlen = 1;
    let set_do = false;
    let replace = false;
  
    add_pseudoheader(header, plen, limit, udp_sz, optno, opt, optlen, set_do, replace);
    println!("Executed add_pseudoheader function with provided values.");
}