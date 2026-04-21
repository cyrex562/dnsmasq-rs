use std::env;
use std::fs;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use dnsmasq_rs::dns_protocol::{DnsHeader, HB3_RD};
use dnsmasq_rs::rfc1035::{DnsPacket, DnsQuestion};

#[derive(Debug)]
struct Config {
    queries: String,
    upstream: SocketAddr,
    candidate: SocketAddr,
    timeout_ms: u64,
}

#[derive(Debug, Clone)]
struct QueryCase {
    name: String,
    qtype: u16,
    qtype_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalizedPacket {
    rcode: u8,
    tc: bool,
    answers: Vec<NormalizedRr>,
    authority: Vec<NormalizedRr>,
    additional: Vec<NormalizedRr>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct NormalizedRr {
    name: String,
    rtype: u16,
    class: u16,
    data: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_args(env::args().skip(1).collect())?;
    let cases = load_queries(&config.queries)?;

    let mut mismatches = 0usize;

    for case in &cases {
        let upstream = query_server(config.upstream, case, config.timeout_ms)?;
        let candidate = query_server(config.candidate, case, config.timeout_ms)?;

        if upstream != candidate {
            mismatches += 1;
            eprintln!("mismatch for {} {}", case.name, case.qtype_name);
            eprintln!("  upstream : {upstream:#?}");
            eprintln!("  candidate: {candidate:#?}");
        } else {
            println!("ok {} {}", case.name, case.qtype_name);
        }
    }

    if mismatches > 0 {
        return Err(format!("{mismatches} parity mismatches detected").into());
    }

    Ok(())
}

fn parse_args(args: Vec<String>) -> Result<Config, Box<dyn std::error::Error>> {
    let mut queries = None;
    let mut upstream = None;
    let mut candidate = None;
    let mut timeout_ms = 2000u64;

    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--queries" => {
                i += 1;
                queries = args.get(i).cloned();
            }
            "--upstream" => {
                i += 1;
                upstream = args.get(i).map(|s| s.parse()).transpose()?;
            }
            "--candidate" => {
                i += 1;
                candidate = args.get(i).map(|s| s.parse()).transpose()?;
            }
            "--timeout-ms" => {
                i += 1;
                timeout_ms = args
                    .get(i)
                    .ok_or("missing value for --timeout-ms")?
                    .parse()?;
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            other => {
                return Err(format!("unknown argument: {other}").into());
            }
        }
        i += 1;
    }

    Ok(Config {
        queries: queries.ok_or("missing --queries")?,
        upstream: upstream.ok_or("missing --upstream")?,
        candidate: candidate.ok_or("missing --candidate")?,
        timeout_ms,
    })
}

fn print_help() {
    println!("parity_probe --queries FILE --upstream HOST:PORT --candidate HOST:PORT [--timeout-ms N]");
}

fn load_queries(path: &str) -> Result<Vec<QueryCase>, Box<dyn std::error::Error>> {
    let text = fs::read_to_string(path)?;
    let mut out = Vec::new();

    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 2 {
            return Err(format!("invalid query line {}: expected '<name> <qtype>'", lineno + 1).into());
        }
        let qtype_name = parts[1].to_ascii_uppercase();
        let qtype = qtype_from_name(&qtype_name)
            .ok_or_else(|| format!("unsupported qtype '{}' on line {}", parts[1], lineno + 1))?;

        out.push(QueryCase {
            name: parts[0].trim_end_matches('.').to_string(),
            qtype,
            qtype_name,
        });
    }

    if out.is_empty() {
        return Err("query file contained no runnable cases".into());
    }

    Ok(out)
}

fn qtype_from_name(name: &str) -> Option<u16> {
    match name {
        "A" => Some(1),
        "NS" => Some(2),
        "CNAME" => Some(5),
        "SOA" => Some(6),
        "PTR" => Some(12),
        "MX" => Some(15),
        "TXT" => Some(16),
        "AAAA" => Some(28),
        "SRV" => Some(33),
        "NAPTR" => Some(35),
        "ANY" => Some(255),
        _ => None,
    }
}

fn query_server(server: SocketAddr, case: &QueryCase, timeout_ms: u64) -> Result<NormalizedPacket, Box<dyn std::error::Error>> {
    let bind_addr = if server.is_ipv4() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    };

    let socket = UdpSocket::bind(bind_addr)?;
    socket.set_read_timeout(Some(Duration::from_millis(timeout_ms)))?;
    socket.set_write_timeout(Some(Duration::from_millis(timeout_ms)))?;

    let mut header = DnsHeader::default();
    header.id = 0x4242;
    header.hb3 = HB3_RD;
    header.qdcount = 1;

    let packet = DnsPacket {
        header,
        questions: vec![DnsQuestion {
            name: case.name.clone(),
            qtype: case.qtype,
            qclass: 1,
        }],
        answers: vec![],
        authority: vec![],
        additional: vec![],
    };

    let wire = packet.write();
    socket.send_to(&wire, server)?;

    let mut buf = [0u8; 4096];
    let (len, _) = socket.recv_from(&mut buf).map_err(|e| {
        io::Error::new(e.kind(), format!("query {} {} to {} failed: {}", case.name, case.qtype_name, server, e))
    })?;

    let packet = DnsPacket::parse(&buf[..len]).map_err(|e| {
        format!("failed to parse reply from {server} for {} {}: {e}", case.name, case.qtype_name)
    })?;

    Ok(normalize_packet(packet))
}

fn normalize_packet(packet: DnsPacket) -> NormalizedPacket {
    let mut answers: Vec<_> = packet.answers.into_iter().map(normalize_rr).collect();
    let mut authority: Vec<_> = packet.authority.into_iter().map(normalize_rr).collect();
    let mut additional: Vec<_> = packet.additional.into_iter().map(normalize_rr).collect();

    answers.sort();
    authority.sort();
    additional.sort();

    NormalizedPacket {
        rcode: packet.header.rcode(),
        tc: packet.header.is_tc(),
        answers,
        authority,
        additional,
    }
}

fn normalize_rr(rr: dnsmasq_rs::rfc1035::DnsRr) -> NormalizedRr {
    NormalizedRr {
        name: rr.name.to_ascii_lowercase(),
        rtype: rr.rtype,
        class: rr.class,
        data: normalize_rdata(rr.rtype, &rr.rdata),
    }
}

fn normalize_rdata(rtype: u16, rdata: &[u8]) -> String {
    match rtype {
        1 if rdata.len() == 4 => Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]).to_string(),
        28 if rdata.len() == 16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(rdata);
            Ipv6Addr::from(octets).to_string()
        }
        2 | 5 | 12 => decode_name_rdata(rdata).unwrap_or_else(|| hex_encode(rdata)),
        15 => normalize_mx_like_rdata(rdata),
        16 => normalize_txt_rdata(rdata),
        _ => hex_encode(rdata),
    }
}

fn decode_name_rdata(rdata: &[u8]) -> Option<String> {
    let mut off = 0usize;
    dnsmasq_rs::rfc1035::extract_name(rdata, &mut off).ok()
}

fn normalize_mx_like_rdata(rdata: &[u8]) -> String {
    if rdata.len() < 2 {
        return hex_encode(rdata);
    }
    let pref = u16::from_be_bytes([rdata[0], rdata[1]]);
    let target = decode_name_rdata(&rdata[2..]).unwrap_or_else(|| hex_encode(&rdata[2..]));
    format!("{pref}:{target}")
}

fn normalize_txt_rdata(rdata: &[u8]) -> String {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < rdata.len() {
        let len = rdata[i] as usize;
        i += 1;
        if i + len > rdata.len() {
            return hex_encode(rdata);
        }
        out.push(String::from_utf8_lossy(&rdata[i..i + len]).to_string());
        i += len;
    }
    out.join("|")
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}
