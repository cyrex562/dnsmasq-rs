use std::net::Ipv6Addr;

fn in6_is_addr_ula(a: &Ipv6Addr) -> bool {
    a.segments()[0] & 0xff00 == 0xfd00
}

fn in6_is_addr_ula_zero(a: &Ipv6Addr) -> bool {
    let segments = a.segments();
    segments[0] == 0xfd00 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0 && segments[4] == 0 && segments[5] == 0 && segments[6] == 0 && segments[7] == 0
}

fn in6_is_addr_link_local_zero(a: &Ipv6Addr) -> bool {
    let segments = a.segments();
    segments[0] == 0xfe80 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0 && segments[4] == 0 && segments[5] == 0 && segments[6] == 0 && segments[7] == 0
}

fn main() {
    // Example Usage
    let ip = "::1".parse::<Ipv6Addr>().unwrap();
    println!("Is ULA: {}", in6_is_addr_ula(&ip));
    println!("Is ULA Zero: {}", in6_is_addr_ula_zero(&ip));
    println!("Is Link Local Zero: {}", in6_is_addr_link_local_zero(&ip));

    let ip2 = "fd00::".parse::<Ipv6Addr>().unwrap();
    println!("Is ULA: {}", in6_is_addr_ula(&ip2));
    println!("Is ULA Zero: {}", in6_is_addr_ula_zero(&ip2));
    println!("Is Link Local Zero: {}", in6_is_addr_link_local_zero(&ip2));    
}