use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

pub enum MySockAddr {
    Sa(SocketAddr),
    In(SocketAddrV4),
    In6(SocketAddrV6),
}
