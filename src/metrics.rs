pub const METRIC_NAMES: [&str; __METRIC_MAX] = [
    "dns_cache_inserted",
    "dns_cache_live_freed",
    "dns_queries_forwarded",
    "dns_auth_answered",
    "dns_local_answered",
    "dns_stale_answered",
    "dns_unanswered",
    "dnssec_max_crypto_use",
    "dnssec_max_sig_fail",
    "dnssec_max_work",
    "bootp",
    "pxe",
    "dhcp_ack",
    "dhcp_decline",
    "dhcp_discover",
    "dhcp_inform",
    "dhcp_nak",
    "dhcp_offer",
    "dhcp_release",
    "dhcp_request",
    "noanswer",
    "leases_allocated_4",
    "leases_pruned_4",
    "leases_allocated_6",
    "leases_pruned_6",
    "tcp_connections",
];

#[repr(usize)]
pub enum Metric {
    DnsCacheInserted = 0,
    DnsCacheLiveFreed,
    DnsQueriesForwarded,
    DnsAuthAnswered,
    DnsLocalAnswered,
    DnsStaleAnswered,
    DnsUnansweredQuery,
    CryptoHwm,
    SigFailHwm,
    WorkHwm,
    Bootp,
    Pxe,
    DhcpAck,
    DhcpDecline,
    DhcpDiscover,
    DhcpInform,
    DhcpNak,
    DhcpOffer,
    DhcpRelease,
    DhcpRequest,
    NoAnswer,
    LeasesAllocated4,
    LeasesPruned4,
    LeasesAllocated6,
    LeasesPruned6,
    TcpConnections,
    MetricMax,
}

pub struct Daemon {
    metrics: [u64; Metric::MetricMax as usize],
    servers: Vec<Server>,
}

pub struct Server {
    queries: u32,
    failed_queries: u32,
    retrys: u32,
    nxdomain_replies: u32,
    query_latency: u32,
}

pub fn get_metric_name(index: Metric) -> &'static str {
    METRIC_NAMES[index as usize]
}

pub fn clear_metrics(daemon: &mut Daemon) {
    for i in 0..Metric::MetricMax as usize {
        daemon.metrics[i] = 0;
    }

    for server in &mut daemon.servers {
        server.queries = 0;
        server.failed_queries = 0;
        server.retrys = 0;
        server.nxdomain_replies = 0;
        server.query_latency = 0;
    }
}

fn main() {
    // Example usage
    let mut daemon = Daemon {
        metrics: [0; Metric::MetricMax as usize],
        servers: vec![
            Server {
                queries: 0,
                failed_queries: 0,
                retrys: 0,
                nxdomain_replies: 0,
                query_latency: 0,
            },
        ],
    };

    clear_metrics(&mut daemon);

    for (i, &metric_name) in METRIC_NAMES.iter().enumerate() {
        println!("Metric {}: {}", i, metric_name);
    }
}