/// Runtime metrics counters.
/// Ported from `metrics.h` / `metrics.c`.

use std::sync::atomic::{AtomicU64, Ordering};
use crate::types::daemon::Daemon;

/// Index enum for all tracked metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    Dhcpack,
    Dhcpdecline,
    Dhcpdiscover,
    Dhcpinform,
    Dhcpnak,
    Dhcpoffer,
    Dhcprelease,
    Dhcprequest,
    Noanswer,
    LeasesAllocated4,
    LeasesPruned4,
    LeasesAllocated6,
    LeasesPruned6,
    TcpConnections,
    Dhcpleasequery,
    Dhcpleaseunassigned,
    Dhcpleaseactive,
    Dhcpleaseunknown,
    // sentinel — keep last
    MetricMax,
}

const METRIC_COUNT: usize = Metric::MetricMax as usize;

static COUNTERS: [AtomicU64; METRIC_COUNT] = {
    // const initializer trick for array of AtomicU64
    const ZERO: AtomicU64 = AtomicU64::new(0);
    [ZERO; METRIC_COUNT]
};

/// Increment a metric counter by 1.
pub fn inc_metric(m: Metric) {
    COUNTERS[m as usize].fetch_add(1, Ordering::Relaxed);
}

/// Read the current value of a metric counter.
pub fn get_metric(m: Metric) -> u64 {
    COUNTERS[m as usize].load(Ordering::Relaxed)
}

/// Every tracked metric except the `MetricMax` sentinel, for callers that
/// need to enumerate all of them (DBus's `GetMetrics`, UBus's `metrics` RPC,
/// the Prometheus `/metrics` endpoint). `Metric` doesn't derive an
/// iteration helper, so this is the one hand-maintained list — keep it in
/// sync whenever a variant is added or removed.
pub const ALL_METRICS: &[Metric] = {
    use Metric::*;
    &[
        DnsCacheInserted, DnsCacheLiveFreed, DnsQueriesForwarded, DnsAuthAnswered,
        DnsLocalAnswered, DnsStaleAnswered, DnsUnansweredQuery, CryptoHwm, SigFailHwm, WorkHwm,
        Bootp, Pxe, Dhcpack, Dhcpdecline, Dhcpdiscover, Dhcpinform, Dhcpnak, Dhcpoffer,
        Dhcprelease, Dhcprequest, Noanswer, LeasesAllocated4, LeasesPruned4, LeasesAllocated6,
        LeasesPruned6, TcpConnections, Dhcpleasequery, Dhcpleaseunassigned, Dhcpleaseactive,
        Dhcpleaseunknown,
    ]
};

/// Reset all metric counters to zero, including per-server statistics.
pub fn clear_metrics(daemon: &mut Daemon) {
    for c in &COUNTERS {
        c.store(0, Ordering::Relaxed);
    }

    for serv in &mut daemon.servers {
        serv.queries = 0;
        serv.failed_queries = 0;
        serv.retrys = 0;
        serv.nxdomain_replies = 0;
        serv.query_latency = 0;
    }
}

/// Human-readable name for a metric (mirrors `get_metric_name()` in metrics.c).
pub fn metric_name(m: Metric) -> &'static str {
    match m {
        Metric::DnsCacheInserted     => "dns_cache_inserted",
        Metric::DnsCacheLiveFreed    => "dns_cache_live_freed",
        Metric::DnsQueriesForwarded  => "dns_queries_forwarded",
        Metric::DnsAuthAnswered      => "dns_auth_answered",
        Metric::DnsLocalAnswered     => "dns_local_answered",
        Metric::DnsStaleAnswered     => "dns_stale_answered",
        Metric::DnsUnansweredQuery   => "dns_unanswered",
        Metric::CryptoHwm            => "dnssec_max_crypto_use",
        Metric::SigFailHwm           => "dnssec_max_sig_fail",
        Metric::WorkHwm              => "dnssec_max_work",
        Metric::Bootp                => "bootp",
        Metric::Pxe                  => "pxe",
        Metric::Dhcpack              => "dhcp_ack",
        Metric::Dhcpdecline          => "dhcp_decline",
        Metric::Dhcpdiscover         => "dhcp_discover",
        Metric::Dhcpinform           => "dhcp_inform",
        Metric::Dhcpnak              => "dhcp_nak",
        Metric::Dhcpoffer            => "dhcp_offer",
        Metric::Dhcprelease          => "dhcp_release",
        Metric::Dhcprequest          => "dhcp_request",
        Metric::Noanswer             => "noanswer",
        Metric::LeasesAllocated4     => "leases_allocated_4",
        Metric::LeasesPruned4        => "leases_pruned_4",
        Metric::LeasesAllocated6     => "leases_allocated_6",
        Metric::LeasesPruned6        => "leases_pruned_6",
        Metric::TcpConnections       => "tcp_connections",
        Metric::Dhcpleasequery       => "dhcp_leasequery",
        Metric::Dhcpleaseunassigned  => "dhcp_lease_unassigned",
        Metric::Dhcpleaseactive      => "dhcp_lease_actve",
        Metric::Dhcpleaseunknown     => "dhcp_lease_unknown",
        Metric::MetricMax            => "<invalid>",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::daemon::Daemon;
    use crate::types::server::Server;
    use crate::types::addr::MySockAddr;

    #[test]
    fn increment_and_read() {
        let mut daemon = Daemon::default();
        clear_metrics(&mut daemon);
        inc_metric(Metric::DnsQueriesForwarded);
        inc_metric(Metric::DnsQueriesForwarded);
        assert_eq!(get_metric(Metric::DnsQueriesForwarded), 2);
        clear_metrics(&mut daemon);
        assert_eq!(get_metric(Metric::DnsQueriesForwarded), 0);
    }

    #[test]
    fn clear_per_server_stats() {
        use std::net::{SocketAddrV4, Ipv4Addr};

        let mut daemon = Daemon::default();
        let mut server = Server {
            flags: crate::types::server::ServFlags::empty(),
            domain: String::new(),
            addr: MySockAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 53)),
            source_addr: MySockAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 0)),
            interface: String::new(),
            ifindex: 0,
            queries: 10,
            failed_queries: 5,
            nxdomain_replies: 3,
            retrys: 2,
            query_latency: 100,
            mma_latency: 0,
            forwardtime: None,
            forwardcount: 0,
            tcpfd: -1,
            serial: 0,
            arrayposn: 0,
            last_server: -1,
            #[cfg(feature = "loop")]
            uid: 0,
        };
        daemon.servers.push(server);

        clear_metrics(&mut daemon);

        assert_eq!(daemon.servers[0].queries, 0);
        assert_eq!(daemon.servers[0].failed_queries, 0);
        assert_eq!(daemon.servers[0].nxdomain_replies, 0);
        assert_eq!(daemon.servers[0].retrys, 0);
        assert_eq!(daemon.servers[0].query_latency, 0);
    }

    #[test]
    fn metric_labels_match_upstream() {
        assert_eq!(metric_name(Metric::DnsCacheInserted), "dns_cache_inserted");
        assert_eq!(metric_name(Metric::DnsCacheLiveFreed), "dns_cache_live_freed");
        assert_eq!(metric_name(Metric::DnsQueriesForwarded), "dns_queries_forwarded");
        assert_eq!(metric_name(Metric::DnsAuthAnswered), "dns_auth_answered");
        assert_eq!(metric_name(Metric::DnsLocalAnswered), "dns_local_answered");
        assert_eq!(metric_name(Metric::DnsStaleAnswered), "dns_stale_answered");
        assert_eq!(metric_name(Metric::DnsUnansweredQuery), "dns_unanswered");
        assert_eq!(metric_name(Metric::CryptoHwm), "dnssec_max_crypto_use");
        assert_eq!(metric_name(Metric::SigFailHwm), "dnssec_max_sig_fail");
        assert_eq!(metric_name(Metric::WorkHwm), "dnssec_max_work");
        assert_eq!(metric_name(Metric::Bootp), "bootp");
        assert_eq!(metric_name(Metric::Pxe), "pxe");
        assert_eq!(metric_name(Metric::Dhcpack), "dhcp_ack");
        assert_eq!(metric_name(Metric::Dhcpdecline), "dhcp_decline");
        assert_eq!(metric_name(Metric::Dhcpdiscover), "dhcp_discover");
        assert_eq!(metric_name(Metric::Dhcpinform), "dhcp_inform");
        assert_eq!(metric_name(Metric::Dhcpnak), "dhcp_nak");
        assert_eq!(metric_name(Metric::Dhcpoffer), "dhcp_offer");
        assert_eq!(metric_name(Metric::Dhcprelease), "dhcp_release");
        assert_eq!(metric_name(Metric::Dhcprequest), "dhcp_request");
        assert_eq!(metric_name(Metric::Noanswer), "noanswer");
        assert_eq!(metric_name(Metric::LeasesAllocated4), "leases_allocated_4");
        assert_eq!(metric_name(Metric::LeasesPruned4), "leases_pruned_4");
        assert_eq!(metric_name(Metric::LeasesAllocated6), "leases_allocated_6");
        assert_eq!(metric_name(Metric::LeasesPruned6), "leases_pruned_6");
        assert_eq!(metric_name(Metric::TcpConnections), "tcp_connections");
        assert_eq!(metric_name(Metric::Dhcpleasequery), "dhcp_leasequery");
        assert_eq!(metric_name(Metric::Dhcpleaseunassigned), "dhcp_lease_unassigned");
        assert_eq!(metric_name(Metric::Dhcpleaseactive), "dhcp_lease_actve");
        assert_eq!(metric_name(Metric::Dhcpleaseunknown), "dhcp_lease_unknown");
    }
}
