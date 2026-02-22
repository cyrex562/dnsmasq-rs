/// Runtime metrics counters.
/// Ported from `metrics.h` / `metrics.c`.

use std::sync::atomic::{AtomicU64, Ordering};

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

/// Reset all metric counters to zero.
pub fn clear_metrics() {
    for c in &COUNTERS {
        c.store(0, Ordering::Relaxed);
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
        Metric::DnsUnansweredQuery   => "dns_unanswered_query",
        Metric::CryptoHwm            => "crypto_hwm",
        Metric::SigFailHwm           => "sig_fail_hwm",
        Metric::WorkHwm              => "work_hwm",
        Metric::Bootp                => "bootp",
        Metric::Pxe                  => "pxe",
        Metric::Dhcpack              => "dhcpack",
        Metric::Dhcpdecline          => "dhcpdecline",
        Metric::Dhcpdiscover         => "dhcpdiscover",
        Metric::Dhcpinform           => "dhcpinform",
        Metric::Dhcpnak              => "dhcpnak",
        Metric::Dhcpoffer            => "dhcpoffer",
        Metric::Dhcprelease          => "dhcprelease",
        Metric::Dhcprequest          => "dhcprequest",
        Metric::Noanswer             => "noanswer",
        Metric::LeasesAllocated4     => "leases_allocated_4",
        Metric::LeasesPruned4        => "leases_pruned_4",
        Metric::LeasesAllocated6     => "leases_allocated_6",
        Metric::LeasesPruned6        => "leases_pruned_6",
        Metric::TcpConnections       => "tcp_connections",
        Metric::Dhcpleasequery       => "dhcpleasequery",
        Metric::Dhcpleaseunassigned  => "dhcpleaseunassigned",
        Metric::Dhcpleaseactive      => "dhcpleaseactive",
        Metric::Dhcpleaseunknown     => "dhcpleaseunknown",
        Metric::MetricMax            => "<invalid>",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn increment_and_read() {
        clear_metrics();
        inc_metric(Metric::DnsQueriesForwarded);
        inc_metric(Metric::DnsQueriesForwarded);
        assert_eq!(get_metric(Metric::DnsQueriesForwarded), 2);
        clear_metrics();
        assert_eq!(get_metric(Metric::DnsQueriesForwarded), 0);
    }

    #[test]
    fn metric_names_not_empty() {
        for i in 0..METRIC_COUNT {
            // SAFETY: MetricMax is the sentinel, not a real metric
            let m = unsafe { std::mem::transmute::<usize, Metric>(i) };
            assert!(!metric_name(m).is_empty());
        }
    }
}
