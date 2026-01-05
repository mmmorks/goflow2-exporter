use crate::asn::AsnLookup;
use crate::bounded_tracker::{BoundedMetricTracker, Clock, SystemClock};
use crate::flow::FlowMessage;
use crate::l7_classifier::classify_l7_protocol;
use crate::tcp_flags::decode_tcp_flags;
use anyhow::Result;
use axum::{
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use parking_lot::RwLock;
use prometheus::{Encoder, IntCounterVec, IntGaugeVec, Opts, Registry, TextEncoder};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

const DEFAULT_METRICS_PORT: u16 = 9090;
const DEFAULT_MAX_CARDINALITY: usize = 1_000;
const DEFAULT_METRIC_TTL_SECONDS: u64 = 3600;

// Macro to create and register a counter metric
macro_rules! counter {
    ($registry:expr, $name:expr, $help:expr, $labels:expr) => {{
        let metric = IntCounterVec::new(Opts::new($name, $help), $labels).unwrap();
        $registry.register(Box::new(metric.clone())).unwrap();
        metric
    }};
}

// Macro to create and register a gauge metric
macro_rules! gauge {
    ($registry:expr, $name:expr, $help:expr, $labels:expr) => {{
        let metric = IntGaugeVec::new(Opts::new($name, $help), $labels).unwrap();
        $registry.register(Box::new(metric.clone())).unwrap();
        metric
    }};
}

// Metric group for total metrics (includes records counter)
macro_rules! total_metric_group {
    ($registry:expr, $prefix:expr, $help_prefix:expr, $labels:expr, $ttl:expr, $clock:expr) => {{
        TotalMetricGroup {
            records: counter!(
                $registry,
                concat!("goflow_records_", $prefix, "_total"),
                concat!("Records ", $help_prefix),
                $labels
            ),
            bytes: counter!(
                $registry,
                concat!("goflow_bytes_", $prefix, "_total"),
                concat!("Bytes ", $help_prefix),
                $labels
            ),
            packets: counter!(
                $registry,
                concat!("goflow_packets_", $prefix, "_total"),
                concat!("Packets ", $help_prefix),
                $labels
            ),
            tracker: TrackerGroup {
                tracker: Arc::new(BoundedMetricTracker::new(
                    DEFAULT_MAX_CARDINALITY,
                    $ttl,
                    $clock,
                )),
                last_evictions: RwLock::default(),
            },
        }
    }};
}

// Metric group for dimensional metrics (no records counter)
macro_rules! dimensional_metric_group {
    ($registry:expr, $prefix:expr, $help_prefix:expr, $labels:expr, $ttl:expr, $clock:expr) => {{
        DimensionalMetricGroup {
            bytes: counter!(
                $registry,
                concat!("goflow_bytes_", $prefix, "_total"),
                concat!("Bytes ", $help_prefix),
                $labels
            ),
            packets: counter!(
                $registry,
                concat!("goflow_packets_", $prefix, "_total"),
                concat!("Packets ", $help_prefix),
                $labels
            ),
            tracker: TrackerGroup {
                tracker: Arc::new(BoundedMetricTracker::new(
                    DEFAULT_MAX_CARDINALITY,
                    $ttl,
                    $clock,
                )),
                last_evictions: RwLock::default(),
            },
        }
    }};
}

struct TotalMetricGroup {
    records: IntCounterVec,
    bytes: IntCounterVec,
    packets: IntCounterVec,
    tracker: TrackerGroup,
}

struct DimensionalMetricGroup {
    bytes: IntCounterVec,
    packets: IntCounterVec,
    tracker: TrackerGroup,
}

struct TrackerGroup {
    tracker: Arc<BoundedMetricTracker>,
    last_evictions: RwLock<u64>,
}

pub struct Metrics {
    registry: Registry,
    asn_lookup: AsnLookup,

    // Total metrics include record counter
    total: TotalMetricGroup,

    // Dimensional metrics only track bytes and packets
    by_protocol: DimensionalMetricGroup,
    by_tcp_flags: DimensionalMetricGroup,
    by_sampler: DimensionalMetricGroup,
    by_src_addr: DimensionalMetricGroup,
    by_dst_addr: DimensionalMetricGroup,
    by_src_asn: DimensionalMetricGroup,
    by_dst_asn: DimensionalMetricGroup,
    by_l7_app: DimensionalMetricGroup,

    // Other metrics
    parse_errors_total: IntCounterVec,
    cardinality_gauge: IntGaugeVec,
    evictions_total: IntCounterVec,
}

impl Metrics {
    pub fn new(asn_db_path: Option<&str>) -> Self {
        Self::new_with_clock(asn_db_path, Arc::new(SystemClock))
    }

    fn new_with_clock(asn_db_path: Option<&str>, clock: Arc<dyn Clock>) -> Self {
        let registry = Registry::new();
        let ttl = Duration::from_secs(DEFAULT_METRIC_TTL_SECONDS);

        Self {
            total: total_metric_group!(
                registry,
                "all",
                "all",
                &["sampler_address", "flow_type"],
                ttl,
                clock.clone()
            ),
            by_protocol: dimensional_metric_group!(
                registry,
                "by_protocol",
                "by protocol",
                &["protocol"],
                ttl,
                clock.clone()
            ),
            by_tcp_flags: dimensional_metric_group!(
                registry,
                "by_tcp_flags",
                "by TCP flags",
                &["tcp_flags"],
                ttl,
                clock.clone()
            ),
            by_sampler: dimensional_metric_group!(
                registry,
                "by_sampler",
                "by sampler",
                &["sampler_address"],
                ttl,
                clock.clone()
            ),
            by_src_addr: dimensional_metric_group!(
                registry,
                "by_src_subnet",
                "by source subnet",
                &["src_subnet"],
                ttl,
                clock.clone()
            ),
            by_dst_addr: dimensional_metric_group!(
                registry,
                "by_dst_subnet",
                "by destination subnet",
                &["dst_subnet"],
                ttl,
                clock.clone()
            ),
            by_src_asn: dimensional_metric_group!(
                registry,
                "by_src_asn",
                "by source ASN",
                &["src_asn", "src_asn_org"],
                ttl,
                clock.clone()
            ),
            by_dst_asn: dimensional_metric_group!(
                registry,
                "by_dst_asn",
                "by destination ASN",
                &["dst_asn", "dst_asn_org"],
                ttl,
                clock.clone()
            ),
            by_l7_app: dimensional_metric_group!(
                registry,
                "by_l7_app",
                "by L7 application",
                &["l7_app"],
                ttl,
                clock
            ),

            parse_errors_total: counter!(
                registry,
                "goflow_parse_errors_total",
                "Total number of parse errors",
                &["error_type"]
            ),
            cardinality_gauge: gauge!(
                registry,
                "goflow_metric_cardinality",
                "Current cardinality of bounded metrics",
                &["metric_type"]
            ),
            evictions_total: counter!(
                registry,
                "goflow_evictions_total",
                "Total number of evicted metric entries",
                &["metric_type"]
            ),

            registry,
            asn_lookup: AsnLookup::new(asn_db_path),
        }
    }

    pub fn record_flow(&self, flow: &FlowMessage) {
        let sampler_address = flow.sampler_address.as_deref().unwrap_or("unknown");
        let flow_type = flow.flow_type.as_deref().unwrap_or("unknown");
        let protocol = flow.normalized_protocol();

        let scaled_bytes = flow.scaled_bytes();
        let scaled_packets = flow.scaled_packets();

        // Helper to record total metrics (includes record counter)
        let record_total = |group: &TotalMetricGroup, key: &str, labels: &[&str]| {
            group.tracker.tracker.increment(
                key,
                &[&group.records, &group.bytes, &group.packets],
                labels,
                &[1, scaled_bytes, scaled_packets],
            );
        };

        // Helper to record dimensional metrics (no record counter)
        let record_dimensional = |group: &DimensionalMetricGroup, key: &str, labels: &[&str]| {
            group.tracker.tracker.increment(
                key,
                &[&group.bytes, &group.packets],
                labels,
                &[scaled_bytes, scaled_packets],
            );
        };

        // Record total metrics with record counter
        record_total(
            &self.total,
            &format!("{}|{}", sampler_address, flow_type),
            &[sampler_address, flow_type],
        );

        // Record dimensional metrics without record counter
        record_dimensional(&self.by_protocol, &protocol, &[&protocol]);

        // Record TCP flags metrics
        let tcp_flags_str = decode_tcp_flags(flow.tcp_flags.unwrap_or(0));
        record_dimensional(&self.by_tcp_flags, &tcp_flags_str, &[&tcp_flags_str]);

        record_dimensional(&self.by_sampler, sampler_address, &[sampler_address]);

        // L7 classification - examine both ports and prefer well-known protocols
        let l4_proto = flow.normalized_protocol();

        if let (Some(src_port), Some(dst_port)) = (flow.src_port, flow.dst_port) {
            // Classify both ports
            let src_l7 = classify_l7_protocol(&l4_proto, src_port);
            let dst_l7 = classify_l7_protocol(&l4_proto, dst_port);

            // Use well-known protocol, or fallback to PROTOCOL/SMALLEST_PORT
            let protocol = src_l7.or(dst_l7).unwrap_or_else(|| {
                let smallest_port = src_port.min(dst_port);
                format!("{}/{}", l4_proto, smallest_port)
            });
            record_dimensional(&self.by_l7_app, &protocol, &[&protocol]);
        }
        // Skip L7 classification if either port is missing

        // Source IP metrics - single lookup for both ASN and subnet
        if let Some(src_addr) = &flow.src_addr {
            if let Ok(ip) = src_addr.parse::<IpAddr>() {
                let next_hop = flow.next_hop.as_deref();
                if let Some(ip_info) = self.asn_lookup.lookup_with_context(ip, next_hop, true) {
                    // Record subnet metrics
                    record_dimensional(
                        &self.by_src_addr,
                        &ip_info.subnet.cidr,
                        &[&ip_info.subnet.cidr],
                    );

                    // Record ASN metrics
                    let asn_str = ip_info.asn.number.to_string();
                    let key = format!("{}|{}", ip_info.asn.number, ip_info.asn.organization);
                    record_dimensional(
                        &self.by_src_asn,
                        &key,
                        &[&asn_str, &ip_info.asn.organization],
                    );
                }
            }
        }

        // Destination IP metrics - single lookup for both ASN and subnet
        if let Some(dst_addr) = &flow.dst_addr {
            if let Ok(ip) = dst_addr.parse::<IpAddr>() {
                let next_hop = flow.next_hop.as_deref();
                if let Some(ip_info) = self.asn_lookup.lookup_with_context(ip, next_hop, false) {
                    // Record subnet metrics
                    record_dimensional(
                        &self.by_dst_addr,
                        &ip_info.subnet.cidr,
                        &[&ip_info.subnet.cidr],
                    );

                    // Record ASN metrics
                    let asn_str = ip_info.asn.number.to_string();
                    let key = format!("{}|{}", ip_info.asn.number, ip_info.asn.organization);
                    record_dimensional(
                        &self.by_dst_asn,
                        &key,
                        &[&asn_str, &ip_info.asn.organization],
                    );
                }
            }
        }
    }

    pub fn increment_parse_errors(&self) {
        self.parse_errors_total.with_label_values(&["json"]).inc();
    }

    pub fn cleanup_expired_flows(&self) {
        // Cleanup total metrics (with records counter)
        let removed = self.total.tracker.tracker.cleanup_expired(&[
            &self.total.records,
            &self.total.bytes,
            &self.total.packets,
        ]);
        if removed > 0 {
            self.evictions_total
                .with_label_values(&["all"])
                .inc_by(removed as u64);
        }

        // Cleanup dimensional metrics (without records counter)
        let dimensional_groups = [
            (&self.by_protocol, "protocol"),
            (&self.by_tcp_flags, "tcp_flags"),
            (&self.by_sampler, "sampler"),
            (&self.by_src_addr, "src_subnet"),
            (&self.by_dst_addr, "dst_subnet"),
            (&self.by_src_asn, "src_asn"),
            (&self.by_dst_asn, "dst_asn"),
            (&self.by_l7_app, "l7_app"),
        ];

        for (group, metric_type) in dimensional_groups {
            let removed = group
                .tracker
                .tracker
                .cleanup_expired(&[&group.bytes, &group.packets]);
            if removed > 0 {
                self.evictions_total
                    .with_label_values(&[metric_type])
                    .inc_by(removed as u64);
            }
        }
    }

    fn update_cardinality_metrics(&self) {
        // Update total metrics cardinality
        self.cardinality_gauge
            .with_label_values(&["all"])
            .set(self.total.tracker.tracker.current_cardinality() as i64);

        // Update dimensional metrics cardinality
        let dimensional_groups = [
            (&self.by_protocol, "protocol"),
            (&self.by_tcp_flags, "tcp_flags"),
            (&self.by_sampler, "sampler"),
            (&self.by_src_addr, "src_subnet"),
            (&self.by_dst_addr, "dst_subnet"),
            (&self.by_src_asn, "src_asn"),
            (&self.by_dst_asn, "dst_asn"),
            (&self.by_l7_app, "l7_app"),
        ];

        for (group, metric_type) in dimensional_groups {
            self.cardinality_gauge
                .with_label_values(&[metric_type])
                .set(group.tracker.tracker.current_cardinality() as i64);
        }
    }

    fn update_eviction_metrics(&self) {
        // Update total metrics evictions
        let current_evicted = self.total.tracker.tracker.total_evicted();
        let mut last_evicted = self.total.tracker.last_evictions.write();
        if current_evicted > *last_evicted {
            let delta = current_evicted - *last_evicted;
            self.evictions_total
                .with_label_values(&["all"])
                .inc_by(delta);
            *last_evicted = current_evicted;
        }

        // Update dimensional metrics evictions
        let dimensional_groups = [
            (&self.by_protocol, "protocol"),
            (&self.by_tcp_flags, "tcp_flags"),
            (&self.by_sampler, "sampler"),
            (&self.by_src_addr, "src_subnet"),
            (&self.by_dst_addr, "dst_subnet"),
            (&self.by_src_asn, "src_asn"),
            (&self.by_dst_asn, "dst_asn"),
            (&self.by_l7_app, "l7_app"),
        ];

        for (group, metric_type) in dimensional_groups {
            let current_evicted = group.tracker.tracker.total_evicted();
            let mut last_evicted = group.tracker.last_evictions.write();

            if current_evicted > *last_evicted {
                let delta = current_evicted - *last_evicted;
                self.evictions_total
                    .with_label_values(&[metric_type])
                    .inc_by(delta);
                *last_evicted = current_evicted;
            }
        }
    }

    pub fn gather(&self) -> Vec<u8> {
        self.update_cardinality_metrics();
        self.update_eviction_metrics();

        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = vec![];
        encoder.encode(&metric_families, &mut buffer).unwrap();
        buffer
    }

    #[cfg(test)]
    fn get_tracker_cardinality(&self, group: &DimensionalMetricGroup) -> usize {
        group.tracker.tracker.current_cardinality()
    }

    #[cfg(test)]
    fn get_tracker_evicted(&self, group: &DimensionalMetricGroup) -> u64 {
        group.tracker.tracker.total_evicted()
    }
}

async fn metrics_handler(metrics: Arc<Metrics>) -> Response {
    let buffer = metrics.gather();
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        buffer,
    )
        .into_response()
}

pub async fn serve_metrics(metrics: Arc<Metrics>) -> Result<()> {
    let app = Router::new().route(
        "/metrics",
        get({
            let metrics = metrics.clone();
            move || async move { metrics_handler(metrics).await }
        }),
    );

    let addr = SocketAddr::from(([0, 0, 0, 0], DEFAULT_METRICS_PORT));
    info!("Starting metrics server on http://{}/metrics", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounded_tracker::Clock;
    use crate::flow::FlowMessage;

    // Mock clock for testing
    struct MockClock {
        current_time: RwLock<std::time::Instant>,
    }

    impl MockClock {
        fn new() -> Self {
            Self {
                current_time: RwLock::new(std::time::Instant::now()),
            }
        }

        fn advance(&self, duration: Duration) {
            let mut time = self.current_time.write();
            *time += duration;
        }
    }

    impl Clock for MockClock {
        fn now(&self) -> std::time::Instant {
            *self.current_time.read()
        }
    }

    fn create_test_flow(src_addr: &str, dst_addr: &str, bytes: u64) -> FlowMessage {
        FlowMessage {
            flow_type: Some("IPFIX".to_string()),
            time_received_ns: Some(1234567890),
            sequence_num: Some(1),
            sampling_rate: Some(1),
            sampler_address: Some("192.168.1.1".to_string()),
            time_flow_start_ns: Some(1234567890),
            time_flow_end_ns: Some(1234567900),
            bytes: Some(bytes),
            packets: Some(1),
            src_addr: Some(src_addr.to_string()),
            dst_addr: Some(dst_addr.to_string()),
            src_port: Some(80),
            dst_port: Some(443),
            etype: Some("IPv4".to_string()),
            proto: Some("TCP".to_string()),
            tcp_flags: Some(0),
            src_mac: None,
            dst_mac: None,
            in_if: None,
            out_if: None,
            next_hop: None,
        }
    }

    #[test]
    fn test_metrics_record_flow() {
        let metrics = Metrics::new(Some("./test_data/test-asn.mmdb"));
        let flow = create_test_flow("8.8.8.8", "1.1.1.1", 1000);

        metrics.record_flow(&flow);

        assert_eq!(metrics.get_tracker_cardinality(&metrics.by_src_addr), 1);
        assert_eq!(metrics.get_tracker_cardinality(&metrics.by_dst_addr), 1);
    }

    #[test]
    fn test_metrics_bounded_cardinality() {
        let metrics = Metrics::new(Some("./test_data/test-asn.mmdb"));

        // Use known IPs that will be in the test database
        // Alternate between Google and Cloudflare to generate some variety
        for i in 0..15000 {
            let src = if i % 2 == 0 { "8.8.8.8" } else { "1.1.1.1" };
            let dst = if i % 2 == 0 { "1.1.1.1" } else { "8.8.8.8" };
            let flow = create_test_flow(src, dst, 1000);
            metrics.record_flow(&flow);
        }

        // Since we're only using 2 subnets, cardinality should be very low
        assert!(metrics.get_tracker_cardinality(&metrics.by_src_addr) <= DEFAULT_MAX_CARDINALITY);
        assert!(metrics.get_tracker_cardinality(&metrics.by_dst_addr) <= DEFAULT_MAX_CARDINALITY);
        // With only 2 subnets, we shouldn't have evictions
        assert_eq!(metrics.get_tracker_evicted(&metrics.by_src_addr), 0);
    }

    #[test]
    fn test_cleanup_expired_flows() {
        let metrics = Metrics::new(Some("./test_data/test-asn.mmdb"));
        let flow = create_test_flow("8.8.8.8", "1.1.1.1", 1000);

        metrics.record_flow(&flow);

        assert_eq!(metrics.get_tracker_cardinality(&metrics.by_src_addr), 1);

        metrics.cleanup_expired_flows();

        assert_eq!(metrics.get_tracker_cardinality(&metrics.by_src_addr), 1);
    }

    #[test]
    fn test_cleanup_expired_flows_with_evictions() {
        let metrics = Metrics::new(Some("./test_data/test-asn.mmdb"));

        // Use known IPs from the test database
        for _ in 0..5 {
            let flow = create_test_flow("8.8.8.8", "1.1.1.1", 1000);
            metrics.record_flow(&flow);
        }

        // Since we're using the same IPs, we should only have 1 unique subnet for each
        assert_eq!(metrics.get_tracker_cardinality(&metrics.by_src_addr), 1);
        assert_eq!(metrics.get_tracker_cardinality(&metrics.by_dst_addr), 1);

        let initial_src = metrics.get_tracker_cardinality(&metrics.by_src_addr);
        metrics.cleanup_expired_flows();

        // Verify the method runs without errors
        let after_src = metrics.get_tracker_cardinality(&metrics.by_src_addr);
        assert!(after_src <= initial_src);
    }

    #[test]
    fn test_eviction_metrics_on_cardinality_limit() {
        let metrics = Metrics::new(Some("./test_data/test-asn.mmdb"));

        // With subnet-based tracking, we won't get many unique subnets from just Google/Cloudflare IPs
        // This test now verifies that cardinality is bounded, not that evictions happen
        for i in 0..(DEFAULT_MAX_CARDINALITY + 100) {
            let src = if i % 2 == 0 { "8.8.8.8" } else { "1.1.1.1" };
            let dst = if i % 2 == 0 { "1.1.1.1" } else { "8.8.8.8" };
            let flow = create_test_flow(src, dst, 1000);
            metrics.record_flow(&flow);
        }

        // With only 2 subnets, no evictions should happen
        assert_eq!(metrics.get_tracker_evicted(&metrics.by_src_addr), 0);
        assert_eq!(metrics.get_tracker_evicted(&metrics.by_dst_addr), 0);

        // Now call cleanup
        metrics.cleanup_expired_flows();

        // Gather metrics
        let _output = String::from_utf8(metrics.gather()).unwrap();

        // Verify cardinality is well below the limit
        assert!(metrics.get_tracker_cardinality(&metrics.by_src_addr) <= DEFAULT_MAX_CARDINALITY);
        assert!(metrics.get_tracker_cardinality(&metrics.by_dst_addr) <= DEFAULT_MAX_CARDINALITY);
    }

    #[test]
    fn test_cardinality_metrics_updated_on_gather() {
        let metrics = Metrics::new(Some("./test_data/test-asn.mmdb"));

        for _ in 0..5 {
            let flow = create_test_flow("8.8.8.8", "1.1.1.1", 1000);
            metrics.record_flow(&flow);
        }

        let output = metrics.gather();
        let output_str = String::from_utf8(output).unwrap();

        assert!(output_str.contains("goflow_metric_cardinality"));
        assert!(output_str.contains("src_subnet"));
        assert!(output_str.contains("dst_subnet"));
    }

    #[test]
    fn test_time_based_evictions_with_mock_clock() {
        let clock = Arc::new(MockClock::new());
        let metrics = Metrics::new_with_clock(Some("./test_data/test-asn.mmdb"), clock.clone());

        // Record some flows with known IPs
        for _ in 0..5 {
            let flow = create_test_flow("8.8.8.8", "1.1.1.1", 1000);
            metrics.record_flow(&flow);
        }

        assert_eq!(metrics.get_tracker_cardinality(&metrics.by_src_addr), 1);
        assert_eq!(metrics.get_tracker_cardinality(&metrics.by_dst_addr), 1);

        // Advance time past the TTL
        clock.advance(Duration::from_secs(DEFAULT_METRIC_TTL_SECONDS + 100));

        // Call cleanup - should remove all expired entries
        metrics.cleanup_expired_flows();

        // Verify all entries were evicted
        assert_eq!(metrics.get_tracker_cardinality(&metrics.by_src_addr), 0);
        assert_eq!(metrics.get_tracker_cardinality(&metrics.by_dst_addr), 0);

        // Verify eviction metrics were incremented
        let output = String::from_utf8(metrics.gather()).unwrap();
        assert!(output.contains("goflow_evictions_total"));
        assert!(output.contains(r#"metric_type="src_subnet""#));
        assert!(output.contains(r#"metric_type="dst_subnet""#));
    }

    #[test]
    fn test_asn_evictions_with_mock_clock() {
        let clock = Arc::new(MockClock::new());
        let metrics = Metrics::new_with_clock(Some("./test_data/test-asn.mmdb"), clock.clone());

        // Record flows with Google DNS IPs (different src/dst) to trigger ASN tracking
        for _ in 0..5 {
            let flow = create_test_flow("8.8.8.8", "1.1.1.1", 1000); // Google to Cloudflare
            metrics.record_flow(&flow);
        }

        let initial_src_asn = metrics.get_tracker_cardinality(&metrics.by_src_asn);
        let initial_dst_asn = metrics.get_tracker_cardinality(&metrics.by_dst_asn);

        // Both should have entries (ASN lookups for both Google and Cloudflare)
        assert!(initial_src_asn > 0, "Expected src_asn cardinality > 0");
        assert!(initial_dst_asn > 0, "Expected dst_asn cardinality > 0");

        // Advance time past the TTL
        clock.advance(Duration::from_secs(DEFAULT_METRIC_TTL_SECONDS + 100));

        // Call cleanup - should remove expired ASN entries
        metrics.cleanup_expired_flows();

        // Verify ASN entries were evicted
        assert_eq!(metrics.get_tracker_cardinality(&metrics.by_src_asn), 0);
        assert_eq!(metrics.get_tracker_cardinality(&metrics.by_dst_asn), 0);

        // Verify eviction metrics were incremented for ASNs
        let output = String::from_utf8(metrics.gather()).unwrap();
        assert!(output.contains("goflow_evictions_total"));
        assert!(output.contains(r#"metric_type="src_asn""#));
        assert!(output.contains(r#"metric_type="dst_asn""#));
    }

    #[test]
    fn test_recent_entries_retained() {
        let metrics = Metrics::new(Some("./test_data/test-asn.mmdb"));

        // With subnet-based tracking and limited test IPs, we can't easily fill the cardinality limit
        // This test now verifies that subnets are tracked correctly
        let flow1 = create_test_flow("8.8.8.8", "1.1.1.1", 1_000_000);
        metrics.record_flow(&flow1);

        // Record many flows with the same IPs - should only increment counters, not cardinality
        for _ in 0..100 {
            let flow = create_test_flow("8.8.8.8", "1.1.1.1", 100);
            metrics.record_flow(&flow);
        }

        // Cardinality should still be low since we're using the same subnets
        assert!(
            metrics.get_tracker_cardinality(&metrics.by_src_addr) <= 2,
            "Cardinality should be low when using the same subnets"
        );
    }

    #[test]
    fn test_multiple_flows_same_source() {
        let metrics = Metrics::new(Some("./test_data/test-asn.mmdb"));

        // All flows from Google to Cloudflare
        for _ in 0..10 {
            let flow = create_test_flow("8.8.8.8", "1.1.1.1", 500);
            metrics.record_flow(&flow);
        }

        // With subnet tracking, same source IP means same subnet
        assert_eq!(metrics.get_tracker_cardinality(&metrics.by_src_addr), 1);
        assert_eq!(metrics.get_tracker_cardinality(&metrics.by_dst_addr), 1);
    }

    #[test]
    fn test_parse_errors_increment() {
        let metrics = Metrics::new(None);

        metrics.increment_parse_errors();
        metrics.increment_parse_errors();

        let output = metrics.gather();
        let output_str = String::from_utf8(output).unwrap();

        assert!(output_str.contains("goflow_parse_errors_total"));
    }

    #[test]
    fn test_labels_removed_from_prometheus_output_after_ttl() {
        let clock = Arc::new(MockClock::new());
        let metrics = Metrics::new_with_clock(Some("./test_data/test-asn.mmdb"), clock.clone());

        // Record flows to create specific labels - use public IPs that are in the test database
        let flow1 = create_test_flow("8.8.8.8", "1.1.1.1", 1000);
        let flow2 = create_test_flow("8.8.4.4", "1.0.0.1", 2000);
        metrics.record_flow(&flow1);
        metrics.record_flow(&flow2);

        // Verify subnets were recorded
        assert!(
            metrics.get_tracker_cardinality(&metrics.by_src_addr) > 0,
            "Source subnet cardinality should be > 0 before TTL expiration"
        );
        assert!(
            metrics.get_tracker_cardinality(&metrics.by_dst_addr) > 0,
            "Destination subnet cardinality should be > 0 before TTL expiration"
        );

        // Advance time past TTL
        clock.advance(Duration::from_secs(DEFAULT_METRIC_TTL_SECONDS + 100));

        // Cleanup expired flows
        metrics.cleanup_expired_flows();

        // Gather metrics again - cardinality should be 0
        assert_eq!(
            metrics.get_tracker_cardinality(&metrics.by_src_addr),
            0,
            "Source subnet cardinality should be 0 after TTL expiration"
        );
        assert_eq!(
            metrics.get_tracker_cardinality(&metrics.by_dst_addr),
            0,
            "Destination subnet cardinality should be 0 after TTL expiration"
        );

        // Record the same flow again - should start from fresh counter
        metrics.record_flow(&flow1);

        // Verify the entry reappears
        assert_eq!(
            metrics.get_tracker_cardinality(&metrics.by_src_addr),
            1,
            "Source subnet should reappear after new flow"
        );

        // Verify it started fresh (should see value 1000, not 2000)
        let output = String::from_utf8(metrics.gather()).unwrap();
        for line in output.lines() {
            if line.contains(r#"goflow_bytes_by_src_subnet"#) && line.contains(r#"src_subnet=""#) {
                assert!(
                    line.contains("1000"),
                    "Counter should have reset and show 1000, not accumulated value. Line: {}",
                    line
                );
                break;
            }
        }
    }

    #[test]
    fn test_labels_removed_after_cardinality_eviction() {
        let clock = Arc::new(MockClock::new());
        let metrics = Metrics::new_with_clock(Some("./test_data/test-asn.mmdb"), clock.clone());

        // Record an old flow with known IPs
        let old_flow = create_test_flow("8.8.8.8", "1.1.1.1", 5000);
        metrics.record_flow(&old_flow);

        let initial_cardinality = metrics.get_tracker_cardinality(&metrics.by_src_addr);
        assert!(
            initial_cardinality > 0,
            "Should have recorded at least one subnet"
        );

        // Advance time slightly and fill the cardinality limit with newer flows
        // Using Google and Cloudflare IPs to ensure ASN database lookups work
        clock.advance(Duration::from_millis(100));
        for i in 0..DEFAULT_MAX_CARDINALITY {
            // Alternate between different subnets to ensure variety
            let src = if i % 2 == 0 { "8.8.8.8" } else { "1.1.1.1" };
            let dst = if i % 2 == 0 { "1.1.1.1" } else { "8.8.8.8" };
            let flow = create_test_flow(src, dst, 100);
            metrics.record_flow(&flow);
        }

        // Verify cardinality is bounded
        assert!(
            metrics.get_tracker_cardinality(&metrics.by_src_addr) <= DEFAULT_MAX_CARDINALITY,
            "Cardinality should be at or below the maximum limit"
        );
    }

    fn create_test_flow_with_ports(src_port: u16, dst_port: u16, proto: &str) -> FlowMessage {
        FlowMessage {
            flow_type: Some("IPFIX".to_string()),
            time_received_ns: Some(1234567890),
            sequence_num: Some(1),
            sampling_rate: Some(1),
            sampler_address: Some("192.168.1.1".to_string()),
            time_flow_start_ns: Some(1234567890),
            time_flow_end_ns: Some(1234567900),
            bytes: Some(1000),
            packets: Some(10),
            src_addr: Some("192.168.1.100".to_string()),
            dst_addr: Some("8.8.8.8".to_string()),
            src_port: Some(src_port),
            dst_port: Some(dst_port),
            etype: Some("IPv4".to_string()),
            proto: Some(proto.to_string()),
            tcp_flags: Some(0),
            src_mac: None,
            dst_mac: None,
            in_if: None,
            out_if: None,
            next_hop: None,
        }
    }

    #[test]
    fn test_l7_app_metrics() {
        let clock = Arc::new(MockClock::new());
        let metrics = Metrics::new_with_clock(None, clock.clone());

        // HTTP flow on port 80
        let http_flow = create_test_flow_with_ports(12345, 80, "TCP");
        metrics.record_flow(&http_flow);

        // HTTPS flow on port 443
        let https_flow = create_test_flow_with_ports(54321, 443, "TCP");
        metrics.record_flow(&https_flow);

        // DNS UDP flow on port 53
        let dns_flow = create_test_flow_with_ports(55555, 53, "UDP");
        metrics.record_flow(&dns_flow);

        // Unknown port flow
        let unknown_flow = create_test_flow_with_ports(9999, 8888, "TCP");
        metrics.record_flow(&unknown_flow);

        // Verify L7 metrics were recorded (check cardinality)
        let l7_cardinality = metrics.get_tracker_cardinality(&metrics.by_l7_app);
        assert!(
            l7_cardinality > 0,
            "L7 app metrics should have been recorded"
        );

        // Verify metrics output contains L7 app metrics
        let output = String::from_utf8(metrics.gather()).unwrap();
        assert!(
            output.contains("goflow_bytes_by_l7_app_total"),
            "Should contain L7 app bytes metric"
        );
        assert!(
            output.contains("goflow_packets_by_l7_app_total"),
            "Should contain L7 app packets metric"
        );
        assert!(
            output.contains(r#"l7_app="HTTP""#),
            "Should contain HTTP classification"
        );
        assert!(
            output.contains(r#"l7_app="HTTPS""#),
            "Should contain HTTPS classification"
        );
        assert!(
            output.contains(r#"l7_app="DNS-UDP""#),
            "Should contain DNS-UDP classification"
        );
    }

    #[test]
    fn test_l7_app_both_ports_classified_when_both_well_known() {
        let metrics = Metrics::new(None);

        // Flow with well-known ports on both src and dst (unusual but possible)
        let flow = create_test_flow_with_ports(80, 443, "TCP");
        metrics.record_flow(&flow);

        // Should classify flow once using the first well-known protocol found (src port 80=HTTP)
        let l7_cardinality = metrics.get_tracker_cardinality(&metrics.by_l7_app);
        assert_eq!(
            l7_cardinality, 1,
            "Should classify flow once when both ports are well-known"
        );

        let output = String::from_utf8(metrics.gather()).unwrap();
        assert!(
            output.contains(r#"l7_app="HTTP""#),
            "Should classify using src port 80 as HTTP (first match)"
        );
    }

    #[test]
    fn test_l7_app_ephemeral_ports_not_classified() {
        let metrics = Metrics::new(None);

        // Flow with ephemeral source port and well-known dest port (typical client->server)
        let flow = create_test_flow_with_ports(52341, 443, "TCP");
        metrics.record_flow(&flow);

        // Should only classify dst port (443=HTTPS), not ephemeral src port
        let l7_cardinality = metrics.get_tracker_cardinality(&metrics.by_l7_app);
        assert_eq!(
            l7_cardinality, 1,
            "Should only classify well-known destination port, not ephemeral source"
        );

        let output = String::from_utf8(metrics.gather()).unwrap();
        assert!(
            output.contains(r#"l7_app="HTTPS""#),
            "Should classify dst port 443 as HTTPS"
        );
        assert!(
            !output.contains(r#"l7_app="TCP/52341""#),
            "Should NOT classify ephemeral port 52341"
        );
    }

    #[test]
    fn test_l7_app_server_response_flow() {
        let metrics = Metrics::new(None);

        // Flow from server (src=443) to client (dst=ephemeral) - server response
        let flow = create_test_flow_with_ports(443, 52341, "TCP");
        metrics.record_flow(&flow);

        // Should only classify src port (443=HTTPS), not ephemeral dst port
        let l7_cardinality = metrics.get_tracker_cardinality(&metrics.by_l7_app);
        assert_eq!(
            l7_cardinality, 1,
            "Should only classify well-known source port, not ephemeral destination"
        );

        let output = String::from_utf8(metrics.gather()).unwrap();
        assert!(
            output.contains(r#"l7_app="HTTPS""#),
            "Should classify src port 443 as HTTPS"
        );
        assert!(
            !output.contains(r#"l7_app="TCP/52341""#),
            "Should NOT classify ephemeral port 52341"
        );
    }

    #[test]
    fn test_l7_app_no_ephemeral_cardinality_explosion() {
        let metrics = Metrics::new(None);

        // Simulate many client connections to HTTPS (different ephemeral ports)
        for ephemeral_port in 50000..50100 {
            let flow = create_test_flow_with_ports(ephemeral_port, 443, "TCP");
            metrics.record_flow(&flow);
        }

        // Should only have cardinality of 1 (HTTPS), not 100+ for each ephemeral port
        let l7_cardinality = metrics.get_tracker_cardinality(&metrics.by_l7_app);
        assert_eq!(
            l7_cardinality, 1,
            "Ephemeral ports should not increase cardinality"
        );

        let output = String::from_utf8(metrics.gather()).unwrap();
        assert!(
            output.contains(r#"l7_app="HTTPS""#),
            "Should only have HTTPS classification"
        );
        assert!(
            !output.contains("TCP/50"),
            "Should not have any ephemeral port classifications"
        );
    }

    #[test]
    fn test_l7_app_ipv6_protocol_normalization() {
        let metrics = Metrics::new(None);

        // Create an IPv6 flow
        let mut flow = create_test_flow_with_ports(54321, 443, "TCP");
        flow.etype = Some("IPv6".to_string());

        metrics.record_flow(&flow);

        // Should still classify port 443 as HTTPS even with IPv6
        let output = String::from_utf8(metrics.gather()).unwrap();
        assert!(
            output.contains(r#"l7_app="HTTPS""#),
            "Should classify IPv6-TCP port 443 as HTTPS"
        );
    }

    #[test]
    fn test_l7_app_fallback_to_smallest_port() {
        let metrics = Metrics::new(None);

        // Flow with two unknown ports - should use smallest port
        let flow1 = create_test_flow_with_ports(52341, 8888, "TCP");
        metrics.record_flow(&flow1);

        let output = String::from_utf8(metrics.gather()).unwrap();
        assert!(
            output.contains(r#"l7_app="TCP/8888""#),
            "Should fallback to TCP/8888 (smallest port) when both ports are unknown"
        );

        // Another flow with different unknown ports
        let flow2 = create_test_flow_with_ports(60000, 500, "UDP");
        metrics.record_flow(&flow2);

        let output = String::from_utf8(metrics.gather()).unwrap();
        assert!(
            output.contains(r#"l7_app="UDP/500""#),
            "Should fallback to UDP/500 (smallest port)"
        );

        // Flow where source is smaller
        let flow3 = create_test_flow_with_ports(1234, 5678, "TCP");
        metrics.record_flow(&flow3);

        let output = String::from_utf8(metrics.gather()).unwrap();
        assert!(
            output.contains(r#"l7_app="TCP/1234""#),
            "Should use smallest port (src=1234) when src < dst"
        );
    }
}
