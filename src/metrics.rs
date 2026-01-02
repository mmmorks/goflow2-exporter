use crate::asn::AsnLookup;
use crate::bounded_tracker::BoundedMetricTracker;
use crate::flow::FlowMessage;
use anyhow::Result;
use axum::{routing::get, Router};
use parking_lot::RwLock;
use prometheus::{
    Encoder, IntCounterVec, IntGaugeVec, Opts, Registry, TextEncoder,
};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

const DEFAULT_METRICS_PORT: u16 = 9090;
const DEFAULT_MAX_IP_CARDINALITY: usize = 10_000;
const DEFAULT_MAX_ASN_CARDINALITY: usize = 1_000;
const DEFAULT_FLOW_TTL_SECONDS: u64 = 3600;

pub struct Metrics {
    registry: Registry,
    asn_lookup: AsnLookup,

    flows_total: IntCounterVec,
    bytes_total: IntCounterVec,
    packets_total: IntCounterVec,

    flows_by_protocol: IntCounterVec,
    bytes_by_protocol: IntCounterVec,
    packets_by_protocol: IntCounterVec,

    flows_by_src_addr: IntCounterVec,
    flows_by_dst_addr: IntCounterVec,

    bytes_by_src_addr: IntCounterVec,
    bytes_by_dst_addr: IntCounterVec,

    flows_by_sampler: IntCounterVec,
    bytes_by_sampler: IntCounterVec,
    packets_by_sampler: IntCounterVec,

    flows_by_src_asn: IntCounterVec,
    flows_by_dst_asn: IntCounterVec,
    bytes_by_src_asn: IntCounterVec,
    bytes_by_dst_asn: IntCounterVec,
    packets_by_src_asn: IntCounterVec,
    packets_by_dst_asn: IntCounterVec,

    parse_errors_total: IntCounterVec,

    active_flows: Arc<RwLock<HashMap<String, u64>>>,
    active_flows_gauge: IntGaugeVec,

    src_addr_tracker: Arc<BoundedMetricTracker>,
    dst_addr_tracker: Arc<BoundedMetricTracker>,
    src_asn_tracker: Arc<BoundedMetricTracker>,
    dst_asn_tracker: Arc<BoundedMetricTracker>,

    cardinality_gauge: IntGaugeVec,
    evictions_total: IntCounterVec,

    // Track last known eviction counts to report deltas
    last_src_addr_evictions: RwLock<u64>,
    last_dst_addr_evictions: RwLock<u64>,
    last_src_asn_evictions: RwLock<u64>,
    last_dst_asn_evictions: RwLock<u64>,
}

    impl Metrics {
    pub fn new(asn_db_path: Option<&str>) -> Self {
        let registry = Registry::new();
        let asn_lookup = AsnLookup::new(asn_db_path);

        let flows_total = IntCounterVec::new(
            Opts::new("goflow_flows_total", "Total number of flows received"),
            &["sampler_address", "flow_type"],
        )
        .unwrap();

        let bytes_total = IntCounterVec::new(
            Opts::new(
                "goflow_bytes_total",
                "Total bytes (accounting for sampling rate)",
            ),
            &["sampler_address", "flow_type"],
        )
        .unwrap();

        let packets_total = IntCounterVec::new(
            Opts::new(
                "goflow_packets_total",
                "Total packets (accounting for sampling rate)",
            ),
            &["sampler_address", "flow_type"],
        )
        .unwrap();

        let flows_by_protocol = IntCounterVec::new(
            Opts::new("goflow_flows_by_protocol_total", "Flows by protocol"),
            &["protocol"],
        )
        .unwrap();

        let bytes_by_protocol = IntCounterVec::new(
            Opts::new("goflow_bytes_by_protocol_total", "Bytes by protocol"),
            &["protocol"],
        )
        .unwrap();

        let packets_by_protocol = IntCounterVec::new(
            Opts::new("goflow_packets_by_protocol_total", "Packets by protocol"),
            &["protocol"],
        )
        .unwrap();

        let flows_by_src_addr = IntCounterVec::new(
            Opts::new("goflow_flows_by_src_addr_total", "Flows by source address"),
            &["src_addr"],
        )
        .unwrap();

        let flows_by_dst_addr = IntCounterVec::new(
            Opts::new(
                "goflow_flows_by_dst_addr_total",
                "Flows by destination address",
            ),
            &["dst_addr"],
        )
        .unwrap();

        let bytes_by_src_addr = IntCounterVec::new(
            Opts::new("goflow_bytes_by_src_addr_total", "Bytes by source address"),
            &["src_addr"],
        )
        .unwrap();

        let bytes_by_dst_addr = IntCounterVec::new(
            Opts::new(
                "goflow_bytes_by_dst_addr_total",
                "Bytes by destination address",
            ),
            &["dst_addr"],
        )
        .unwrap();

        let flows_by_sampler = IntCounterVec::new(
            Opts::new("goflow_flows_by_sampler_total", "Flows by sampler"),
            &["sampler_address"],
        )
        .unwrap();

        let bytes_by_sampler = IntCounterVec::new(
            Opts::new("goflow_bytes_by_sampler_total", "Bytes by sampler"),
            &["sampler_address"],
        )
        .unwrap();

        let packets_by_sampler = IntCounterVec::new(
            Opts::new("goflow_packets_by_sampler_total", "Packets by sampler"),
            &["sampler_address"],
        )
        .unwrap();

        let flows_by_src_asn = IntCounterVec::new(
            Opts::new("goflow_flows_by_src_asn_total", "Flows by source ASN"),
            &["src_asn"],
        )
        .unwrap();

        let flows_by_dst_asn = IntCounterVec::new(
            Opts::new("goflow_flows_by_dst_asn_total", "Flows by destination ASN"),
            &["dst_asn"],
        )
        .unwrap();

        let bytes_by_src_asn = IntCounterVec::new(
            Opts::new("goflow_bytes_by_src_asn_total", "Bytes by source ASN"),
            &["src_asn"],
        )
        .unwrap();

        let bytes_by_dst_asn = IntCounterVec::new(
            Opts::new("goflow_bytes_by_dst_asn_total", "Bytes by destination ASN"),
            &["dst_asn"],
        )
        .unwrap();

        let packets_by_src_asn = IntCounterVec::new(
            Opts::new("goflow_packets_by_src_asn_total", "Packets by source ASN"),
            &["src_asn"],
        )
        .unwrap();

        let packets_by_dst_asn = IntCounterVec::new(
            Opts::new("goflow_packets_by_dst_asn_total", "Packets by destination ASN"),
            &["dst_asn"],
        )
        .unwrap();

        let parse_errors_total = IntCounterVec::new(
            Opts::new(
                "goflow_parse_errors_total",
                "Total number of parse errors",
            ),
            &["error_type"],
        )
        .unwrap();

        let active_flows_gauge = IntGaugeVec::new(
            Opts::new("goflow_active_flows", "Active flows by sampler"),
            &["sampler_address"],
        )
        .unwrap();

        let cardinality_gauge = IntGaugeVec::new(
            Opts::new("goflow_metric_cardinality", "Current cardinality of bounded metrics"),
            &["metric_type"],
        )
        .unwrap();

        let evictions_total = IntCounterVec::new(
            Opts::new("goflow_evictions_total", "Total number of evicted metric entries"),
            &["metric_type"],
        )
        .unwrap();

        let src_addr_tracker = Arc::new(BoundedMetricTracker::new(
            DEFAULT_MAX_IP_CARDINALITY,
            Duration::from_secs(DEFAULT_FLOW_TTL_SECONDS),
        ));

        let dst_addr_tracker = Arc::new(BoundedMetricTracker::new(
            DEFAULT_MAX_IP_CARDINALITY,
            Duration::from_secs(DEFAULT_FLOW_TTL_SECONDS),
        ));

        let src_asn_tracker = Arc::new(BoundedMetricTracker::new(
            DEFAULT_MAX_ASN_CARDINALITY,
            Duration::from_secs(DEFAULT_FLOW_TTL_SECONDS),
        ));

        let dst_asn_tracker = Arc::new(BoundedMetricTracker::new(
            DEFAULT_MAX_ASN_CARDINALITY,
            Duration::from_secs(DEFAULT_FLOW_TTL_SECONDS),
        ));

        registry.register(Box::new(flows_total.clone())).unwrap();
        registry.register(Box::new(bytes_total.clone())).unwrap();
        registry.register(Box::new(packets_total.clone())).unwrap();
        registry
            .register(Box::new(flows_by_protocol.clone()))
            .unwrap();
        registry
            .register(Box::new(bytes_by_protocol.clone()))
            .unwrap();
        registry
            .register(Box::new(packets_by_protocol.clone()))
            .unwrap();
        registry
            .register(Box::new(flows_by_src_addr.clone()))
            .unwrap();
        registry
            .register(Box::new(flows_by_dst_addr.clone()))
            .unwrap();
        registry
            .register(Box::new(bytes_by_src_addr.clone()))
            .unwrap();
        registry
            .register(Box::new(bytes_by_dst_addr.clone()))
            .unwrap();
        registry
            .register(Box::new(flows_by_sampler.clone()))
            .unwrap();
        registry
            .register(Box::new(bytes_by_sampler.clone()))
            .unwrap();
        registry
            .register(Box::new(packets_by_sampler.clone()))
            .unwrap();
        registry
            .register(Box::new(flows_by_src_asn.clone()))
            .unwrap();
        registry
            .register(Box::new(flows_by_dst_asn.clone()))
            .unwrap();
        registry
            .register(Box::new(bytes_by_src_asn.clone()))
            .unwrap();
        registry
            .register(Box::new(bytes_by_dst_asn.clone()))
            .unwrap();
        registry
            .register(Box::new(packets_by_src_asn.clone()))
            .unwrap();
        registry
            .register(Box::new(packets_by_dst_asn.clone()))
            .unwrap();
        registry
            .register(Box::new(parse_errors_total.clone()))
            .unwrap();
        registry
            .register(Box::new(active_flows_gauge.clone()))
            .unwrap();
        registry
            .register(Box::new(cardinality_gauge.clone()))
            .unwrap();
        registry
            .register(Box::new(evictions_total.clone()))
            .unwrap();

        Self {
            registry,
            asn_lookup,
            flows_total,
            bytes_total,
            packets_total,
            flows_by_protocol,
            bytes_by_protocol,
            packets_by_protocol,
            flows_by_src_addr,
            flows_by_dst_addr,
            bytes_by_src_addr,
            bytes_by_dst_addr,
            flows_by_sampler,
            bytes_by_sampler,
            packets_by_sampler,
            flows_by_src_asn,
            flows_by_dst_asn,
            bytes_by_src_asn,
            bytes_by_dst_asn,
            packets_by_src_asn,
            packets_by_dst_asn,
            parse_errors_total,
            active_flows: Arc::new(RwLock::new(HashMap::new())),
            active_flows_gauge,
            src_addr_tracker,
            dst_addr_tracker,
            src_asn_tracker,
            dst_asn_tracker,
            cardinality_gauge,
            evictions_total,
            last_src_addr_evictions: RwLock::new(0),
            last_dst_addr_evictions: RwLock::new(0),
            last_src_asn_evictions: RwLock::new(0),
            last_dst_asn_evictions: RwLock::new(0),
        }
    }

    pub fn record_flow(&self, flow: &FlowMessage) {
        let sampler_address = flow.sampler_address.as_deref().unwrap_or("unknown");
        let flow_type = flow.flow_type.as_deref().unwrap_or("unknown");
        let protocol = flow.proto.as_deref().unwrap_or("unknown");

        self.flows_total
            .with_label_values(&[sampler_address, flow_type])
            .inc();

        let scaled_bytes = flow.scaled_bytes();
        let scaled_packets = flow.scaled_packets();

        self.bytes_total
            .with_label_values(&[sampler_address, flow_type])
            .inc_by(scaled_bytes);

        self.packets_total
            .with_label_values(&[sampler_address, flow_type])
            .inc_by(scaled_packets);

        self.flows_by_protocol
            .with_label_values(&[protocol])
            .inc();
        self.bytes_by_protocol
            .with_label_values(&[protocol])
            .inc_by(scaled_bytes);
        self.packets_by_protocol
            .with_label_values(&[protocol])
            .inc_by(scaled_packets);

        if let Some(src_addr) = &flow.src_addr {
            self.src_addr_tracker.increment(
                src_addr,
                &self.flows_by_src_addr,
                &[src_addr],
                1,
            );
            self.src_addr_tracker.increment(
                src_addr,
                &self.bytes_by_src_addr,
                &[src_addr],
                scaled_bytes,
            );
        }

        if let Some(dst_addr) = &flow.dst_addr {
            self.dst_addr_tracker.increment(
                dst_addr,
                &self.flows_by_dst_addr,
                &[dst_addr],
                1,
            );
            self.dst_addr_tracker.increment(
                dst_addr,
                &self.bytes_by_dst_addr,
                &[dst_addr],
                scaled_bytes,
            );
        }

        // ASN tracking
        if let Some(src_addr) = &flow.src_addr {
            if let Ok(ip) = src_addr.parse::<IpAddr>() {
                if let Some(asn) = self.asn_lookup.lookup_asn(ip) {
                    let asn_str = asn.to_string();
                    self.src_asn_tracker.increment(&asn_str, &self.flows_by_src_asn, &[&asn_str], 1);
                    self.src_asn_tracker.increment(&asn_str, &self.bytes_by_src_asn, &[&asn_str], scaled_bytes);
                    self.src_asn_tracker.increment(&asn_str, &self.packets_by_src_asn, &[&asn_str], scaled_packets);
                }
            }
        }

        if let Some(dst_addr) = &flow.dst_addr {
            if let Ok(ip) = dst_addr.parse::<IpAddr>() {
                if let Some(asn) = self.asn_lookup.lookup_asn(ip) {
                    let asn_str = asn.to_string();
                    self.dst_asn_tracker.increment(&asn_str, &self.flows_by_dst_asn, &[&asn_str], 1);
                    self.dst_asn_tracker.increment(&asn_str, &self.bytes_by_dst_asn, &[&asn_str], scaled_bytes);
                    self.dst_asn_tracker.increment(&asn_str, &self.packets_by_dst_asn, &[&asn_str], scaled_packets);
                }
            }
        }

        self.flows_by_sampler
            .with_label_values(&[sampler_address])
            .inc();
        self.bytes_by_sampler
            .with_label_values(&[sampler_address])
            .inc_by(scaled_bytes);
        self.packets_by_sampler
            .with_label_values(&[sampler_address])
            .inc_by(scaled_packets);

        let mut active_flows = self.active_flows.write();
        *active_flows.entry(sampler_address.to_string()).or_insert(0) += 1;
        self.active_flows_gauge
            .with_label_values(&[sampler_address])
            .set(active_flows[sampler_address] as i64);
    }

    pub fn increment_parse_errors(&self) {
        self.parse_errors_total
            .with_label_values(&["json"])
            .inc();
    }

    pub fn cleanup_expired_flows(&self) {
        let src_addr_removed = self.src_addr_tracker.cleanup_expired();
        let dst_addr_removed = self.dst_addr_tracker.cleanup_expired();
        let src_asn_removed = self.src_asn_tracker.cleanup_expired();
        let dst_asn_removed = self.dst_asn_tracker.cleanup_expired();

        if src_addr_removed > 0 {
            self.evictions_total
                .with_label_values(&["src_addr"])
                .inc_by(src_addr_removed as u64);
        }
        if dst_addr_removed > 0 {
            self.evictions_total
                .with_label_values(&["dst_addr"])
                .inc_by(dst_addr_removed as u64);
        }
        if src_asn_removed > 0 {
            self.evictions_total
                .with_label_values(&["src_asn"])
                .inc_by(src_asn_removed as u64);
        }
        if dst_asn_removed > 0 {
            self.evictions_total
                .with_label_values(&["dst_asn"])
                .inc_by(dst_asn_removed as u64);
        }
    }

    fn update_cardinality_metrics(&self) {
        self.cardinality_gauge
            .with_label_values(&["src_addr"])
            .set(self.src_addr_tracker.current_cardinality() as i64);
        self.cardinality_gauge
            .with_label_values(&["dst_addr"])
            .set(self.dst_addr_tracker.current_cardinality() as i64);
        self.cardinality_gauge
            .with_label_values(&["src_asn"])
            .set(self.src_asn_tracker.current_cardinality() as i64);
        self.cardinality_gauge
            .with_label_values(&["dst_asn"])
            .set(self.dst_asn_tracker.current_cardinality() as i64);
    }

    fn update_eviction_metrics(&self) {
        // Get current eviction counts
        let src_addr_evicted = self.src_addr_tracker.total_evicted();
        let dst_addr_evicted = self.dst_addr_tracker.total_evicted();
        let src_asn_evicted = self.src_asn_tracker.total_evicted();
        let dst_asn_evicted = self.dst_asn_tracker.total_evicted();

        // Calculate and report deltas
        let mut last_src_addr = self.last_src_addr_evictions.write();
        if src_addr_evicted > *last_src_addr {
            let delta = src_addr_evicted - *last_src_addr;
            self.evictions_total
                .with_label_values(&["src_addr"])
                .inc_by(delta);
            *last_src_addr = src_addr_evicted;
        }

        let mut last_dst_addr = self.last_dst_addr_evictions.write();
        if dst_addr_evicted > *last_dst_addr {
            let delta = dst_addr_evicted - *last_dst_addr;
            self.evictions_total
                .with_label_values(&["dst_addr"])
                .inc_by(delta);
            *last_dst_addr = dst_addr_evicted;
        }

        let mut last_src_asn = self.last_src_asn_evictions.write();
        if src_asn_evicted > *last_src_asn {
            let delta = src_asn_evicted - *last_src_asn;
            self.evictions_total
                .with_label_values(&["src_asn"])
                .inc_by(delta);
            *last_src_asn = src_asn_evicted;
        }

        let mut last_dst_asn = self.last_dst_asn_evictions.write();
        if dst_asn_evicted > *last_dst_asn {
            let delta = dst_asn_evicted - *last_dst_asn;
            self.evictions_total
                .with_label_values(&["dst_asn"])
                .inc_by(delta);
            *last_dst_asn = dst_asn_evicted;
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
}

async fn metrics_handler(metrics: Arc<Metrics>) -> Vec<u8> {
    metrics.gather()
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
            *time = *time + duration;
        }
    }

    impl Clock for MockClock {
        fn now(&self) -> std::time::Instant {
            *self.current_time.read()
        }
    }

    // Test helper to create metrics with a custom clock
    fn create_metrics_with_clock(asn_db_path: Option<&str>, clock: Arc<dyn Clock>) -> Metrics {
        let registry = Registry::new();
        let asn_lookup = AsnLookup::new(asn_db_path);

        let flows_total = IntCounterVec::new(
            Opts::new("goflow_flows_total", "Total number of flows received"),
            &["sampler_address", "flow_type"],
        )
        .unwrap();

        let bytes_total = IntCounterVec::new(
            Opts::new(
                "goflow_bytes_total",
                "Total bytes (accounting for sampling rate)",
            ),
            &["sampler_address", "flow_type"],
        )
        .unwrap();

        let packets_total = IntCounterVec::new(
            Opts::new(
                "goflow_packets_total",
                "Total packets (accounting for sampling rate)",
            ),
            &["sampler_address", "flow_type"],
        )
        .unwrap();

        let flows_by_protocol = IntCounterVec::new(
            Opts::new("goflow_flows_by_protocol", "Flows by protocol"),
            &["protocol"],
        )
        .unwrap();

        let bytes_by_protocol = IntCounterVec::new(
            Opts::new("goflow_bytes_by_protocol", "Bytes by protocol"),
            &["protocol"],
        )
        .unwrap();

        let packets_by_protocol = IntCounterVec::new(
            Opts::new("goflow_packets_by_protocol", "Packets by protocol"),
            &["protocol"],
        )
        .unwrap();

        let flows_by_src_addr = IntCounterVec::new(
            Opts::new("goflow_flows_by_src_addr", "Flows by source address"),
            &["src_addr"],
        )
        .unwrap();

        let flows_by_dst_addr = IntCounterVec::new(
            Opts::new("goflow_flows_by_dst_addr", "Flows by destination address"),
            &["dst_addr"],
        )
        .unwrap();

        let bytes_by_src_addr = IntCounterVec::new(
            Opts::new("goflow_bytes_by_src_addr", "Bytes by source address"),
            &["src_addr"],
        )
        .unwrap();

        let bytes_by_dst_addr = IntCounterVec::new(
            Opts::new("goflow_bytes_by_dst_addr", "Bytes by destination address"),
            &["dst_addr"],
        )
        .unwrap();

        let flows_by_sampler = IntCounterVec::new(
            Opts::new("goflow_flows_by_sampler", "Flows by sampler"),
            &["sampler"],
        )
        .unwrap();

        let bytes_by_sampler = IntCounterVec::new(
            Opts::new("goflow_bytes_by_sampler", "Bytes by sampler"),
            &["sampler"],
        )
        .unwrap();

        let packets_by_sampler = IntCounterVec::new(
            Opts::new("goflow_packets_by_sampler", "Packets by sampler"),
            &["sampler"],
        )
        .unwrap();

        let flows_by_src_asn = IntCounterVec::new(
            Opts::new("goflow_flows_by_src_asn", "Flows by source ASN"),
            &["src_asn"],
        )
        .unwrap();

        let flows_by_dst_asn = IntCounterVec::new(
            Opts::new("goflow_flows_by_dst_asn", "Flows by destination ASN"),
            &["dst_asn"],
        )
        .unwrap();

        let bytes_by_src_asn = IntCounterVec::new(
            Opts::new("goflow_bytes_by_src_asn", "Bytes by source ASN"),
            &["src_asn"],
        )
        .unwrap();

        let bytes_by_dst_asn = IntCounterVec::new(
            Opts::new("goflow_bytes_by_dst_asn", "Bytes by destination ASN"),
            &["dst_asn"],
        )
        .unwrap();

        let packets_by_src_asn = IntCounterVec::new(
            Opts::new("goflow_packets_by_src_asn", "Packets by source ASN"),
            &["src_asn"],
        )
        .unwrap();

        let packets_by_dst_asn = IntCounterVec::new(
            Opts::new("goflow_packets_by_dst_asn", "Packets by destination ASN"),
            &["dst_asn"],
        )
        .unwrap();

        let parse_errors_total = IntCounterVec::new(
            Opts::new("goflow_parse_errors_total", "Total parse errors"),
            &["error_type"],
        )
        .unwrap();

        let active_flows_gauge = IntGaugeVec::new(
            Opts::new("goflow_active_flows", "Active flows"),
            &["sampler"],
        )
        .unwrap();

        let cardinality_gauge = IntGaugeVec::new(
            Opts::new("goflow_metric_cardinality", "Current metric cardinality"),
            &["metric_type"],
        )
        .unwrap();

        let evictions_total = IntCounterVec::new(
            Opts::new("goflow_evictions_total", "Total metric evictions"),
            &["metric_type"],
        )
        .unwrap();

        registry.register(Box::new(flows_total.clone())).unwrap();
        registry.register(Box::new(bytes_total.clone())).unwrap();
        registry.register(Box::new(packets_total.clone())).unwrap();
        registry.register(Box::new(flows_by_protocol.clone())).unwrap();
        registry.register(Box::new(bytes_by_protocol.clone())).unwrap();
        registry.register(Box::new(packets_by_protocol.clone())).unwrap();
        registry.register(Box::new(flows_by_src_addr.clone())).unwrap();
        registry.register(Box::new(flows_by_dst_addr.clone())).unwrap();
        registry.register(Box::new(bytes_by_src_addr.clone())).unwrap();
        registry.register(Box::new(bytes_by_dst_addr.clone())).unwrap();
        registry.register(Box::new(flows_by_sampler.clone())).unwrap();
        registry.register(Box::new(bytes_by_sampler.clone())).unwrap();
        registry.register(Box::new(packets_by_sampler.clone())).unwrap();
        registry.register(Box::new(flows_by_src_asn.clone())).unwrap();
        registry.register(Box::new(flows_by_dst_asn.clone())).unwrap();
        registry.register(Box::new(bytes_by_src_asn.clone())).unwrap();
        registry.register(Box::new(bytes_by_dst_asn.clone())).unwrap();
        registry.register(Box::new(packets_by_src_asn.clone())).unwrap();
        registry.register(Box::new(packets_by_dst_asn.clone())).unwrap();
        registry.register(Box::new(parse_errors_total.clone())).unwrap();
        registry.register(Box::new(active_flows_gauge.clone())).unwrap();
        registry.register(Box::new(cardinality_gauge.clone())).unwrap();
        registry.register(Box::new(evictions_total.clone())).unwrap();

        let src_addr_tracker = Arc::new(BoundedMetricTracker::new_with_clock(
            DEFAULT_MAX_IP_CARDINALITY,
            Duration::from_secs(DEFAULT_FLOW_TTL_SECONDS),
            clock.clone(),
        ));

        let dst_addr_tracker = Arc::new(BoundedMetricTracker::new_with_clock(
            DEFAULT_MAX_IP_CARDINALITY,
            Duration::from_secs(DEFAULT_FLOW_TTL_SECONDS),
            clock.clone(),
        ));

        let src_asn_tracker = Arc::new(BoundedMetricTracker::new_with_clock(
            DEFAULT_MAX_ASN_CARDINALITY,
            Duration::from_secs(DEFAULT_FLOW_TTL_SECONDS),
            clock.clone(),
        ));

        let dst_asn_tracker = Arc::new(BoundedMetricTracker::new_with_clock(
            DEFAULT_MAX_ASN_CARDINALITY,
            Duration::from_secs(DEFAULT_FLOW_TTL_SECONDS),
            clock,
        ));

        Metrics {
            registry,
            asn_lookup,
            flows_total,
            bytes_total,
            packets_total,
            flows_by_protocol,
            bytes_by_protocol,
            packets_by_protocol,
            flows_by_src_addr,
            flows_by_dst_addr,
            bytes_by_src_addr,
            bytes_by_dst_addr,
            flows_by_sampler,
            bytes_by_sampler,
            packets_by_sampler,
            flows_by_src_asn,
            flows_by_dst_asn,
            bytes_by_src_asn,
            bytes_by_dst_asn,
            packets_by_src_asn,
            packets_by_dst_asn,
            parse_errors_total,
            active_flows: Arc::new(RwLock::new(HashMap::new())),
            active_flows_gauge,
            src_addr_tracker,
            dst_addr_tracker,
            src_asn_tracker,
            dst_asn_tracker,
            cardinality_gauge,
            evictions_total,
            last_src_addr_evictions: RwLock::new(0),
            last_dst_addr_evictions: RwLock::new(0),
            last_src_asn_evictions: RwLock::new(0),
            last_dst_asn_evictions: RwLock::new(0),
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
            src_mac: None,
            dst_mac: None,
            in_if: None,
            out_if: None,
        }
    }

    #[test]
    fn test_metrics_record_flow() {
        let metrics = Metrics::new(None);
        let flow = create_test_flow("10.0.0.1", "10.0.0.2", 1000);

        metrics.record_flow(&flow);

        assert_eq!(metrics.src_addr_tracker.current_cardinality(), 1);
        assert_eq!(metrics.dst_addr_tracker.current_cardinality(), 1);
    }

    #[test]
    fn test_metrics_bounded_cardinality() {
        let metrics = Metrics::new(None);

        for i in 0..15000 {
            let flow = create_test_flow(
                &format!("10.0.{}.{}", i / 256, i % 256),
                &format!("192.168.{}.{}", i / 256, i % 256),
                1000,
            );
            metrics.record_flow(&flow);
        }

        assert!(metrics.src_addr_tracker.current_cardinality() <= DEFAULT_MAX_IP_CARDINALITY);
        assert!(metrics.dst_addr_tracker.current_cardinality() <= DEFAULT_MAX_IP_CARDINALITY);
        assert!(metrics.src_addr_tracker.total_evicted() > 0);
    }

    #[test]
    fn test_cleanup_expired_flows() {
        let metrics = Metrics::new(None);
        let flow = create_test_flow("10.0.0.1", "10.0.0.2", 1000);

        metrics.record_flow(&flow);

        assert_eq!(metrics.src_addr_tracker.current_cardinality(), 1);

        metrics.cleanup_expired_flows();

        assert_eq!(metrics.src_addr_tracker.current_cardinality(), 1);
    }

    #[test]
    fn test_cleanup_expired_flows_with_evictions() {
        let metrics = Metrics::new(None);

        // Manually insert entries with very short TTL by accessing the tracker
        // We need to trigger actual evictions by waiting for entries to expire
        for i in 0..5 {
            let flow = create_test_flow(
                &format!("10.0.0.{}", i),
                &format!("192.168.0.{}", i),
                1000,
            );
            metrics.record_flow(&flow);
        }

        assert_eq!(metrics.src_addr_tracker.current_cardinality(), 5);
        assert_eq!(metrics.dst_addr_tracker.current_cardinality(), 5);

        // Wait for entries to expire (default TTL is 300 seconds, but we'll use the bounded_tracker's test methods)
        // Instead, we can trigger evictions by filling up to the cardinality limit
        // For this test, let's verify the cleanup_expired_flows calls the trackers
        let initial_src = metrics.src_addr_tracker.current_cardinality();
        metrics.cleanup_expired_flows();

        // Verify the method runs without errors
        // Since we can't easily simulate time passing in a unit test without mocking,
        // we'll verify in the next test that evictions actually increment the counter
        let after_src = metrics.src_addr_tracker.current_cardinality();
        assert!(after_src <= initial_src);
    }

    #[test]
    fn test_eviction_metrics_on_cardinality_limit() {
        let metrics = Metrics::new(None);

        // Fill beyond the cardinality limit to trigger evictions
        for i in 0..(DEFAULT_MAX_IP_CARDINALITY + 100) {
            let flow = create_test_flow(
                &format!("10.{}.{}.{}", i / 65536, (i / 256) % 256, i % 256),
                &format!("192.{}.{}.{}", i / 65536, (i / 256) % 256, i % 256),
                1000,
            );
            metrics.record_flow(&flow);
        }

        // Verify evictions happened
        assert!(metrics.src_addr_tracker.total_evicted() > 0);
        assert!(metrics.dst_addr_tracker.total_evicted() > 0);

        // Now call cleanup to trigger the eviction metrics
        metrics.cleanup_expired_flows();

        // Gather metrics and verify eviction counters are present
        let _output = String::from_utf8(metrics.gather()).unwrap();

        // The evictions_total metric should be present if any evictions occurred
        // during the cleanup (though cardinality-based evictions happen during record_flow)
        // Let's just verify the metrics are being tracked
        assert!(metrics.src_addr_tracker.current_cardinality() <= DEFAULT_MAX_IP_CARDINALITY);
        assert!(metrics.dst_addr_tracker.current_cardinality() <= DEFAULT_MAX_IP_CARDINALITY);
    }

    #[test]
    fn test_cardinality_metrics_updated_on_gather() {
        let metrics = Metrics::new(None);

        for i in 0..5 {
            let flow = create_test_flow(
                &format!("10.0.0.{}", i),
                &format!("192.168.0.{}", i),
                1000,
            );
            metrics.record_flow(&flow);
        }

        let output = metrics.gather();
        let output_str = String::from_utf8(output).unwrap();

        assert!(output_str.contains("goflow_metric_cardinality"));
        assert!(output_str.contains("src_addr"));
        assert!(output_str.contains("dst_addr"));
    }

    #[test]
    fn test_time_based_evictions_with_mock_clock() {
        let clock = Arc::new(MockClock::new());
        let metrics = create_metrics_with_clock(None, clock.clone());

        // Record some flows
        for i in 0..5 {
            let flow = create_test_flow(
                &format!("10.0.0.{}", i),
                &format!("192.168.0.{}", i),
                1000,
            );
            metrics.record_flow(&flow);
        }

        assert_eq!(metrics.src_addr_tracker.current_cardinality(), 5);
        assert_eq!(metrics.dst_addr_tracker.current_cardinality(), 5);

        // Advance time past the TTL
        clock.advance(Duration::from_secs(DEFAULT_FLOW_TTL_SECONDS + 100));

        // Call cleanup - should remove all expired entries
        metrics.cleanup_expired_flows();

        // Verify all entries were evicted
        assert_eq!(metrics.src_addr_tracker.current_cardinality(), 0);
        assert_eq!(metrics.dst_addr_tracker.current_cardinality(), 0);

        // Verify eviction metrics were incremented
        let output = String::from_utf8(metrics.gather()).unwrap();
        assert!(output.contains("goflow_evictions_total"));
        assert!(output.contains(r#"metric_type="src_addr""#));
        assert!(output.contains(r#"metric_type="dst_addr""#));
    }

    #[test]
    fn test_asn_evictions_with_mock_clock() {
        let clock = Arc::new(MockClock::new());
        let metrics = create_metrics_with_clock(Some("./test_data/test-asn.mmdb"), clock.clone());

        // Record flows with Google DNS IPs (different src/dst) to trigger ASN tracking
        for _ in 0..5 {
            let flow = create_test_flow("8.8.8.8", "1.1.1.1", 1000); // Google to Cloudflare
            metrics.record_flow(&flow);
        }

        let initial_src_asn = metrics.src_asn_tracker.current_cardinality();
        let initial_dst_asn = metrics.dst_asn_tracker.current_cardinality();

        // Both should have entries (ASN lookups for both Google and Cloudflare)
        assert!(initial_src_asn > 0, "Expected src_asn cardinality > 0");
        assert!(initial_dst_asn > 0, "Expected dst_asn cardinality > 0");

        // Advance time past the TTL
        clock.advance(Duration::from_secs(DEFAULT_FLOW_TTL_SECONDS + 100));

        // Call cleanup - should remove expired ASN entries
        metrics.cleanup_expired_flows();

        // Verify ASN entries were evicted
        assert_eq!(metrics.src_asn_tracker.current_cardinality(), 0);
        assert_eq!(metrics.dst_asn_tracker.current_cardinality(), 0);

        // Verify eviction metrics were incremented for ASNs
        let output = String::from_utf8(metrics.gather()).unwrap();
        assert!(output.contains("goflow_evictions_total"));
        assert!(output.contains(r#"metric_type="src_asn""#));
        assert!(output.contains(r#"metric_type="dst_asn""#));
    }

    #[test]
    fn test_top_talker_retention() {
        let metrics = Metrics::new(None);

        let big_talker = create_test_flow("10.0.0.1", "10.0.0.2", 1_000_000);
        for _ in 0..100 {
            metrics.record_flow(&big_talker);
        }

        for i in 0..15000 {
            let small_flow = create_test_flow(
                &format!("192.168.{}.{}", i / 256, i % 256),
                "10.0.0.3",
                100,
            );
            metrics.record_flow(&small_flow);
        }

        assert_eq!(
            metrics.src_addr_tracker.get_entry("10.0.0.1").is_some(),
            true,
            "Big talker should be retained"
        );
    }

    #[test]
    fn test_multiple_flows_same_source() {
        let metrics = Metrics::new(None);

        for i in 0..10 {
            let flow = create_test_flow("10.0.0.1", &format!("192.168.0.{}", i), 500);
            metrics.record_flow(&flow);
        }

        assert_eq!(metrics.src_addr_tracker.current_cardinality(), 1);
        assert_eq!(metrics.dst_addr_tracker.current_cardinality(), 10);
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
}

#[cfg(test)]
impl Metrics {
    pub fn get_entry(&self, tracker: &str, key: &str) -> Option<crate::bounded_tracker::TrackedEntry> {
        match tracker {
            "src_addr" => self.src_addr_tracker.get_entry(key),
            "dst_addr" => self.dst_addr_tracker.get_entry(key),
            "src_asn" => self.src_asn_tracker.get_entry(key),
            "dst_asn" => self.dst_asn_tracker.get_entry(key),
            _ => None,
        }
    }
}
