use crate::asn::AsnLookup;
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
use tracing::info;

const DEFAULT_METRICS_PORT: u16 = 9090;

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
            self.flows_by_src_addr
                .with_label_values(&[src_addr])
                .inc();
            self.bytes_by_src_addr
                .with_label_values(&[src_addr])
                .inc_by(scaled_bytes);
        }

        if let Some(dst_addr) = &flow.dst_addr {
            self.flows_by_dst_addr
                .with_label_values(&[dst_addr])
                .inc();
            self.bytes_by_dst_addr
                .with_label_values(&[dst_addr])
                .inc_by(scaled_bytes);
        }

        // ASN tracking
        if let Some(src_addr) = &flow.src_addr {
            if let Ok(ip) = src_addr.parse::<IpAddr>() {
                if let Some(asn) = self.asn_lookup.lookup_asn(ip) {
                    let asn_str = asn.to_string();
                    self.flows_by_src_asn.with_label_values(&[&asn_str]).inc();
                    self.bytes_by_src_asn.with_label_values(&[&asn_str]).inc_by(scaled_bytes);
                    self.packets_by_src_asn.with_label_values(&[&asn_str]).inc_by(scaled_packets);
                }
            }
        }

        if let Some(dst_addr) = &flow.dst_addr {
            if let Ok(ip) = dst_addr.parse::<IpAddr>() {
                if let Some(asn) = self.asn_lookup.lookup_asn(ip) {
                    let asn_str = asn.to_string();
                    self.flows_by_dst_asn.with_label_values(&[&asn_str]).inc();
                    self.bytes_by_dst_asn.with_label_values(&[&asn_str]).inc_by(scaled_bytes);
                    self.packets_by_dst_asn.with_label_values(&[&asn_str]).inc_by(scaled_packets);
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

    pub fn gather(&self) -> Vec<u8> {
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
