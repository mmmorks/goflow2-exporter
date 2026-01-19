# goflow2-exporter

A high-performance Rust application that consumes NetFlow/IPFIX events from goflow2 via stdin and exposes aggregated metrics via a Prometheus endpoint.

## Features

- **Real-time Flow Processing**: Consumes goflow2 JSON output via stdin
- **Prometheus Integration**: Exposes comprehensive metrics on port 9090
- **ASN Enrichment**: Automatic IP-to-ASN lookup with organization names using MaxMind GeoLite2 ASN database
- **Multi-dimensional Aggregation**: Track records, bytes, and packets by:
  - Protocol (TCP, UDP, ICMP, IPv6-ICMP, etc.)
  - Source and destination subnets (CIDR notation)
  - Source and destination ASN (with organization names)
  - TCP flags (SYN, ACK, FIN, etc.)
  - Layer 7 application (HTTPS, DNS, SSH, etc.)
  - Sampler address (router)
  - Flow type (NetFlow v5/v9, IPFIX, sFlow)
- **L7 Protocol Classification**: Automatic application-layer protocol detection based on port numbers
- **NAT Flow Correlation**: Maps inbound traffic to true internal destination IPs for accurate per-device metrics
- **Bounded Metric Cardinality**: Automatic cardinality tracking with configurable limits and LRU eviction to prevent metric explosion
- **Sampling Rate Correction**: Automatically scales byte and packet counts based on sampling rates (including sampling_rate=0 handling)
- **Async Processing**: Built on Tokio for efficient concurrent operations
- **Error Tracking**: Parse error metrics for monitoring data quality

## Prerequisites

- Rust 1.70 or later
- goflow2 installed and configured
- A NetFlow/IPFIX source (e.g., Mikrotik router)
- (Optional) MaxMind GeoLite2 ASN database for ASN enrichment

## Installation

```bash
cargo build --release
```

The binary will be available at `target/release/goflow2-exporter`.

## Usage

### Basic Usage

Pipe goflow2 output directly to the aggregator:

```bash
goflow2 -listen netflow://:2055 | ./target/release/goflow2-exporter
```

### With ASN Enrichment

To enable ASN lookups with organization names, set the `ASN_DB_PATH` environment variable:

```bash
ASN_DB_PATH=/path/to/GeoLite2-ASN.mmdb goflow2 -listen netflow://:2055 | ./target/release/goflow2-exporter
```

The ASN database is bundled in the Docker image at `/app/data/GeoLite2-ASN.mmdb` by default.

### With Logging

Enable debug logging:

```bash
RUST_LOG=debug goflow2 -listen netflow://:2055 | ./target/release/goflow2-exporter
```

### MikroTik Configuration

Configure your MikroTik router to send NetFlow data:

```
/ip traffic-flow
set enabled=yes interfaces=all
/ip traffic-flow target
add address=<goflow2-server-ip>:2055 version=9
```

For IPFIX:

```
/ip traffic-flow
set enabled=yes interfaces=all
/ip traffic-flow ipfix
set active-flow-timeout=5m inactive-flow-timeout=15s
/ip traffic-flow target
add address=<goflow2-server-ip>:2055 version=ipfix
```

## Prometheus Metrics

The aggregator exposes metrics on `http://localhost:9090/metrics`.

### Available Metrics

All traffic metrics (bytes, packets) are automatically scaled by the sampling rate.

#### Totals
- `goflow_records_all_total{sampler_address, flow_type}` - Total flow records received
- `goflow_bytes_all_total{sampler_address, flow_type}` - Total bytes
- `goflow_packets_all_total{sampler_address, flow_type}` - Total packets

#### By Protocol
- `goflow_bytes_by_protocol_total{protocol}` - Bytes by protocol (TCP, UDP, IPv6-TCP, etc.)
- `goflow_packets_by_protocol_total{protocol}` - Packets by protocol

#### By Subnet (CIDR)
- `goflow_bytes_by_src_subnet_total{src_subnet}` - Bytes by source subnet
- `goflow_packets_by_src_subnet_total{src_subnet}` - Packets by source subnet
- `goflow_bytes_by_dst_subnet_total{dst_subnet}` - Bytes by destination subnet
- `goflow_packets_by_dst_subnet_total{dst_subnet}` - Packets by destination subnet

#### By ASN
- `goflow_bytes_by_src_asn_total{src_asn, src_asn_org}` - Bytes by source ASN with organization name
- `goflow_packets_by_src_asn_total{src_asn, src_asn_org}` - Packets by source ASN
- `goflow_bytes_by_dst_asn_total{dst_asn, dst_asn_org}` - Bytes by destination ASN with organization name
- `goflow_packets_by_dst_asn_total{dst_asn, dst_asn_org}` - Packets by destination ASN

#### By TCP Flags
- `goflow_bytes_by_tcp_flags_total{tcp_flags}` - Bytes by TCP flags (SYN, ACK, FIN, RST, etc.)
- `goflow_packets_by_tcp_flags_total{tcp_flags}` - Packets by TCP flags

#### By Layer 7 Application
- `goflow_bytes_by_l7_app_total{l7_app}` - Bytes by application protocol (HTTPS, DNS, SSH, etc.)
- `goflow_packets_by_l7_app_total{l7_app}` - Packets by application protocol

#### By Sampler
- `goflow_bytes_by_sampler_total{sampler_address}` - Bytes by sampler/router
- `goflow_packets_by_sampler_total{sampler_address}` - Packets by sampler/router

#### Operational Metrics
- `goflow_parse_errors_total` - JSON parse errors
- `goflow_metric_cardinality{metric_type}` - Current unique label combinations per metric group
- `goflow_evictions_total{metric_type}` - Count of label evictions due to cardinality limits

### Example Prometheus Queries

**Top talkers by bytes (by subnet):**
```promql
topk(10, rate(goflow_bytes_by_src_subnet_total[5m]))
```

**Traffic by protocol:**
```promql
sum by (protocol) (rate(goflow_bytes_by_protocol_total[5m]))
```

**Total bandwidth from all samplers (in Mbps):**
```promql
sum(rate(goflow_bytes_all_total[1m])) * 8 / 1000000
```

**Traffic by Layer 7 application:**
```promql
topk(10, sum by (l7_app) (rate(goflow_bytes_by_l7_app_total[5m])))
```

**Traffic by ASN with organization names:**
```promql
topk(10, sum by (dst_asn, dst_asn_org) (rate(goflow_bytes_by_dst_asn_total[5m])))
```

**Packet rate by sampler:**
```promql
sum by (sampler_address) (rate(goflow_packets_by_sampler_total[5m]))
```

**Monitor metric cardinality:**
```promql
goflow_metric_cardinality
```

## Architecture

### Components

1. **stdin_reader**: Asynchronously reads and parses JSON flow records from stdin
2. **flow**: Data structures representing goflow2 flow messages
3. **metrics**: Prometheus metric collection and HTTP server
4. **main**: Orchestrates the async tasks and handles shutdown

### Data Flow

```
MikroTik Router → goflow2 → JSON → stdin_reader → metrics → Prometheus
                 (NetFlow)        (async parsing)  (aggregation)  (HTTP)
```

### Concurrency Model

- **Main Task**: Coordinates shutdown and monitors subtasks
- **Metrics Server**: Axum HTTP server on port 9090
- **Stdin Processor**: Reads and processes flow events

All tasks run concurrently using Tokio's async runtime.

## Configuration

### Environment Variables

- `RUST_LOG`: Set logging level (trace, debug, info, warn, error)
  - Example: `RUST_LOG=info` or `RUST_LOG=goflow2_exporter=debug`

### Customization

To change the metrics port, modify `DEFAULT_METRICS_PORT` in `src/metrics.rs`.

## Docker Deployment

The default Dockerfile builds on top of the official goflow2 image, combining both components into a single container.

### Quick Start with Docker

Build and run the all-in-one image:

```bash
docker build -t goflow2-exporter .
docker run -d -p 2055:2055/udp -p 9090:9090 goflow2-exporter
```

### Docker Compose (Full Stack)

The included `docker-compose.yml` deploys the complete monitoring stack:

```bash
docker-compose up -d
```

This provides:
- **goflow2-exporter**: NetFlow collector and metrics aggregator (ports 2055/udp, 9090)
- **Prometheus**: Metrics storage and queries (port 9091)
- **Grafana**: Visualization dashboard (port 3000, admin/admin)

### Standalone Aggregator Only

If you want to run the aggregator separately (with goflow2 running elsewhere):

```bash
docker build -f Dockerfile.standalone -t goflow2-exporter-standalone .
goflow2 -listen netflow://:2055 | docker run -i -p 9090:9090 goflow2-exporter-standalone
```

## Performance Considerations

- **Sampling Rate**: The aggregator automatically scales byte/packet counts by the sampling rate reported in each flow
- **Memory**: Metrics are aggregated per unique label combination (subnets, protocols, etc.)
- **Cardinality**: Subnet-based tracking (CIDR notation) significantly reduces cardinality compared to tracking individual IP addresses. Requires ASN database for subnet lookups.

## Development

### Building

```bash
cargo build
```

### Running Tests

```bash
cargo test
```

### Testing with Sample Data

Create a sample flow JSON file:

```json
{"type":"NETFLOW_V9","time_received_ns":1681583295157626000,"sequence_num":1,"sampling_rate":100,"sampler_address":"192.168.1.1","time_flow_start_ns":1681583295157626000,"time_flow_end_ns":1681583295157626000,"bytes":1500,"packets":1,"src_addr":"10.0.1.100","dst_addr":"8.8.8.8","etype":"IPv4","proto":"TCP","src_port":443,"dst_port":50001}
```

Then pipe it to the aggregator:

```bash
cat sample_flows.json | cargo run
```

## Troubleshooting

### No data in Prometheus

1. Check that goflow2 is receiving flows: `goflow2 -listen netflow://:2055`
2. Verify JSON output is being produced
3. Check logs: `RUST_LOG=debug ./goflow2-exporter`
4. Verify metrics endpoint: `curl http://localhost:9090/metrics`

### Parse errors increasing

- Check `goflow_parse_errors_total` metric
- Review logs for malformed JSON
- Verify goflow2 is outputting valid JSON

### High memory usage

- Review the number of unique IPs in your metrics
- Consider aggregating at a higher level (subnets instead of individual IPs)
- Implement metric expiration for inactive flows

## License

MIT

## References

- [goflow2 Documentation](https://github.com/netsampler/goflow2)
- [Prometheus Rust Client](https://docs.rs/prometheus/)
- [MikroTik Traffic Flow](https://help.mikrotik.com/docs/display/ROS/Traffic+Flow)
