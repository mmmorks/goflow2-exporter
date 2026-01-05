# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

goflow2-exporter is a high-performance Rust application that consumes NetFlow/IPFIX flow data from goflow2 via stdin and exposes aggregated metrics via a Prometheus endpoint on port 9090. It's designed to handle high-volume flow data with bounded metric cardinality to prevent metric explosion.

## Build and Test Commands

### Building
```bash
# Development build
cargo build

# Release build (optimized)
cargo build --release

# Binary location
./target/release/goflow2-exporter
```

### Testing
```bash
# Run all tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_name

# Run tests in specific module
cargo test metrics::tests::

# Check code without building
cargo check
```

### Running Locally
```bash
# With sample data
cat examples/sample_flow.json | cargo run

# With goflow2 (production-like)
goflow2 -listen netflow://:2055 | ./target/release/goflow2-exporter

# With ASN database
ASN_DB_PATH=./data/GeoLite2-ASN.mmdb cargo run

# With debug logging
RUST_LOG=debug cargo run
```

### Metrics Verification
```bash
# View all metrics
curl http://localhost:9090/metrics

# Filter for goflow metrics
curl http://localhost:9090/metrics | grep goflow_

# Check specific metric
curl http://localhost:9090/metrics | grep goflow_bytes_by_protocol
```

## Technology Stack

### Core Dependencies
- **tokio**: Async runtime for concurrent operations
- **serde/serde_json**: JSON serialization/deserialization
- **prometheus**: Metric collection and exposition
- **axum**: HTTP server framework for metrics endpoint
- **maxminddb**: ASN database lookups
- **ipnet**: CIDR/subnet handling
- **parking_lot**: High-performance synchronization primitives
- **tracing**: Structured logging

## Architecture

### Data Flow
```
Router (NetFlow/IPFIX) → goflow2 → JSON (stdin) → goflow2-exporter → Prometheus HTTP endpoint
```

### Module Structure

The codebase is organized into focused modules with clear responsibilities:

- **`main.rs`**: Orchestrates three concurrent async tasks using Tokio's select! macro:
  1. Metrics HTTP server (Axum on port 9090)
  2. Stdin processor (reads and parses JSON flow records)
  3. Cleanup task (runs every 5 minutes to expire old metrics)

- **`flow.rs`**: Defines `FlowMessage` struct that mirrors goflow2's JSON output. Key methods:
  - `scaled_bytes()` / `scaled_packets()`: Multiply raw values by sampling_rate (handles sampling_rate=0 as 1:1)
  - `normalized_protocol()`: Prefixes IPv6 protocols with "IPv6-" (e.g., "IPv6-TCP")

- **`metrics.rs`**: Core metrics collection with two metric group types:
  - `TotalMetricGroup`: Includes records, bytes, and packets counters (for top-level aggregation)
  - `DimensionalMetricGroup`: Only bytes and packets counters (for protocol, ASN, subnet, etc.)
  - Uses macros (`counter!`, `gauge!`, `total_metric_group!`, `dimensional_metric_group!`) to reduce boilerplate
  - All metrics use `BoundedMetricTracker` for cardinality control

- **`bounded_tracker.rs`**: Implements cardinality limiting with two eviction strategies:
  - LRU eviction when max_entries limit is reached (default: 10,000)
  - TTL-based expiration via `cleanup_expired()` (default: 1 hour)
  - Uses `Clock` trait for testability (allows time mocking in tests)
  - Automatically removes Prometheus label values when entries are evicted

- **`asn.rs`**: Provides unified IP lookup that returns both ASN and subnet info in a single database query:
  - Returns `IpInfo { asn: AsnInfo, subnet: SubnetInfo }`
  - Automatically detects own public IPv6 addresses (6rd tunnels) using next_hop patterns
  - Uses MaxMind GeoLite2 ASN database for external IPs
  - Calculates CIDR notation using ipnet library
  - Gracefully handles missing database (returns None)

- **`stdin_reader.rs`**: Async stdin processing with support for:
  - Line-by-line JSON parsing
  - Multiple concatenated JSON objects on a single line
  - Parse error tracking without stopping processing

- **`tcp_flags.rs`**: Decodes TCP flag bitmask into human-readable strings

- **`l7_classifier.rs`**: Classifies flows by Layer 7 application protocol based on port numbers:
  - Maps (L4 protocol, port) tuples to application names (e.g., "HTTP", "DNS-UDP", "MySQL")
  - Returns transport-specific names (e.g., "HTTPS" vs "HTTP", "DNS-UDP" vs "DNS-TCP")
  - Handles IPv6 protocol normalization (strips "IPv6-" prefix for port matching)
  - Unknown ports are labeled as "PROTOCOL/PORT" (e.g., "TCP/8888")
  - Includes well-known ports for web, email, databases, services, and games

### Concurrency Model

The application uses Tokio's async runtime with three concurrent tasks:

1. **Metrics Server Task**: Axum HTTP server serving `/metrics` endpoint
2. **Stdin Processor Task**: Reads stdin, parses JSON, calls `metrics.record_flow()`
3. **Cleanup Task**: Periodic timer (5 min) that calls `metrics.cleanup_expired_flows()`

All tasks share an `Arc<Metrics>` for thread-safe metric updates. The main task uses `tokio::select!` to handle graceful shutdown on Ctrl+C or task failure.

### Key Concepts

#### Sampling Rate Normalization
- NetFlow/IPFIX data often uses sampling (e.g., 1:100)
- `FlowMessage::scaled_bytes()` and `scaled_packets()` multiply by sampling_rate
- `sampling_rate=0` is treated as 1:1 (no sampling)

#### Protocol Normalization
- IPv6 protocols are prefixed with "IPv6-" (e.g., "IPv6-TCP", "IPv6-UDP")
- IPv4 protocols remain unprefixed (e.g., "TCP", "UDP")
- Exception: "IPv6-ICMP" is not double-prefixed
- See `FlowMessage::normalized_protocol()` in [src/flow.rs](src/flow.rs)

#### ASN Enrichment

The system provides synthetic ASN classifications for different IP address types:

**Private IPv4 (RFC 1918):**
- ASN 64512: 10.0.0.0/8 (Class A)
- ASN 64513: 172.16.0.0/12 (Class B)
- ASN 64514: 192.168.0.0/16 (Class C)

**IPv6 Private and Local:**
- ASN 64515: fc00::/7 (ULA - Unique Local Addresses)
- ASN 64516: Own public IPv6 (6rd/tunnel addresses, auto-detected via next_hop)

**Public IPs:**
- Uses MaxMind GeoLite2 ASN database (configured via ASN_DB_PATH env var)
- Falls back to ASN 0 "Unknown" if database unavailable

**Own IPv6 Detection (6rd Tunnels):**
The system automatically detects your own public IPv6 addresses in 6rd deployments by analyzing the `next_hop` field:
- `next_hop = "::300:0:0:0"` indicates outbound traffic → src_addr is own IPv6
- `next_hop = "::4000:0:0:0"` indicates inbound traffic → dst_addr is own IPv6
- All detected addresses are grouped by /64 prefix
- See `classify_own_ipv6()` in [src/asn.rs](src/asn.rs#L44) for implementation

#### L7 Protocol Classification

The system classifies flows by Layer 7 application protocol based on port numbers:

**Classification Strategy:**
- Uses `classify_l7_protocol()` in [src/l7_classifier.rs](src/l7_classifier.rs)
- Classifies BOTH source and destination ports (flows are double-counted)
- Returns transport-specific names (e.g., "HTTPS" vs "HTTP", "DNS-UDP" vs "DNS-TCP")
- Unknown ports are labeled as "PROTOCOL/PORT" (e.g., "TCP/8888")

**Well-known Port Mappings:**
- Web: HTTP (80, 8080), HTTPS (443, 8443)
- DNS: DNS-UDP (53), DNS-TCP (53)
- Email: SMTP (25, 587), IMAP (143, 993), POP3 (110, 995), and secure variants
- Databases: MySQL (3306), PostgreSQL (5432), MongoDB (27017), Redis (6379)
- Services: SSH (22), FTP (20-21), NTP (123), DHCP (67-68)
- Games: Minecraft (25565)
- Other: RDP (3389), VNC (5900), LDAP (389, 636)

**IPv6 Handling:**
The classifier automatically normalizes IPv6 protocols (strips "IPv6-" prefix) to apply the same port mappings.

**Extending Port Mappings:**
Add new ports to the match statement in `classify_l7_protocol()` following the existing pattern.

**Cardinality Considerations:**
Since unknown ports are labeled by port number, this can lead to high cardinality with many unique ports. The `BoundedMetricTracker` handles this through LRU eviction and TTL-based expiration. Monitor `goflow_metric_cardinality{metric_type="l7_app"}` to track growth.

### Metrics Design Patterns

#### Cardinality Bounding

All dimensional metrics use `BoundedMetricTracker` to prevent unbounded metric growth:

- **Subnet aggregation**: IPs are grouped by CIDR subnet (from ASN database) instead of individual IPs
- **LRU eviction**: When cardinality limit is hit, oldest entries are evicted
- **TTL expiration**: Inactive flows expire after 1 hour
- **Prometheus cleanup**: When entries are evicted, corresponding Prometheus labels are removed via `remove_label_values()`

This ensures metrics remain bounded even with millions of unique flows.

#### Two Metric Group Types

1. **TotalMetricGroup** (`total` metrics):
   - Includes `records` counter (counts flow records received)
   - Used for top-level aggregation by sampler_address and flow_type
   - Example: `goflow_records_all_total{sampler_address="192.168.1.1", flow_type="IPFIX"}`

2. **DimensionalMetricGroup** (all `by_*` metrics):
   - Only includes `bytes` and `packets` counters (no records counter)
   - Used for dimensional breakdowns (protocol, ASN, subnet, TCP flags, sampler)
   - Avoids redundant record counting in dimensional views
   - Example: `goflow_bytes_by_protocol_total{protocol="TCP"}`

#### Macro-Based Metric Creation

The codebase uses macros to reduce boilerplate when creating metrics:

```rust
// Creates and registers a counter metric
counter!($registry, $name, $help, $labels)

// Creates and registers a gauge metric
gauge!($registry, $name, $help, $labels)

// Creates a TotalMetricGroup (with records counter)
total_metric_group!($registry, $prefix, $help_prefix, $labels, $ttl, $clock)

// Creates a DimensionalMetricGroup (without records counter)
dimensional_metric_group!($registry, $prefix, $help_prefix, $labels, $ttl, $clock)
```

### Testing Patterns

#### Time-Based Testing

Use the `Clock` trait and `MockClock` for testing time-dependent behavior:

```rust
let clock = Arc::new(MockClock::new());
let metrics = Metrics::new_with_clock(Some("./test_data/test-asn.mmdb"), clock.clone());

// Record some flows
metrics.record_flow(&flow);

// Advance time past TTL
clock.advance(Duration::from_secs(3700));

// Verify expiration behavior
metrics.cleanup_expired_flows();
```

#### ASN Database Testing

Tests use `./test_data/test-asn.mmdb` with known entries:
- `8.8.8.8` → Google (ASN 15169, subnet 8.8.8.0/24)
- `1.1.1.1` → Cloudflare (ASN 13335)
- `2001:4860:4860::8888` → Google IPv6 (ASN 15169, subnet 2001:4860:4860::/48)

#### Integration Testing

The `tests/integration_tests.rs` file contains end-to-end tests that verify the full stdin → metrics pipeline.

## Important Configuration

### Environment Variables

- `ASN_DB_PATH`: Path to MaxMind GeoLite2 ASN database (default: `./data/GeoLite2-ASN.mmdb`)
- `RUST_LOG`: Logging level (trace, debug, info, warn, error)

### Constants in `metrics.rs`

- `DEFAULT_METRICS_PORT`: 9090
- `DEFAULT_MAX_CARDINALITY`: 10,000 entries per metric group
- `DEFAULT_FLOW_TTL_SECONDS`: 3,600 seconds (1 hour)
- Cleanup interval: 300 seconds (5 minutes) in [src/main.rs:39](src/main.rs#L39)

## Common Development Tasks

### Adding a New Metric

1. Decide if it needs a records counter (use `TotalMetricGroup`) or just bytes/packets (use `DimensionalMetricGroup`)
2. Add the metric group to `Metrics` struct in [metrics.rs](src/metrics.rs)
3. Initialize it in `Metrics::new_with_clock()` using the appropriate macro
4. Add recording logic in `Metrics::record_flow()`
5. Add cleanup logic in `Metrics::cleanup_expired_flows()`
6. Add to `update_cardinality_metrics()` and `update_eviction_metrics()`
7. Add tests for the new metric

### Modifying Flow Parsing

Flow parsing happens in [stdin_reader.rs](src/stdin_reader.rs):
- Modify `FlowMessage` struct in [flow.rs](src/flow.rs) to add/remove fields
- Update serde field mappings with `#[serde(rename = "...")]`
- Run tests to ensure existing flows still parse correctly

### Testing with Mock Data

Create sample flows matching goflow2's JSON format:
```bash
echo '{"type":"IPFIX","sampling_rate":0,"sampler_address":"192.168.1.1","bytes":1000,"packets":10,"src_addr":"8.8.8.8","dst_addr":"1.1.1.1","proto":"TCP","etype":"IPv4"}' | cargo run
```

## Important Patterns

### Error Handling
- Uses `anyhow::Result` for error propagation
- Parse errors increment `goflow_parse_errors_total` metric
- Graceful degradation (e.g., ASN lookup failures don't stop processing)

### Thread Safety
- Metrics wrapped in `Arc<Metrics>` for shared access
- Uses `parking_lot::RwLock` for interior mutability
- All operations are async-safe

### Logging
- Uses `tracing` crate with structured logging
- Log levels controlled by RUST_LOG environment variable
- Default level: info

## Performance Considerations

- **Sampling rate**: Automatically accounted for in scaled_bytes/scaled_packets
- **Memory**: Proportional to unique label combinations (protocols, subnets, ASNs)
- **Cardinality**: Use subnet tracking instead of individual IPs to reduce memory footprint
- **Concurrency**: All I/O operations are async (no blocking)

## Troubleshooting

### High Parse Error Rate
- Check `goflow_parse_errors_total` metric
- Enable debug logging: `RUST_LOG=debug`
- Verify goflow2 JSON output format

### Missing ASN Data
- Verify ASN_DB_PATH points to valid MaxMind database
- Check file permissions
- Review logs for ASN lookup errors

### Memory Growth
- Check number of unique subnets/ASNs being tracked
- Review bounded tracker limits in [src/bounded_tracker.rs](src/bounded_tracker.rs)
- Consider increasing cleanup frequency

## Deployment Notes

- **Docker**: Default Dockerfile builds on top of official goflow2 image (all-in-one)
- **Docker Compose**: Includes Prometheus and Grafana for full monitoring stack
- **Standalone**: `Dockerfile.standalone` builds just the aggregator
- See [QUICKSTART.md](QUICKSTART.md) for deployment examples
- See [DEPLOYMENT.md](DEPLOYMENT.md) for production deployment patterns

## Python Tooling

The repository includes Python scripts for Grafana dashboard management:

- `grafana-dashboard-template.py`: Generates Grafana dashboard JSON from template
- Requires Python 3.x with dependencies in `pyproject.toml`
- Uses `.venv` for virtual environment

To work with Python scripts:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
python grafana-dashboard-template.py
```

## Code Style Guidelines

**Self-documenting code is preferred over comments:**
- Use clear, descriptive variable and function names
- Keep functions focused and single-purpose
- Structure code to reveal intent
- Only add comments where the logic is non-obvious to a reasonably experienced developer

**Public API documentation:**
- Always add doc comments (`///`) for public functions, structs, enums, and modules
- Document expected behavior, parameters, return values, and any panics or errors
- Include usage examples for non-trivial public APIs

**When to add comments:**
- Complex algorithms or non-obvious business logic
- Why a particular approach was chosen (especially if it seems counterintuitive)
- Workarounds for external issues or bugs
- Important performance considerations

**When NOT to add comments:**
- Stating what the code obviously does
- Redundant documentation of function signatures (types are self-documenting in Rust)
- Change history (use git for this)
- Private implementation details that are already clear from the code

**Example:**
```rust
// Bad: Comment states the obvious
// Increment the counter
counter += 1;

// Good: Code is self-explanatory, no comment needed
counter += 1;

// Good: Comment explains non-obvious behavior
// sampling_rate=0 means no sampling, treat as 1:1
let rate = if sampling_rate == 0 { 1 } else { sampling_rate };
```

## Commit Guidelines

When making code changes, each commit should be:

1. **Self-contained**: A complete, logical unit of work that can stand alone
2. **Well-tested**: Include all necessary unit tests and integration tests
3. **Documented**: Update any relevant documentation (README.md, code comments, this file, etc.)
4. **Descriptive**: Use clear, concise commit messages that explain the "why" not just the "what"
5. **Clean**: No tool advertising or attribution in commit messages - keep them professional and focused on the change itself

**Commit workflow:**
- Make code changes
- Write/update tests to cover the changes
- Update documentation (README, comments, etc.)
- Run tests: `cargo test`
- Verify build: `cargo build`
- Commit with descriptive message focusing on the change itself
