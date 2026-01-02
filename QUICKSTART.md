# Quick Start Guide

## 1. Build the Project

```bash
cargo build --release
```

The binary will be at `target/release/goflow2-exporter`.

## 2. Test with Sample Data

```bash
cat examples/sample_flow.json | ./target/release/goflow2-exporter &
```

## 3. Check Metrics

```bash
curl http://localhost:9090/metrics | grep goflow_
```

## 4. Production Deployment

### Option A: Docker (Recommended - All-in-One)

Build and run the combined goflow2 + aggregator image:

```bash
docker build -t goflow2-exporter .
docker run -d \
  -p 2055:2055/udp \
  -p 9090:9090 \
  --name goflow2-exporter \
  goflow2-exporter
```

### Option B: Docker Compose (Full Stack with Prometheus & Grafana)

```bash
docker-compose up -d
```

This will start:
- goflow2-exporter on ports 2055/udp (NetFlow) and 9090 (metrics)
- Prometheus on port 9091
- Grafana on port 3000 (admin/admin)

Access Grafana at http://localhost:3000 and add Prometheus as a data source at http://prometheus:9090.

### Option C: Direct Usage (Binary)

```bash
goflow2 -listen netflow://:2055 | ./target/release/goflow2-exporter
```

### Option D: Systemd Service

```bash
sudo cp examples/goflow2-exporter.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable goflow2-exporter
sudo systemctl start goflow2-exporter
```

## 5. Configure Your Router

### MikroTik NetFlow v9

```
/ip traffic-flow
set enabled=yes interfaces=all
/ip traffic-flow target
add address=<server-ip>:2055 version=9
```

### MikroTik IPFIX

```
/ip traffic-flow
set enabled=yes interfaces=all
/ip traffic-flow ipfix
set active-flow-timeout=5m inactive-flow-timeout=15s
/ip traffic-flow target
add address=<server-ip>:2055 version=ipfix
```

## 6. View Metrics in Prometheus

Example queries:

**Top 10 source IPs by bandwidth:**
```promql
topk(10, rate(goflow_bytes_by_src_addr_total[5m]))
```

**Total bandwidth in Mbps:**
```promql
sum(rate(goflow_bytes_total[1m])) * 8 / 1000000
```

**Traffic by protocol:**
```promql
sum by (protocol) (rate(goflow_bytes_by_protocol_total[5m]))
```

## 7. Monitoring

Check application logs:
```bash
journalctl -u goflow2-exporter -f
```

Check for parse errors:
```bash
curl -s http://localhost:9090/metrics | grep parse_errors
```

## Troubleshooting

### No flows received
1. Check goflow2 is running: `ps aux | grep goflow2`
2. Check UDP port 2055 is open: `sudo netstat -uln | grep 2055`
3. Verify router configuration
4. Test with tcpdump: `sudo tcpdump -i any -n udp port 2055`

### High parse errors
1. Check goflow2 is outputting JSON: `goflow2 -listen netflow://:2055 | head`
2. Review logs: `RUST_LOG=debug ./goflow2-exporter`

### Metrics not updating
1. Verify aggregator is running: `curl http://localhost:9090/metrics`
2. Check if flows are being processed (logs should show activity)
3. Ensure flows are reaching goflow2
