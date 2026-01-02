# Deployment Guide

## Overview

This project provides multiple deployment options depending on your infrastructure needs.

## Deployment Options Comparison

| Option | Complexity | Use Case | Containers |
|--------|-----------|----------|------------|
| **All-in-One Docker** | ⭐ Simple | Single-host deployment | 1 |
| **Docker Compose** | ⭐⭐ Moderate | Full monitoring stack | 3 |
| **Binary + goflow2** | ⭐⭐⭐ Advanced | Custom integration | 0 |
| **Systemd Service** | ⭐⭐⭐ Advanced | Production Linux servers | 0 |

## 1. All-in-One Docker (Recommended for Most Users)

The simplest deployment combines goflow2 and the aggregator in a single container.

### Build

```bash
docker build -t goflow2-aggregator .
```

### Run

```bash
docker run -d \
  --name goflow2-aggregator \
  --restart unless-stopped \
  -p 2055:2055/udp \
  -p 9090:9090 \
  -e RUST_LOG=info \
  goflow2-aggregator
```

### Verify

```bash
# Check it's running
docker ps

# View logs
docker logs -f goflow2-aggregator

# Test metrics endpoint
curl http://localhost:9090/metrics | grep goflow_
```

### Configure Your Router

Point your MikroTik (or other NetFlow source) to send flows to `<docker-host-ip>:2055`.

**Advantages:**
- Single container to manage
- Minimal resource overhead
- Easy to deploy and update
- Built on official goflow2 image

## 2. Docker Compose (Full Stack)

Deploy a complete monitoring solution with Prometheus and Grafana.

### Deploy

```bash
docker-compose up -d
```

### Access

- **Metrics**: http://localhost:9090/metrics
- **Prometheus**: http://localhost:9091
- **Grafana**: http://localhost:3000 (admin/admin)

### Configure Grafana

1. Access Grafana at http://localhost:3000
2. Add Prometheus data source:
   - URL: `http://prometheus:9090`
   - Access: `Server (default)`
3. Create dashboards using the example queries from the README

**Advantages:**
- Complete monitoring stack out of the box
- Ready-to-use Prometheus storage
- Grafana for visualization
- Easy to customize

## 3. Binary Deployment

Build and run the native binary, piping goflow2 output directly.

### Build

```bash
cargo build --release
```

### Install goflow2

```bash
# Linux
wget https://github.com/netsampler/goflow2/releases/latest/download/goflow2-linux-amd64 -O /usr/local/bin/goflow2
chmod +x /usr/local/bin/goflow2

# macOS
wget https://github.com/netsampler/goflow2/releases/latest/download/goflow2-darwin-amd64 -O /usr/local/bin/goflow2
chmod +x /usr/local/bin/goflow2
```

### Run

```bash
goflow2 -listen netflow://:2055 | ./target/release/goflow2-aggregator
```

**Advantages:**
- No Docker required
- Native performance
- Full control over process management
- Easy to integrate with existing systems

## 4. Systemd Service (Production Linux)

Run as a systemd service for automatic startup and management.

### Install

```bash
# Build the binary
cargo build --release
sudo cp target/release/goflow2-aggregator /usr/local/bin/

# Install goflow2
sudo wget https://github.com/netsampler/goflow2/releases/latest/download/goflow2-linux-amd64 -O /usr/local/bin/goflow2
sudo chmod +x /usr/local/bin/goflow2

# Create user
sudo useradd -r -s /bin/false goflow

# Install service
sudo cp examples/goflow2-aggregator.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable goflow2-aggregator
sudo systemctl start goflow2-aggregator
```

### Manage

```bash
# Check status
sudo systemctl status goflow2-aggregator

# View logs
sudo journalctl -u goflow2-aggregator -f

# Restart
sudo systemctl restart goflow2-aggregator
```

**Advantages:**
- Automatic startup on boot
- Integrated logging with journald
- Standard Linux service management
- Production-ready

## 5. Kubernetes (Advanced)

For Kubernetes deployments, use the all-in-one Docker image with a Deployment and Service.

### Example Manifests

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: goflow2-aggregator
spec:
  replicas: 1
  selector:
    matchLabels:
      app: goflow2-aggregator
  template:
    metadata:
      labels:
        app: goflow2-aggregator
    spec:
      containers:
      - name: goflow2-aggregator
        image: goflow2-aggregator:latest
        ports:
        - containerPort: 2055
          protocol: UDP
          name: netflow
        - containerPort: 9090
          protocol: TCP
          name: metrics
        env:
        - name: RUST_LOG
          value: "info"
---
apiVersion: v1
kind: Service
metadata:
  name: goflow2-aggregator
spec:
  type: LoadBalancer
  ports:
  - port: 2055
    protocol: UDP
    name: netflow
  - port: 9090
    protocol: TCP
    name: metrics
  selector:
    app: goflow2-aggregator
```

**Advantages:**
- Scalable (though typically single replica for NetFlow)
- Integrates with Kubernetes service discovery
- Native Prometheus scraping via ServiceMonitor
- Cloud-native deployment

## Monitoring and Alerting

### Prometheus Scrape Config

Add to your Prometheus configuration:

```yaml
scrape_configs:
  - job_name: 'goflow2-aggregator'
    static_configs:
      - targets: ['localhost:9090']
```

### Example Alerts

```yaml
groups:
  - name: netflow
    rules:
      - alert: NetFlowParseErrorsHigh
        expr: rate(goflow_parse_errors_total[5m]) > 10
        for: 5m
        annotations:
          summary: "High NetFlow parse error rate"

      - alert: NoNetFlowData
        expr: rate(goflow_flows_total[5m]) == 0
        for: 10m
        annotations:
          summary: "No NetFlow data received"
```

## Scaling Considerations

### Vertical Scaling
- The aggregator is CPU-bound during JSON parsing
- Increase CPU allocation for high flow rates
- Memory usage depends on label cardinality (unique IPs, etc.)

### Horizontal Scaling
- NetFlow typically requires sticky sessions (sampler → collector mapping)
- Consider sharding by source router if needed
- Use load balancer with source IP affinity

## Security Recommendations

1. **Network Isolation**: Run on a dedicated management network
2. **Firewall Rules**: Restrict UDP 2055 to known NetFlow sources
3. **Metrics Access**: Secure Prometheus endpoint (reverse proxy + auth)
4. **Container Security**: Use non-root user, read-only filesystem where possible
5. **TLS**: Consider TLS termination proxy for metrics endpoint

## Troubleshooting

### No flows received
```bash
# Check UDP port is listening
sudo netstat -uln | grep 2055

# Check with tcpdump
sudo tcpdump -i any -n udp port 2055

# Verify router config
# MikroTik: /ip traffic-flow print
```

### High memory usage
```bash
# Check metric cardinality
curl -s http://localhost:9090/metrics | wc -l

# Consider aggregating by subnet instead of individual IPs
# Implement metric retention/expiration
```

### Parse errors
```bash
# Check error count
curl -s http://localhost:9090/metrics | grep parse_errors

# View logs for details
docker logs goflow2-aggregator | grep -i error
```
