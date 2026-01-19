---
# goflow2-exporter-9fcu
title: Update README.md to reflect current metrics
status: completed
type: bug
priority: high
created_at: 2026-01-19T06:50:07Z
updated_at: 2026-01-19T06:54:33Z
---

The README.md documentation is out of sync with the actual codebase:

**Incorrect/outdated items:**
1. Line 18 mentions 'Active Flow Tracking' - this feature was removed in commit 1d4040d
2. Line 94-98 documents `goflow_flows_*` metrics - these were renamed to `goflow_records_*` in commit df6970a
3. Line 111 documents `goflow_active_flows` metric - this was removed

**Missing documentation for:**
- `goflow_bytes_by_tcp_flags_total` / `goflow_packets_by_tcp_flags_total`
- `goflow_bytes_by_src_asn_total` / `goflow_packets_by_src_asn_total` (with org names)
- `goflow_bytes_by_dst_asn_total` / `goflow_packets_by_dst_asn_total` (with org names)
- `goflow_bytes_by_l7_app_total` / `goflow_packets_by_l7_app_total`
- `goflow_metric_cardinality` gauge
- `goflow_evictions_total` counter

## Checklist
- [x] Remove references to 'Active Flow Tracking' feature
- [x] Remove `goflow_active_flows` metric documentation
- [x] Rename `goflow_flows_*` to `goflow_records_*` throughout
- [x] Add documentation for TCP flags metrics
- [x] Add documentation for ASN metrics (src/dst with org names)
- [x] Add documentation for L7 application metrics
- [x] Add documentation for cardinality and eviction metrics
- [x] Update example Prometheus queries if needed
