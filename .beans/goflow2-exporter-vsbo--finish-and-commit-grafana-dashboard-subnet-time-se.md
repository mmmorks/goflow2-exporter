---
# goflow2-exporter-vsbo
title: Finish and commit Grafana dashboard subnet time series panels
status: completed
type: task
priority: normal
created_at: 2026-01-19T06:42:23Z
updated_at: 2026-01-19T06:47:49Z
---

There are uncommitted changes to grafana-dashboard-template.py that add two new time series panels:
- Top 50 Source Subnets by Traffic
- Top 50 Destination Subnets by Traffic

## Checklist
- [x] Review the panel configurations for correctness
- [x] Fix the panel title mismatch (says 'ASNs' but queries 'dst_subnet')
- [x] Regenerate grafana-dashboard.json from template
- [x] Commit the changes
