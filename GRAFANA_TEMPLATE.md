# Grafana Dashboard Template

This directory contains a concise Python template that generates the comprehensive Grafana dashboard for goflow2-exporter.

## Files

- **[grafana-dashboard-template.py](grafana-dashboard-template.py)**: Template generator (314 lines)
- **[grafana-dashboard.json](grafana-dashboard.json)**: Generated dashboard (2,040 lines)

## Benefits

The template approach provides several advantages over maintaining a raw JSON file:

1. **Conciseness**: 314 lines vs 2,040 lines (85% reduction)
2. **Maintainability**: Reusable functions eliminate repetitive panel configurations
3. **Consistency**: Changes to panel styles automatically apply to all similar panels
4. **Readability**: Clear Python code vs nested JSON structures
5. **Easy modifications**: Add new metrics or panels with minimal code

## Usage

### Generate the dashboard:

```bash
python3 grafana-dashboard-template.py > grafana-dashboard.json
```

### Import into Grafana:

1. Open Grafana web interface
2. Navigate to Dashboards → Import
3. Upload `grafana-dashboard.json`
4. Select your Prometheus datasource
5. Click Import

## Template Structure

The template defines helper functions for common panel types:

- `gauge_panel()`: Creates gauge visualizations (Traffic Rate, Packet Rate, Record Rate)
- `timeseries_panel()`: Creates time-series charts (Protocol traffic, ASN traffic, TCP flags)
- `piechart_panel()`: Creates pie charts (Protocol distribution, TCP flags distribution)
- `table_panel()`: Creates ranked tables (Top IPs, Top ASNs)

### Example: Adding a New Metric

To add a new gauge for a hypothetical "Error Rate" metric:

```python
panels.append(
    gauge_panel(99, "Error Rate", "Flow processing errors per second",
               f"rate(goflow_errors_total{INSTANCE_FILTER}{RATE_INTERVAL})", "eps",
               [{"color": "green", "value": None}, {"color": "yellow", "value": 1},
                {"color": "red", "value": 10}], GridPos(6, 4, 8, 0))
)
```

### Example: Modifying All Timeseries Panels

Change line smoothing for all timeseries panels by editing `timeseries_panel()`:

```python
"lineInterpolation": "linear",  # Change from "smooth" to "linear"
```

## Dashboard Contents

The generated dashboard includes:

### Overview (Row 1)
- Traffic Rate gauge (Bps)
- Record Rate gauge (records/sec)
- Metric Cardinality pie chart

### Protocol Analysis (Rows 2-3)
- Traffic by Protocol (timeseries + pie chart)
- Packet Rate by Protocol

### ASN Analysis (Rows 4-5)
- Top 10 Source/Destination ASNs (timeseries)
- Top 20 Source/Destination ASNs (tables with org names)

### IP Analysis (Rows 6-7)
- Top 20 Source/Destination IPs by Traffic (tables)
- Top 20 Source/Destination IPs by Packets (tables)

### TCP Analysis (Row 8)
- Packet Rate by TCP Flags (timeseries + pie chart)

### System Metrics (Row 9)
- Metric Eviction Rate
- Packet Rate gauge

## Variables

The dashboard includes two template variables:

- `DS_PROMETHEUS`: Prometheus datasource selector
- `instance`: Instance filter (auto-populated from `goflow_records_all_total` metric)

## Customization

Common customization points:

1. **Thresholds**: Adjust warning/critical levels in gauge panels
2. **Top N**: Change `topk(20, ...)` to show more/fewer items in tables
3. **Time range**: Modify `"time": {"from": "now-1h", "to": "now"}`
4. **Refresh rate**: Change `"refresh": "30s"` to desired interval
5. **Grid layout**: Adjust `GridPos()` values to rearrange panels

## Regeneration

After modifying the template, regenerate the dashboard:

```bash
python3 grafana-dashboard-template.py > grafana-dashboard.json
```

Then re-import into Grafana or use the Grafana API to update it automatically.
