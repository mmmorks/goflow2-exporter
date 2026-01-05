#!/usr/bin/env -S uv run --script
#
# /// script
# requires-python = ">=3.12"
# dependencies = ["grafana_foundation_sdk"]
# ///
"""
Grafana Dashboard Template Generator for goflow2-exporter
Generates the comprehensive NetFlow traffic analysis dashboard using Grafana Foundation SDK
"""

from grafana_foundation_sdk.builders.dashboard import Dashboard, ThresholdsConfig, DatasourceVariable, QueryVariable
from grafana_foundation_sdk.builders.gauge import Panel as Gauge
from grafana_foundation_sdk.builders.timeseries import Panel as Timeseries
from grafana_foundation_sdk.builders.piechart import Panel as Piechart, PieChartLegendOptions
from grafana_foundation_sdk.builders.table import Panel as Table
from grafana_foundation_sdk.builders.prometheus import Dataquery as PrometheusQuery
from grafana_foundation_sdk.models.prometheus import PromQueryFormat
from grafana_foundation_sdk.builders.common import VizLegendOptions, VizTooltipOptions, TableSortByFieldState as TableSortBuilder, StackingConfig
from grafana_foundation_sdk.models.dashboard import DataSourceRef, Threshold, ThresholdsMode, DataTransformerConfig, DynamicConfigValue, VariableRefresh
from grafana_foundation_sdk.models.piechart import PieChartLabels, PieChartType, PieChartLegendValues
from grafana_foundation_sdk.models.common import (
    LineInterpolation,
    LegendDisplayMode,
    LegendPlacement,
    TooltipDisplayMode,
    SortOrder,
    TableCellHeight,
    StackingMode,
)
from grafana_foundation_sdk.cog import encoder

# Common configurations
RATE_INTERVAL = "[$__rate_interval]"
INSTANCE_FILTER = '{instance="$instance"}'
DATASOURCE = DataSourceRef(type_val="prometheus", uid="${DS_PROMETHEUS}")

# Panel dimension presets
class Size:
    """Common panel sizes (height, width)"""
    HALF = (8, 12)      # Half-width panel
    FULL = (8, 24)      # Full-width panel
    GAUGE = (6, 4)      # Standard gauge
    TABLE = (9, 12)     # Standard table
    LARGE = (9, 12)     # Larger panel

def prom_query(expr: str, legend: str = "", instant: bool = False) -> PrometheusQuery:
    """Create a Prometheus query with standard settings"""
    q = PrometheusQuery().expr(expr).ref_id("A")
    if legend:
        q = q.legend_format(legend)
    return q.instant() if instant else q.range()

def rate_query(metric: str, legend: str = "") -> PrometheusQuery:
    """Create a rate query with standard interval"""
    return prom_query(f"rate({metric}{INSTANCE_FILTER}{RATE_INTERVAL})", legend)

def topk_query(k: int, metric: str, legend: str = "__auto", instant: bool = True) -> PrometheusQuery:
    """Create a topk rate query for table display"""
    return (
        prom_query(f"topk({k}, rate({metric}{INSTANCE_FILTER}{RATE_INTERVAL}))", legend, instant)
        .format(PromQueryFormat.TABLE)
    )

# Panel factory functions with sensible defaults
def gauge_panel(
    title: str,
    description: str,
    query: PrometheusQuery,
    unit: str,
    thresholds: list[tuple[str, float | None]] | None = None,
    size=Size.GAUGE
) -> Gauge:
    """Create a gauge panel with standard configuration

    Args:
        thresholds: List of (color, value) tuples. First should have value=None for base.
                   Example: [("green", None), ("yellow", 1000), ("red", 10000)]
    """
    h, w = size
    panel = (
        Gauge()
        .title(title)
        .description(description)
        .datasource(DATASOURCE)
        .unit(unit)
        .height(h).span(w)
        .show_threshold_markers(True)
        .show_threshold_labels(False)
        .with_target(query)
    )

    if thresholds:
        panel.thresholds(
            ThresholdsConfig()
            .mode(ThresholdsMode.ABSOLUTE)
            .steps([
                Threshold(color=color, value=value) for color, value in thresholds
            ]))

    return panel

def timeseries_panel(
    title: str,
    description: str,
    query: PrometheusQuery,
    unit: str,
    size=Size.HALF,
    legend_calcs: list[str] = ["mean", "max"],
    stacked: bool = False
) -> Timeseries:
    """Create a timeseries panel with standard styling

    Args:
        legend_calcs: Legend calculations to display, e.g. ["mean", "max"]
        stacked: Whether to stack the series (normal stacking mode)
    """
    h, w = size
    panel = (
        Timeseries()
        .title(title)
        .description(description)
        .datasource(DATASOURCE)
        .unit(unit)
        .height(h).span(w)
        .line_width(2)
        .fill_opacity(20)
        .line_interpolation(LineInterpolation.SMOOTH)
        .with_target(query)
    )

    # Add legend configuration if calcs provided
    if legend_calcs:
        legend_opts = (
            VizLegendOptions()
            .calcs(legend_calcs)
            .display_mode(LegendDisplayMode.TABLE)
            .placement(LegendPlacement.BOTTOM)
            .show_legend(True)
            .sort_by("Mean")
            .sort_desc(True)
        )
        panel = panel.legend(legend_opts)

        # Add multi-series tooltip with descending sort
        tooltip_opts = (
            VizTooltipOptions()
            .mode(TooltipDisplayMode.MULTI)
            .sort(SortOrder.DESCENDING)
        )
        panel = panel.tooltip(tooltip_opts)

    # Add stacking if requested
    if stacked:
        stacking_config = StackingConfig().mode(StackingMode.NORMAL).group("A")
        panel = panel.stacking(stacking_config)

    return panel

def piechart_panel(
    title: str,
    description: str,
    query: PrometheusQuery,
    labels=None,
    size=Size.HALF,
    show_legend_table: bool = True
) -> Piechart:
    """Create a pie chart panel with standard configuration

    Args:
        show_legend_table: If True, show legend as a table on the right with values
    """
    h, w = size
    if labels is None:
        labels = [PieChartLabels.NAME, PieChartLabels.PERCENT]

    panel = (
        Piechart()
        .title(title)
        .description(description)
        .datasource(DATASOURCE)
        .height(h).span(w)
        .display_labels(labels)
        .pie_type(PieChartType.PIE)
        .with_target(query)
    )

    # Add table-style legend if requested
    if show_legend_table:
        legend_opts = (
            PieChartLegendOptions()
            .show_legend(True)
            .display_mode(LegendDisplayMode.TABLE)
            .placement(LegendPlacement.RIGHT)
            .values([PieChartLegendValues.VALUE, PieChartLegendValues.PERCENT])
        )
        panel = panel.legend(legend_opts)

    return panel

def table_panel(
    title: str,
    description: str,
    query: PrometheusQuery,
    unit: str,
    value_column: str,
    size=Size.TABLE,
    rename_columns: dict[str, str] | None = None,
    column_width: dict[str, int] | None = None,
    unit_overrides: dict[str, str] | None = None
) -> Table:
    """Create a table panel with standard configuration

    Args:
        value_column: Name for the Value column (e.g., "Traffic Rate", "Packet Rate")
        rename_columns: Dictionary of column renames (e.g., {"dst_subnet": "Destination Subnet"})
        column_width: Dictionary of column widths (e.g., {"Destination Subnet": 200})
        unit_overrides: Dictionary of unit overrides for specific columns (e.g., {"ASN": "none", "Count": "short"})
    """
    h, w = size
    rename_columns = rename_columns or {}
    column_width = column_width or {}
    unit_overrides = unit_overrides or {}

    panel = (
        Table()
        .title(title)
        .description(description)
        .datasource(DATASOURCE)
        .unit(unit)
        .height(h).span(w)
        .with_target(query)
        .show_header(True)
        .cell_height(TableCellHeight.SM)
        .sort_by([
            TableSortBuilder()
            .display_name(value_column)
            .desc(True)
        ])
    )

    # Add organize transformation to hide unwanted fields and rename columns
    hide_fields = ["Time", "__name__", "flow_type", "instance", "job", "sampler_address"]

    all_renames = {"Value": value_column}
    all_renames.update(rename_columns)

    organize_transform = DataTransformerConfig(
        id_val="organize",
        options={
            "excludeByName": {field: True for field in hide_fields},
            "indexByName": {},
            "renameByName": all_renames
        }
    )
    panel = panel.with_transformation(organize_transform)

    # Add column width overrides
    for col_name, width in column_width.items():
        panel = panel.override_by_name(
            col_name,
            [DynamicConfigValue(id_val="custom.width", value=width)]
        )

    # Add unit overrides for specific columns
    for col_name, unit_val in unit_overrides.items():
        panel = panel.override_by_name(
            col_name,
            [DynamicConfigValue(id_val="unit", value=unit_val)]
        )

    return panel

def create_dashboard() -> Dashboard:
    """Generate the complete Grafana dashboard"""

    dashboard = (
        Dashboard("NetFlow Traffic Analysis (goflow2-exporter)")
        .uid("goflow2-netflow")
        .tags(["netflow", "ipfix", "network", "traffic"])
        .refresh("30s")
        .editable()
        .time("now-1h", "now")
        .timezone("browser")
        .with_variable(
            DatasourceVariable("DS_PROMETHEUS")
            .type("prometheus")
            .label("Prometheus")
        )
        .with_variable(
            QueryVariable("instance")
            .label("Instance")
            .datasource(DATASOURCE)
            .query("label_values(goflow_records_all_total, instance)")
            .refresh(VariableRefresh.ON_DASHBOARD_LOAD)
        )

        # Row 1: Overview gauges and protocol distribution
        .with_panel(gauge_panel(
            "Traffic Rate", "Total traffic rate in bytes per second",
            rate_query("goflow_bytes_all_total", "Traffic Rate"),
            unit="Bps",
            thresholds=[("green", None), ("yellow", 10_000_000), ("red", 100_000_000)]
        ))
        .with_panel(gauge_panel(
            "Record Rate", "Total flow records per second",
            rate_query("goflow_records_all_total", "Record Rate"),
            unit="rps",
            thresholds=[("green", None), ("yellow", 100), ("red", 1000)]
        ))
        .with_panel(gauge_panel(
            "Packet Rate", "Total packet rate",
            rate_query("goflow_packets_all_total", "Packet Rate"),
            unit="pps",
            thresholds=[("green", None), ("yellow", 1000), ("red", 10_000)]
        ))

        .with_panel(timeseries_panel(
            "Protocol Distribution by Traffic", "Protocol breakdown by traffic volume over time",
            prom_query(f"sum by (protocol) (rate(goflow_bytes_by_protocol_total{INSTANCE_FILTER}{RATE_INTERVAL}))", "{{protocol}}"),
            unit="Bps",
            size=(6,12),
            stacked=True
        ))

        # Row 2: Protocol analysis
        .with_panel(timeseries_panel(
            "TCP Flags Distribution by Packets", "TCP flags breakdown by packet rate over time",
            prom_query(f"sum by (tcp_flags) (rate(goflow_packets_by_tcp_flags_total{INSTANCE_FILTER}{RATE_INTERVAL}))", "{{tcp_flags}}"),
            unit="pps",
            stacked=True
        ))
        .with_panel(timeseries_panel(
            "Traffic by Protocol", "Traffic by protocol over time",
            rate_query("goflow_bytes_by_protocol_total", "{{protocol}}"),
            unit="Bps",
            stacked=True
        ))

        # Row 3: Packet rates
        .with_panel(timeseries_panel(
            "Packet Rate by TCP Flags", "Packet rate by TCP flags over time",
            rate_query("goflow_packets_by_tcp_flags_total", "{{tcp_flags}}"),
            unit="pps",
            stacked=True
        ))
        .with_panel(timeseries_panel(
            "Packet Rate by Protocol", "Packet rate by protocol",
            rate_query("goflow_packets_by_protocol_total", "{{protocol}}"),
            unit="pps",
            stacked=True
        ))

        # Row 4: L7 Application metrics
        .with_panel(timeseries_panel(
            "Traffic by L7 Application", "Traffic breakdown by Layer 7 application/service",
            prom_query(f"sum by (l7_app) (rate(goflow_bytes_by_l7_app_total{INSTANCE_FILTER}{RATE_INTERVAL}))", "{{l7_app}}"),
            unit="Bps",
            stacked=True
        ))
        .with_panel(timeseries_panel(
            "Packet Rate by L7 Application", "Packet rate breakdown by Layer 7 application/service",
            prom_query(f"sum by (l7_app) (rate(goflow_packets_by_l7_app_total{INSTANCE_FILTER}{RATE_INTERVAL}))", "{{l7_app}}"),
            unit="pps",
            stacked=True
        ))

        # Row 5: L7 Application distribution
        .with_panel(piechart_panel(
            "L7 Application Distribution (Traffic)", "Distribution of traffic by Layer 7 application",
            prom_query(f"topk(10, sum by (l7_app) (rate(goflow_bytes_by_l7_app_total{INSTANCE_FILTER}{RATE_INTERVAL})))", "{{l7_app}}"),
            labels=[PieChartLabels.NAME, PieChartLabels.PERCENT],
            show_legend_table=True
        ))
        .with_panel(piechart_panel(
            "L7 Application Distribution (Packets)", "Distribution of packets by Layer 7 application",
            prom_query(f"topk(10, sum by (l7_app) (rate(goflow_packets_by_l7_app_total{INSTANCE_FILTER}{RATE_INTERVAL})))", "{{l7_app}}"),
            labels=[PieChartLabels.NAME, PieChartLabels.PERCENT],
            show_legend_table=True
        ))

        # Row 6: Top L7 Applications
        .with_panel(table_panel(
            "Top 20 L7 Applications by Traffic", "Top Layer 7 applications by traffic volume",
            topk_query(20, "goflow_bytes_by_l7_app_total"),
            unit="Bps",
            value_column="Traffic Rate",
            rename_columns={"l7_app": "Application"},
            column_width={"Application": 180}
        ))
        .with_panel(table_panel(
            "Top 20 L7 Applications by Packet Rate", "Top Layer 7 applications by packet count",
            topk_query(20, "goflow_packets_by_l7_app_total"),
            unit="pps",
            value_column="Packet Rate",
            rename_columns={"l7_app": "Application"},
            column_width={"Application": 180}
        ))

        # Row 7: Top ASNs by traffic (timeseries)
        .with_panel(timeseries_panel(
            "Top 10 Source ASNs (Traffic)", "Top source ASNs by traffic",
            prom_query(f"topk(10, rate(goflow_bytes_by_src_asn_total{INSTANCE_FILTER}{RATE_INTERVAL}))", "AS{{src_asn}} - {{src_asn_org}}"),
            unit="Bps", size=(9, 12)
        ))
        .with_panel(timeseries_panel(
            "Top 10 Destination ASNs (Traffic)", "Top destination ASNs by traffic",
            prom_query(f"topk(10, rate(goflow_bytes_by_dst_asn_total{INSTANCE_FILTER}{RATE_INTERVAL}))", "AS{{dst_asn}} - {{dst_asn_org}}"),
            unit="Bps", size=(9, 12)
        ))

        # Row 8: Top ASNs by traffic (tables)
        .with_panel(table_panel(
            "Top 20 Destination ASNs with Organizations", "ASN traffic breakdown with organization names",
            topk_query(20, "goflow_bytes_by_dst_asn_total"),
            unit="Bps",
            value_column="Traffic Rate",
            rename_columns={"dst_asn": "ASN", "dst_asn_org": "Organization"},
            column_width={"Organization": 300},
            unit_overrides={"ASN": "none"}
        ))
        .with_panel(table_panel(
            "Top 20 Source ASNs with Organizations", "Source ASN traffic breakdown with organization names",
            topk_query(20, "goflow_bytes_by_src_asn_total"),
            unit="Bps",
            value_column="Traffic Rate",
            rename_columns={"src_asn": "ASN", "src_asn_org": "Organization"},
            column_width={"Organization": 300},
            unit_overrides={"ASN": "none"}
        ))

        # Row 9: Top ASNs by packets
        .with_panel(table_panel(
            "Top 20 Destination ASNs by Packet Rate", "Destination ASN packet rate with organization names",
            topk_query(20, "goflow_packets_by_dst_asn_total"),
            unit="pps",
            value_column="Packet Rate",
            rename_columns={"dst_asn": "ASN", "dst_asn_org": "Organization"},
            column_width={"Organization": 300},
            unit_overrides={"ASN": "none"}
        ))
        .with_panel(table_panel(
            "Top 20 Source ASNs by Packet Rate", "Source ASN packet rate with organization names",
            topk_query(20, "goflow_packets_by_src_asn_total"),
            unit="pps",
            value_column="Packet Rate",
            rename_columns={"src_asn": "ASN", "src_asn_org": "Organization"},
            column_width={"Organization": 300},
            unit_overrides={"ASN": "none"}
        ))

        # Row 10: Top subnets by traffic
        .with_panel(table_panel(
            "Top 20 Source Subnets by Traffic", "Top source Subnets by traffic volume",
            topk_query(20, "goflow_bytes_by_src_subnet_total"),
            unit="Bps",
            value_column="Traffic Rate",
            rename_columns={"src_subnet": "Source Subnet"},
            column_width={"Source Subnet": 200}
        ))
        .with_panel(table_panel(
            "Top 20 Destination Subnets by Traffic", "Top destination Subnets by traffic volume",
            topk_query(20, "goflow_bytes_by_dst_subnet_total"),
            unit="Bps",
            value_column="Traffic Rate",
            rename_columns={"dst_subnet": "Destination Subnet"},
            column_width={"Destination Subnet": 200}
        ))

        # Row 11: Top Subnets by packets
        .with_panel(table_panel(
            "Top 20 Source Subnets by Packet Rate", "Top source Subnets by packet count",
            topk_query(20, "goflow_packets_by_src_subnet_total"),
            unit="pps",
            value_column="Packet Rate",
            rename_columns={"src_subnet": "Source Subnet"},
            column_width={"Source Subnet": 200}
        ))
        .with_panel(table_panel(
            "Top 20 Destination Subnets by Packet Rate", "Top destination Subnets by packet count",
            topk_query(20, "goflow_packets_by_dst_subnet_total"),
            unit="pps",
            value_column="Packet Rate",
            rename_columns={"dst_subnet": "Destination Subnet"},
            column_width={"Destination Subnet": 200}
        ))

        # Row 12: Metric cardinality and eviction rate
        .with_panel(piechart_panel(
            "Metric Cardinality", "Metric cardinality by type",
            prom_query(f"goflow_metric_cardinality{INSTANCE_FILTER}", "{{metric_type}}"),
            labels=[PieChartLabels.NAME, PieChartLabels.VALUE],
            show_legend_table=True
        ))
        .with_panel(timeseries_panel(
            "Metric Eviction Rate", "Rate of metric evictions due to cardinality limits or TTL expiration",
            rate_query("goflow_evictions_total", "{{metric_type}}"),
            unit="eps"
        ))
    )

    return dashboard

if __name__ == "__main__":
    dashboard = create_dashboard().build()
    json_output = encoder.JSONEncoder(sort_keys=True, indent=2).encode(dashboard)
    print(json_output)
