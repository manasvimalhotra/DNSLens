"""Summary statistics and Plotly figures. Pure display helpers - no networking."""
import pandas as pd
import plotly.graph_objects as go

PROTOCOLS = ["DNS-UDP", "DoT", "DoH"]
COLORS = {"DNS-UDP": "#6B7C86", "DoT": "#1F6F8B", "DoH": "#D98324"}
REQUIRED_COLUMNS = [
    "timestamp_utc", "run_id", "network_label", "domain", "record_type", "protocol",
    "resolver", "attempt", "elapsed_ms", "request_success", "dns_rcode",
    "resolved_ips", "error", "timeout_s",
]


def missing_columns(df):
    return [c for c in REQUIRED_COLUMNS if c not in df.columns]


def prepare(df):
    """Return a typed copy for analysis. The original raw frame is never modified."""
    out = df.copy()
    out["elapsed_ms"] = pd.to_numeric(out["elapsed_ms"], errors="coerce")
    out["request_success"] = (
        out["request_success"].astype(str).str.strip().str.lower().isin(["true", "1", "yes"])
    )
    return out


def summarize(df):
    """One row per protocol. Latency stats use successful responses only."""
    rows = []
    protocols = [p for p in PROTOCOLS if p in set(df["protocol"])]
    protocols += sorted(set(df["protocol"]) - set(PROTOCOLS))
    for proto in protocols:
        sub = df[df["protocol"] == proto]
        ok = sub[sub["request_success"] & sub["elapsed_ms"].notna()]["elapsed_ms"]
        rows.append({
            "protocol": proto,
            "attempts": len(sub),
            "successful": int(sub["request_success"].sum()),
            "failed": int((~sub["request_success"]).sum()),
            "success_rate_pct": 100 * sub["request_success"].mean() if len(sub) else float("nan"),
            "mean_ms": ok.mean() if len(ok) else float("nan"),
            "median_ms": ok.median() if len(ok) else float("nan"),
            "min_ms": ok.min() if len(ok) else float("nan"),
            "max_ms": ok.max() if len(ok) else float("nan"),
            "std_ms": ok.std(ddof=1) if len(ok) > 1 else float("nan"),  # sample SD
        })
    return pd.DataFrame(rows)


def _label(row):
    return f"{row['protocol']}<br>n={row['successful']}/{row['attempts']}"


def fig_mean(summary):
    s = summary.dropna(subset=["mean_ms"])
    fig = go.Figure(go.Bar(
        x=[_label(r) for _, r in s.iterrows()],
        y=s["mean_ms"],
        error_y=dict(type="data", array=s["std_ms"].fillna(0), visible=True),
        marker_color=[COLORS.get(p, "#888") for p in s["protocol"]],
        customdata=s[["median_ms", "std_ms"]],
        hovertemplate="Mean %{y:.1f} ms<br>Median %{customdata[0]:.1f} ms"
                      "<br>SD %{customdata[1]:.1f} ms<extra></extra>",
    ))
    fig.update_layout(
        title="One-shot DNS lookup latency by transport (mean, error bars = ±1 standard deviation)",
        xaxis_title="Protocol (successful samples / total attempts)",
        yaxis_title="Response time (ms)", yaxis_rangemode="tozero",
        showlegend=False, margin=dict(t=70),
    )
    return fig


def fig_box(df):
    ok = df[df["request_success"] & df["elapsed_ms"].notna()]
    fig = go.Figure()
    for proto in [p for p in PROTOCOLS if p in set(ok["protocol"])]:
        fig.add_trace(go.Box(
            y=ok[ok["protocol"] == proto]["elapsed_ms"], name=proto,
            boxpoints="all", jitter=0.4, pointpos=0, marker_color=COLORS[proto],
            marker_size=4, line_width=1.5,
        ))
    fig.update_layout(
        title="Latency distribution (every successful sample)",
        xaxis_title="Protocol", yaxis_title="Response time (ms)",
        yaxis_rangemode="tozero", showlegend=False, margin=dict(t=60),
    )
    return fig


def fig_success(summary):
    fig = go.Figure(go.Bar(
        x=summary["protocol"], y=summary["success_rate_pct"],
        marker_color=[COLORS.get(p, "#888") for p in summary["protocol"]],
        text=[f"{v:.1f}%" for v in summary["success_rate_pct"]], textposition="outside",
        customdata=summary[["successful", "attempts"]],
        hovertemplate="%{customdata[0]} of %{customdata[1]} valid DNS responses<extra></extra>",
    ))
    fig.update_layout(
        title="Success rate (valid DNS responses / total attempts)",
        xaxis_title="Protocol", yaxis_title="Success rate (%)",
        yaxis_range=[0, 110], showlegend=False, margin=dict(t=60),
    )
    return fig


def observation(summary):
    """Cautious, data-derived sentence. Describes only this dataset."""
    s = summary.dropna(subset=["median_ms"])
    if s.empty:
        return "No successful responses were recorded, so no latency comparison is possible."
    fastest = s.loc[s["median_ms"].idxmin()]
    text = f"In this dataset, {fastest['protocol']} had the lowest median latency ({fastest['median_ms']:.1f} ms)."
    sd = s.dropna(subset=["std_ms"])
    if len(sd) > 1:
        wide = sd.loc[sd["std_ms"].idxmax()]
        text += f" {wide['protocol']} showed the widest spread (SD {wide['std_ms']:.1f} ms)."
    bad = summary[summary["failed"] > 0]
    if not bad.empty:
        text += " Failed attempts: " + ", ".join(f"{r['protocol']} {r['failed']}" for _, r in bad.iterrows()) + "."
    return text


def fig_domain(df):
    """Median latency per domain, grouped by protocol (successful samples only)."""
    ok = df[df["request_success"] & df["elapsed_ms"].notna()]
    med = ok.groupby(["domain", "protocol"])["elapsed_ms"].median().reset_index()
    fig = go.Figure()
    for proto in [p for p in PROTOCOLS if p in set(med["protocol"])]:
        s = med[med["protocol"] == proto]
        fig.add_trace(go.Bar(x=s["domain"], y=s["elapsed_ms"], name=proto, marker_color=COLORS[proto]))
    fig.update_layout(
        barmode="group", title="Median latency by domain and protocol",
        xaxis_title="Domain", yaxis_title="Median response time (ms)",
        legend_title="Protocol", margin=dict(t=60),
    )
    return fig


def fig_compare(all_summary):
    """Median latency per protocol, one bar group per saved run (e.g. Wi-Fi vs hotspot)."""
    palette = ["#1F6F8B", "#D98324", "#6B7C86", "#8A5FA8", "#3E8E5A"]
    fig = go.Figure()
    for i, run in enumerate(all_summary["run"].unique()):
        s = all_summary[all_summary["run"] == run]
        fig.add_trace(go.Bar(
            x=s["protocol"], y=s["median_ms"], name=run, marker_color=palette[i % len(palette)],
            error_y=dict(type="data", array=s["std_ms"].fillna(0), visible=True),
        ))
    fig.update_layout(
        barmode="group", title="Median latency by protocol across runs (error bars = ±1 standard deviation)",
        xaxis_title="Protocol", yaxis_title="Median response time (ms)", yaxis_rangemode="tozero",
        legend_title="Run", margin=dict(t=60),
    )
    return fig