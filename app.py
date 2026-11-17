"""DNSLens dashboard (Streamlit). UI only: all DNS networking lives in backend/."""
import re
from datetime import datetime

import pandas as pd
import streamlit as st

from frontend.charts import (
    COLORS, PROTOCOLS, fig_box, fig_compare, fig_domain, fig_mean, fig_success, missing_columns,
    observation, prepare, summarize,
)
from frontend.wireshark_tab import render as render_wireshark
from frontend.demo import DEMO_LABEL, make_demo_rows

try:
    from backend.experiment import run_experiment
    BACKEND_OK, BACKEND_ERR = True, ""
except Exception as exc:  # backend not ready yet, or import path problem
    run_experiment, BACKEND_OK, BACKEND_ERR = None, False, str(exc)

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
DEFAULT_DOMAINS = "\n".join([
    "google.com", "wikipedia.org", "youtube.com", "github.com", "cloudflare.com",
    "microsoft.com", "apple.com", "example.com", "amazon.in", "python.org",
])
MAX_ATTEMPTS_WARN = 600

st.set_page_config(page_title="DNSLens", layout="wide")
st.markdown("""
<style>
.block-container{padding-top:2rem;max-width:1250px}
.pill{display:inline-block;padding:.2rem .75rem;border-radius:999px;color:#fff;font-size:.85rem;margin:0 .4rem .4rem 0}
.card{border:1px solid #DDE4E8;border-left:6px solid var(--c);border-radius:8px;padding:.9rem 1.1rem;background:#fff}
.card .name{font-weight:600;font-size:1.05rem}
.card .big{font-size:2.1rem;font-weight:650;line-height:1.15}
.card .sub{color:#5B6B75;font-size:.85rem;margin-top:.2rem}
</style>
""", unsafe_allow_html=True)
st.title("DNSLens - DNS Performance & Privacy Comparison")
st.markdown(
    "".join(f'<span class="pill" style="background:{COLORS[p]}">{p}: {d}</span>' for p, d in
            [("DNS-UDP", "UDP 53"), ("DoT", "TLS 853"), ("DoH", "HTTPS 443")]),
    unsafe_allow_html=True,
)
st.caption("One-shot lookup time to Google Public DNS (A records), measured with the same domains and timeout for every protocol.")


def parse_domains(text):
    """Split on any line ending (CRLF or LF), lowercase, drop blanks and duplicates."""
    cleaned = [ln.strip().lower().rstrip(".") for ln in text.splitlines() if ln.strip()]
    unique = list(dict.fromkeys(cleaned))
    invalid = [d for d in unique if not DOMAIN_RE.match(d)]
    return unique, invalid


def add_run(df_run, demo, expected_rows, source):
    hist = st.session_state.setdefault("history", [])
    hist.append(dict(name=f"Run {len(hist) + 1}: {source}", raw=df_run, demo=demo, expected=expected_rows,
                     finished=datetime.now().strftime("%Y%m%d_%H%M%S")))


# ---------------------------------------------------------------- sidebar inputs
with st.sidebar:
    st.header("Test settings")
    domains_text = st.text_area("Domains (one per line)", DEFAULT_DOMAINS, height=230)
    net_choice = st.selectbox("Network", ["Home Wi-Fi", "Phone Hotspot", "Other"])
    network_label = net_choice
    if net_choice == "Other":
        network_label = st.text_input("Describe the network", placeholder="e.g. College Wi-Fi").strip()
    c1, c2 = st.columns(2)
    repetitions = c1.number_input("Repetitions", 1, 20, 5, 1, help="Use at least 5 for the official run.")
    timeout_s = c2.number_input("Timeout (s)", 1.0, 15.0, 5.0, 0.5)
    use_demo = st.toggle(
        "Use demo data", value=not BACKEND_OK, disabled=not BACKEND_OK,
        help="Demo rows are random, NOT measurements. Turn off for the real experiment.",
    )
    domains, invalid = parse_domains(domains_text)
    expected = len(domains) * 3 * int(repetitions)
    st.caption(f"{len(domains)} domains x 3 protocols x {int(repetitions)} repetitions = **{expected} attempts**")
    run_clicked = st.button("Run experiment", type="primary", width="stretch")
    st.divider()
    up = st.file_uploader("Load a saved raw CSV", type="csv", help="Re-open an earlier experiment, e.g. data/raw/wifi.csv")
    if up is not None and st.session_state.get("loaded_file") != f"{up.name}-{up.size}":
        st.session_state["loaded_file"] = f"{up.name}-{up.size}"
        try:
            loaded = pd.read_csv(up, dtype=str, keep_default_na=False)
            gaps = missing_columns(loaded)
            if gaps:
                st.error("CSV is missing columns: " + ", ".join(gaps))
            else:
                add_run(loaded, DEMO_LABEL in set(loaded["network_label"]), len(loaded), up.name)
        except Exception as exc:
            st.error(f"Could not read CSV: {exc}")
    if st.session_state.get("history") and st.button("Clear all runs", width="stretch"):
        st.session_state.pop("history"); st.session_state.pop("loaded_file", None); st.rerun()
    if not BACKEND_OK:
        st.warning(f"Backend not found, so only demo mode is available. ({BACKEND_ERR})")
    if int(repetitions) < 5:
        st.info("The official run needs at least 5 repetitions.")
    if expected > MAX_ATTEMPTS_WARN:
        st.info(f"{expected} attempts will take a while: runs are sequential.")

# ---------------------------------------------------------------- run
if run_clicked:
    if not domains:
        st.error("Enter at least one domain.")
    elif invalid:
        st.error("Not valid domain names: " + ", ".join(invalid) + ". Use names like example.com, without http:// or paths.")
    elif not network_label:
        st.error("Describe the network before running.")
    else:
        try:
            with st.spinner(f"Running {expected} DNS measurements one at a time..."):
                rows = (make_demo_rows(domains, int(repetitions), float(timeout_s), seed=7 + len(st.session_state.get('history', []))) if use_demo else
                        run_experiment(domains=domains, repetitions=int(repetitions),
                                       network_label=network_label, timeout_s=float(timeout_s)))
            df_new = pd.DataFrame(rows)
            gaps = missing_columns(df_new)
            if df_new.empty:
                st.error("The backend returned no rows.")
            elif gaps:
                st.error("Backend rows are missing agreed fields: " + ", ".join(gaps)
                         + ". Ask the backend owner; do not rename fields in the UI.")
            else:
                add_run(df_new, bool(use_demo), expected, network_label)
        except Exception as exc:
            st.error(f"Experiment failed: {exc}")

hist = st.session_state.get("history", [])
if not hist:
    st.info("Set up your test in the sidebar, then select **Run experiment**, or load a saved CSV. Results appear here.")
    st.stop()
names = [h["name"] for h in hist]
chosen = st.selectbox("Viewing run", names, index=len(names) - 1) if len(names) > 1 else names[0]
cur = hist[names.index(chosen)]
raw, is_demo = cur["raw"], cur["demo"]
df = prepare(raw)
summary = summarize(df)

if is_demo:
    st.error(f"{DEMO_LABEL}. These rows are random placeholders for UI testing, not experimental findings.")
if len(raw) != cur["expected"]:
    st.warning(f"Expected {cur['expected']} rows but received {len(raw)}. Check the backend before using this run.")

tab_res, tab_chart, tab_cmp, tab_ws, tab_raw, tab_method = st.tabs(["Results", "Charts", "Compare runs", "Wireshark", "Raw data", "Method"])

# ---------------------------------------------------------------- results tab
with tab_res:
    st.info(observation(summary))
    udp = summary.loc[summary["protocol"] == "DNS-UDP", "median_ms"]
    udp_med = udp.iloc[0] if len(udp) and pd.notna(udp.iloc[0]) else None
    cols = st.columns(len(summary))
    for col, (_, r) in zip(cols, summary.iterrows()):
        med = "n/a" if pd.isna(r["median_ms"]) else f"{r['median_ms']:.1f} ms"
        mean = "n/a" if pd.isna(r["mean_ms"]) else f"{r['mean_ms']:.1f} ms"
        ov = (f"+{r['median_ms'] - udp_med:.1f} ms vs DNS-UDP (median)"
              if udp_med is not None and r["protocol"] != "DNS-UDP" and pd.notna(r["median_ms"])
              else "baseline" if r["protocol"] == "DNS-UDP" else "")
        col.markdown(
            f'<div class="card" style="--c:{COLORS.get(r["protocol"], "#888")}">'
            f'<div class="name">{r["protocol"]}</div><div class="big">{med}</div>'
            f'<div class="sub">median | mean {mean}</div>'
            f'<div class="sub">{ov}</div>'
            f'<div class="sub">success {r["success_rate_pct"]:.1f}% | {r["successful"]} of {r["attempts"]} attempts</div></div>',
            unsafe_allow_html=True)
    st.write("")
    m1, m2, m3 = st.columns(3)
    m1.metric("Total attempts", len(df))
    m2.metric("Valid DNS responses", int(df["request_success"].sum()))
    m3.metric("Overall success rate", f"{100 * df['request_success'].mean():.1f}%")

    st.subheader("Detailed statistics")
    stats = summary.rename(columns={
        "protocol": "Protocol", "attempts": "Attempts", "successful": "Valid responses", "failed": "Failures",
        "success_rate_pct": "Success rate (%)", "mean_ms": "Mean (ms)", "median_ms": "Median (ms)",
        "min_ms": "Min (ms)", "max_ms": "Max (ms)", "std_ms": "Std dev (ms)"}).round(2)
    st.dataframe(stats, hide_index=True, width="stretch")
    st.download_button("Download summary CSV", stats.to_csv(index=False).encode("utf-8-sig"),
                       file_name=f"{'DEMO_' if is_demo else ''}dnslens_summary.csv", mime="text/csv")
    with st.expander("DNS response codes by protocol"):
        st.caption("NXDOMAIN is a valid DNS response (the name does not exist), not a network failure.")
        codes = (df.assign(dns_rcode=df["dns_rcode"].replace("", "no response").fillna("no response"))
                 .groupby(["protocol", "dns_rcode"]).size().reset_index(name="count"))
        st.dataframe(codes, hide_index=True, width="stretch")

# ---------------------------------------------------------------- charts tab
with tab_chart:
    if summary["mean_ms"].notna().any():
        a, b = st.columns(2)
        a.plotly_chart(fig_mean(summary), width="stretch")
        b.plotly_chart(fig_box(df), width="stretch")
        st.plotly_chart(fig_domain(df), width="stretch")
    else:
        st.warning("No successful responses, so there are no latency charts to draw.")
    st.plotly_chart(fig_success(summary), width="stretch")

# ---------------------------------------------------------------- compare tab
with tab_cmp:
    if len(hist) < 2:
        st.info("Run the same plan on a second network (for example Wi-Fi, then phone hotspot), or load another CSV. "
                "Runs are kept here until you clear them or close the page.")
    else:
        parts = []
        for h in hist:
            sm = summarize(prepare(h["raw"])); sm["run"] = h["name"]; sm["demo"] = h["demo"]
            parts.append(sm)
        allsum = pd.concat(parts, ignore_index=True)
        if allsum["demo"].any():
            st.error(f"{DEMO_LABEL}: at least one run being compared is demo data.")
        st.plotly_chart(fig_compare(allsum), width="stretch")
        st.caption("Compare runs only if the domains, timeout and repetitions were the same.")
        cols_show = ["run", "protocol", "attempts", "successful", "success_rate_pct", "mean_ms", "median_ms", "std_ms"]
        st.dataframe(allsum[cols_show].round(2), hide_index=True, width="stretch")

# ---------------------------------------------------------------- wireshark tab
with tab_ws:
    render_wireshark()

# ---------------------------------------------------------------- raw tab
with tab_raw:
    f1, f2 = st.columns(2)
    pick_p = f1.multiselect("Protocol", sorted(raw["protocol"].unique()), default=sorted(raw["protocol"].unique()))
    pick_d = f2.multiselect("Domain", sorted(raw["domain"].unique()), default=sorted(raw["domain"].unique()))
    only_fail = st.checkbox("Show failed attempts only")
    view = raw[raw["protocol"].isin(pick_p) & raw["domain"].isin(pick_d)]
    if only_fail:
        view = view[~df.loc[view.index, "request_success"]]
    st.caption(f"Showing {len(view)} of {len(raw)} rows. The CSV download always contains all rows.")
    st.dataframe(view, hide_index=True, width="stretch")
    st.download_button(
        "Download raw CSV (all rows)", raw.to_csv(index=False).encode("utf-8-sig"),  # BOM: Excel reads UTF-8
        file_name=f"{'DEMO_' if is_demo else ''}dnslens_raw_{cur['finished']}.csv",
        mime="text/csv", type="primary")

# ---------------------------------------------------------------- method tab
with tab_method:
    first = raw.iloc[0]
    st.markdown(f"""
- **Resolver:** {first['resolver']} (UDP 53 at 8.8.8.8, DoT 853, DoH 443 at `dns.google/dns-query`)
- **Record type:** {first['record_type']} (IPv4) for every lookup
- **Network:** {first['network_label']} | **Timeout:** {first['timeout_s']} s | **Repetitions:** {int(pd.to_numeric(raw['attempt']).max())} per domain and protocol
- **One-shot timing:** each DoT and DoH attempt includes secure connection setup; UDP has no TLS handshake. This is not pure server processing time and not website load time.
- **Caching:** Google Public DNS may already hold cached answers, so lookups are not guaranteed cold.
- **Scope:** results apply only to this device, network, resolver and time window. Mean and SD use successful responses only; failed attempts stay in the table and CSV.
""")
