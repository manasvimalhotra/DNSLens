"""Wireshark evidence tab: reads a saved capture; no live capturing happens here."""
import tempfile
from pathlib import Path

import plotly.graph_objects as go
import streamlit as st

from frontend.charts import COLORS
from wireshark.pcap_summary import observer_view, summarise

DEFAULT_CAPTURE = Path(__file__).resolve().parent.parent / "data" / "raw" / "capture_wifi.pcapng"


@st.cache_data(show_spinner="Reading capture...")
def analyse(data: bytes):
    with tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False) as tmp:
        tmp.write(data)
    path = Path(tmp.name)
    try:
        return summarise(path), observer_view(path)
    finally:
        path.unlink(missing_ok=True)


def _bar(summary, column, title, unit):
    s = summary.dropna(subset=[column])
    fig = go.Figure(go.Bar(x=s["protocol"], y=s[column], marker_color=[COLORS.get(p, "#888") for p in s["protocol"]]))
    fig.update_layout(title=title, xaxis_title="Protocol", yaxis_title=unit, showlegend=False,
                      yaxis_rangemode="tozero", margin=dict(t=60))
    return fig


def render():
    st.markdown("Packet-level evidence from a **Wireshark capture** (traffic to and from 8.8.8.8 only). "
                "It checks which ports each method used and what an observer on the network can read.")
    up = st.file_uploader("Upload a Wireshark capture (.pcapng or .pcap)", type=["pcap", "pcapng"], key="pcap_upload")
    if up is not None:
        data, name = up.getvalue(), up.name
    elif DEFAULT_CAPTURE.exists():
        data, name = DEFAULT_CAPTURE.read_bytes(), DEFAULT_CAPTURE.name
    else:
        st.info("Upload your capture, or save it as `data/raw/capture_wifi.pcapng` to load it automatically.")
        return
    try:
        flows, (names, sni) = analyse(data)
    except Exception as exc:
        st.error(f"Could not read the capture: {exc}")
        return
    if flows.empty:
        st.warning("No traffic to or from 8.8.8.8 on UDP 53, TCP 853 or TCP 443 was found in this capture.")
        return

    st.caption(f"Capture: {name} | {len(flows)} connections to Google Public DNS found")
    summary = flows.groupby("protocol").agg(
        lookups=("protocol", "size"), mean_packets=("packets", "mean"), mean_bytes=("bytes", "mean"),
        mean_handshake_ms=("tcp_handshake_ms", "mean"), mean_flow_ms=("flow_duration_ms", "mean")).round(2).reset_index()
    st.dataframe(summary, hide_index=True, width="stretch")
    a, b = st.columns(2)
    a.plotly_chart(_bar(summary, "mean_packets", "Packets per lookup (from the capture)", "Packets"), width="stretch")
    if summary["mean_handshake_ms"].notna().any():
        b.plotly_chart(_bar(summary, "mean_handshake_ms", "TCP handshake time (UDP has none)", "Milliseconds"), width="stretch")
    st.caption("A capture may also contain traffic from other apps (for example a browser using Google DNS). "
               "Close other apps before capturing. TCP flow time includes connection teardown.")

    st.subheader("What an observer on the network can read")
    c1, c2, c3 = st.columns(3)
    with c1.container(border=True):
        st.markdown("**DNS-UDP (port 53)**")
        st.write("Domain names readable: " + (", ".join(f"`{n}`" for n in names) if names else "none found"))
    with c2.container(border=True):
        st.markdown("**DoT (TCP 853)**")
        st.write("Domain names readable: **no** (encrypted)")
        st.write(f"`dns.google` visible in clear text: **{'yes' if sni['DoT'] else 'not found'}**")
    with c3.container(border=True):
        st.markdown("**DoH (TCP 443)**")
        st.write("Domain names readable: **no** (encrypted)")
        st.write(f"`dns.google` visible in clear text: **{'yes' if sni['DoH'] else 'not found'}**")

    st.subheader("Screenshots")
    shots = st.file_uploader("Add your Wireshark screenshots", type=["png", "jpg", "jpeg"],
                             accept_multiple_files=True, key="ws_shots")
    if shots:
        cols = st.columns(2)
        for i, shot in enumerate(shots):
            cols[i % 2].image(shot, caption=shot.name, width="stretch")
