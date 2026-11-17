"""Summarise a Wireshark capture per protocol (traffic to/from 8.8.8.8 only).
    python wireshark/pcap_summary.py data/raw/capture_wifi.pcapng
Each lookup is a 'flow' (one client port). Writes <capture>_flows.csv next to the capture."""
import sys
from pathlib import Path

import pandas as pd
from scapy.all import DNS, IP, TCP, UDP, rdpcap

RESOLVER = "8.8.8.8"
PORTS = {("udp", 53): "DNS-UDP", ("tcp", 853): "DoT", ("tcp", 443): "DoH"}


def classify(pkt):
    if IP not in pkt or RESOLVER not in (pkt[IP].src, pkt[IP].dst):
        return None
    layer, kind = (pkt[UDP], "udp") if UDP in pkt else (pkt[TCP], "tcp") if TCP in pkt else (None, None)
    if layer is None:
        return None
    outbound = pkt[IP].dst == RESOLVER
    server_port, client_port = (layer.dport, layer.sport) if outbound else (layer.sport, layer.dport)
    protocol = PORTS.get((kind, server_port))
    return (protocol, client_port, outbound, layer) if protocol else None


def summarise(path):
    flows = {}
    for pkt in rdpcap(str(path)):
        info = classify(pkt)
        if not info:
            continue
        protocol, port, outbound, layer = info
        f = flows.setdefault((protocol, port), dict(protocol=protocol, client_port=port, packets=0, bytes=0,
                             first=float(pkt.time), last=float(pkt.time), syn=None, synack=None, reply=None))
        t = float(pkt.time)
        f["packets"] += 1
        f["bytes"] += len(pkt)
        f["last"] = t
        if protocol == "DNS-UDP" and not outbound and f["reply"] is None:
            f["reply"] = t
        if protocol != "DNS-UDP":
            flags = int(layer.flags)
            if flags & 0x02 and not flags & 0x10 and f["syn"] is None:
                f["syn"] = t
            if flags & 0x12 == 0x12 and f["synack"] is None:
                f["synack"] = t
    rows = []
    for f in flows.values():
        udp = f["protocol"] == "DNS-UDP"
        rows.append(dict(
            protocol=f["protocol"], client_port=f["client_port"], packets=f["packets"], bytes=f["bytes"],
            tcp_handshake_ms=None if udp or not (f["syn"] and f["synack"]) else round((f["synack"] - f["syn"]) * 1000, 2),
            flow_duration_ms=round(((f["reply"] - f["first"]) if udp and f["reply"] else (f["last"] - f["first"])) * 1000, 2),
        ))
    return pd.DataFrame(rows)


def observer_view(path):
    """What someone watching the network could read: plain DNS names, and whether 'dns.google'
    appears in clear text inside the TCP payloads (the TLS server name)."""
    names, sni = set(), {"DoT": False, "DoH": False}
    for pkt in rdpcap(str(path)):
        info = classify(pkt)
        if not info:
            continue
        protocol, _, _, layer = info
        if protocol == "DNS-UDP":
            if pkt.haslayer(DNS) and pkt[DNS].qd is not None:
                names.add(pkt[DNS].qd.qname.decode(errors="replace").rstrip("."))
        elif b"dns.google" in bytes(layer.payload):
            sni[protocol] = True
    return sorted(names), sni


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("Usage: python wireshark/pcap_summary.py <capture.pcapng>")
    path = Path(sys.argv[1])
    flows = summarise(path)
    if flows.empty:
        sys.exit("No traffic to/from 8.8.8.8 on UDP 53, TCP 853 or TCP 443 found in this capture.")
    out = path.with_name(path.stem + "_flows.csv")
    flows.to_csv(out, index=False)
    summary = flows.groupby("protocol").agg(
        lookups=("protocol", "size"), mean_packets=("packets", "mean"), mean_bytes=("bytes", "mean"),
        mean_handshake_ms=("tcp_handshake_ms", "mean"), mean_flow_ms=("flow_duration_ms", "mean")).round(2)
    print(summary.to_string())
    print(f"\nPer-lookup flows saved to {out}")
    print("Note: TCP flow duration includes connection teardown; UDP duration is request to first reply.")
