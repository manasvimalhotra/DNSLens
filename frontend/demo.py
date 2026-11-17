"""Demo rows for UI development ONLY. Never use these as experimental findings."""
import random
from datetime import datetime, timezone

DEMO_LABEL = "DEMO DATA - NOT MEASURED"
_PROTOCOLS = [("DNS-UDP", 24.0), ("DoT", 61.0), ("DoH", 74.0)]  # arbitrary made-up centres


def make_demo_rows(domains, repetitions, timeout_s=5.0, seed=7):
    rng = random.Random(seed)
    rows = []
    for attempt in range(1, repetitions + 1):
        order = _PROTOCOLS[:]
        rng.shuffle(order)
        for domain in domains:
            for protocol, centre in order:
                failed = rng.random() < 0.03
                elapsed = timeout_s * 1000 if failed else max(3.0, rng.gauss(centre, centre * 0.25))
                rows.append({
                    "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                    "run_id": "DEMO",
                    "network_label": DEMO_LABEL,
                    "domain": domain,
                    "record_type": "A",
                    "protocol": protocol,
                    "resolver": "Google Public DNS",
                    "attempt": attempt,
                    "elapsed_ms": round(elapsed, 2),
                    "request_success": not failed,
                    "dns_rcode": "" if failed else "NOERROR",
                    "resolved_ips": "" if failed else "203.0.113.10",
                    "error": "Timeout (demo)" if failed else "",
                    "timeout_s": timeout_s,
                })
    return rows
