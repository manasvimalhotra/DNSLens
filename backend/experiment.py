"""Experiment runner: repetitions, rotating protocol order, partial CSV saving."""
import csv
import uuid
from datetime import datetime, timezone
from pathlib import Path

from backend import dns_engine

FIELDS = ["timestamp_utc", "run_id", "network_label", "domain", "record_type", "protocol",
          "resolver", "attempt", "elapsed_ms", "request_success", "dns_rcode",
          "resolved_ips", "error", "timeout_s"]
RAW_DIR = Path(__file__).resolve().parent.parent / "data" / "raw"


def normalize_domains(domains):
    """Lowercase, strip, drop blanks and duplicates (order preserved)."""
    cleaned = [d.strip().lower().rstrip(".") for d in domains if d and d.strip()]
    return list(dict.fromkeys(cleaned))


def run_experiment(domains, repetitions, network_label, timeout_s=5.0, save_csv=True, out_dir=None):
    """Return one dict per attempt (domains x 3 protocols x repetitions).

    Sequential on purpose. Protocol order rotates every round and domain, so UDP is not
    always first. Each row is appended to a CSV immediately, so a late crash keeps earlier data.
    """
    domains = normalize_domains(domains)
    if not domains:
        raise ValueError("No domains supplied.")
    if repetitions < 1:
        raise ValueError("repetitions must be at least 1.")

    run_id = uuid.uuid4().hex[:8]
    protocols = dns_engine.PROTOCOLS
    rows, writer, handle = [], None, None
    if save_csv:
        folder = Path(out_dir) if out_dir else RAW_DIR
        folder.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        handle = open(folder / f"dnslens_{stamp}_{run_id}.csv", "w", newline="", encoding="utf-8-sig")
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
    try:
        for attempt in range(1, repetitions + 1):
            for d_index, domain in enumerate(domains):
                shift = (attempt + d_index) % len(protocols)
                for protocol in protocols[shift:] + protocols[:shift]:
                    outcome = dns_engine.query_once(protocol, domain, timeout_s)
                    row = {
                        "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                        "run_id": run_id, "network_label": network_label, "domain": domain,
                        "record_type": "A", "protocol": protocol,
                        "resolver": dns_engine.RESOLVER_NAME, "attempt": attempt,
                        **outcome, "timeout_s": timeout_s,
                    }
                    rows.append(row)
                    if writer:
                        writer.writerow(row)
                        handle.flush()
    finally:
        if handle:
            handle.close()
    return rows
