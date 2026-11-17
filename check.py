"""Checkpoint B: one domain, three protocols. Run: python check.py [domain]"""
import sys
from backend.experiment import run_experiment

domain = sys.argv[1] if len(sys.argv) > 1 else "example.com"
for row in run_experiment([domain], 1, "pilot check", save_csv=False):
    print(f"{row['protocol']:8} ok={row['request_success']!s:5} {row['elapsed_ms']:8.2f} ms "
          f"rcode={row['dns_rcode'] or '-':8} ips={row['resolved_ips'] or '-'} {row['error']}")
