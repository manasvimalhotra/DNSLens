"""Clean capture helper. Start Wireshark capturing FIRST, then run:
    python wireshark/wireshark_demo.py [domain]
One lookup per protocol, 3 s apart, so each shows up as a separate burst in Wireshark."""
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent))
from backend.dns_engine import PROTOCOLS, query_once  # noqa: E402

domain = sys.argv[1] if len(sys.argv) > 1 else "example.com"
print(f"Lookup of {domain} (A record). Match these times against Wireshark's packet list.\n")
for protocol in PROTOCOLS:
    stamp = datetime.now(timezone.utc).strftime("%H:%M:%S.%f")[:-3]
    r = query_once(protocol, domain, 5.0)
    print(f"{stamp} UTC  {protocol:8} ok={r['request_success']!s:5} {r['elapsed_ms']:8.2f} ms  "
          f"rcode={r['dns_rcode'] or '-'}  ips={r['resolved_ips'] or '-'}  {r['error']}")
    time.sleep(3)
print("\nDone. Stop the capture and save it as data/raw/capture_<network>.pcapng")
