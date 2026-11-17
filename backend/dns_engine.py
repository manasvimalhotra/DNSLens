"""One DNS lookup over UDP, DoT or DoH to Google Public DNS. No UI code here."""
import time

import dns.exception
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype

RESOLVER_NAME = "Google Public DNS"
RESOLVER_IP = "8.8.8.8"
DOT_HOSTNAME = "dns.google"
DOH_URL = "https://dns.google/dns-query"  # RFC 8484 endpoint
PROTOCOLS = ["DNS-UDP", "DoT", "DoH"]


def build_query(domain):
    """The same A-record question is used for every transport."""
    return dns.message.make_query(domain, "A")


def _send(protocol, query, timeout_s):
    if protocol == "DNS-UDP":
        return dns.query.udp(query, RESOLVER_IP, port=53, timeout=timeout_s)
    if protocol == "DoT":
        return dns.query.tls(query, RESOLVER_IP, port=853, timeout=timeout_s,
                             server_hostname=DOT_HOSTNAME, verify=True)
    if protocol == "DoH":
        return dns.query.https(query, DOH_URL, timeout=timeout_s,
                               bootstrap_address=RESOLVER_IP, verify=True)
    raise ValueError(f"Unknown protocol: {protocol}")


def query_once(protocol, domain, timeout_s=5.0):
    """Run one fresh-connection lookup. Never raises: failures become a result dict.

    Timer covers only the transport call (includes TLS/HTTPS setup for DoT/DoH).
    request_success means a valid DNS response arrived, even if its rcode is NXDOMAIN.
    """
    query = build_query(domain)  # built before the timer starts
    result = {"elapsed_ms": 0.0, "request_success": False, "dns_rcode": "",
              "resolved_ips": "", "error": ""}
    start = time.perf_counter()
    try:
        response = _send(protocol, query, timeout_s)
        result["elapsed_ms"] = round((time.perf_counter() - start) * 1000, 2)
        result["request_success"] = True
        result["dns_rcode"] = dns.rcode.to_text(response.rcode())
        ips = [r.address for rrset in response.answer
               if rrset.rdtype == dns.rdatatype.A for r in rrset]
        result["resolved_ips"] = ";".join(ips)
    except dns.exception.Timeout:
        result["elapsed_ms"] = round((time.perf_counter() - start) * 1000, 2)
        result["error"] = f"Timeout after {timeout_s}s"
    except Exception as exc:  # network, TLS, HTTP, malformed response ...
        result["elapsed_ms"] = round((time.perf_counter() - start) * 1000, 2)
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result
