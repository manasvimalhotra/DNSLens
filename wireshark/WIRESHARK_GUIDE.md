# DNSLens - Wireshark packet-capture evidence

**Purpose:** the Python timings come from our own program. Wireshark gives independent, packet-level proof of
*what actually travelled on the wire* for each method. It does not replace the Python measurements.

## 1. Install
- **Windows:** download the installer from wireshark.org and keep the **Npcap** option ticked. Run Wireshark as normal.
- **macOS:** install the .dmg from wireshark.org (or `brew install --cask wireshark`) and accept the ChmodBPF
  installer so capturing works without sudo. Log out and back in once if asked.

## 2. Prepare a clean capture
1. Close browsers, cloud sync, video calls and downloads, which add noise.
2. Open Wireshark and double-click your active interface (**Wi-Fi**, or the hotspot connection).
3. Capture filter (before starting, in the capture filter box): `host 8.8.8.8`
4. Start capturing, then in the DNSLens folder run:
   `python wireshark/wireshark_demo.py example.com`
   (one lookup per protocol, 3 s apart; note the printed times).
5. Stop the capture and save as `data/raw/capture_wifi.pcapng` (or `capture_hotspot.pcapng`).
   Optional: capture an entire official run the same way and save it too.

## 3. Display filters to use (type in the green bar)
| What to show | Filter |
|---|---|
| Traditional DNS (readable) | `udp.port == 53 && ip.addr == 8.8.8.8` |
| The domain inside plain DNS | `dns.qry.name == "example.com"` |
| DoT (TCP 853) | `tcp.port == 853` |
| DoH (TCP 443 to Google) | `tcp.port == 443 && ip.addr == 8.8.8.8` |
| TLS handshake only | `tls.handshake` |
| TCP connection setup | `tcp.flags.syn == 1` |
| Server name in the TLS hello | `tls.handshake.extensions_server_name` |

## 4. What you should observe (verify in YOUR capture; do not assume)
- **DNS-UDP:** a query and a response, 2 packets. The domain name and the returned IP are readable in the
  packet details (Domain Name System section). Nothing is encrypted.
- **DoT:** TCP three-way handshake (SYN, SYN-ACK, ACK) on port 853, then a TLS handshake (Client Hello, Server Hello,
  certificate), then **Application Data**. The DNS content is not readable.
- **DoH:** TCP handshake on port 443, TLS handshake with `dns.google` visible as the server name, then encrypted
  Application Data. Looks like ordinary HTTPS to an observer.
- **Why one-shot DoT/DoH cost more here:** each of our attempts opens a new connection, so the handshake packets
  appear in the capture before any DNS data. This is direct evidence for the timing caveat.
- The server name in the TLS hello is still visible, so DoT/DoH do not hide everything.

## 5. Screenshots to take for the report and slides
1. Packet list filtered to UDP 53 with the DNS query/response expanded (readable domain and IP).
2. DoT filtered, showing the SYN / SYN-ACK / ACK, TLS handshake and Application Data.
3. DoH filtered, same view, with the `dns.google` server name expanded.
4. Statistics > Conversations > TCP/UDP tab, showing packets and bytes per conversation.
Tip: View > Time Display Format > Seconds Since Previous Displayed Packet to read gaps between packets.

## 6. Numbers from the capture (optional but impressive)
`python wireshark/pcap_summary.py data/raw/capture_wifi.pcapng`
prints, per protocol: number of lookups, packets and bytes per lookup, TCP handshake time and flow duration,
and saves a per-lookup CSV. Compare these with `elapsed_ms` from the CSV, and state that small differences are
expected (Python overhead, capture timestamps, TCP teardown included in TCP flow duration).

## 7. Report wording
"Packet captures taken with Wireshark on [network] confirm that traditional DNS used UDP port 53 with readable
queries, while DoT used TLS on TCP 853 and DoH used HTTPS on TCP 443, each preceded by a TCP and TLS
handshake. Captures cover the tested device and network only."

## 8. If something goes wrong
- **No packets:** wrong interface selected; pick the one whose graph is moving.
- **Only DNS-UDP visible:** DoT/DoH may be blocked on that network. Capture the failed attempts and report the block.
- **No DoH packets under `host 8.8.8.8`:** check the filter `tcp.port == 443`; confirm the run used `bootstrap_address`.
- **Other apps' traffic to 8.8.8.8:** close them and repeat the capture.
