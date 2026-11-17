# DNSLens

A Computer Networks project that compares the lookup time of **Traditional DNS (UDP 53)**, **DNS over TLS (DoT, TCP 853)** and **DNS over HTTPS (DoH, TCP 443)**, all sent to Google Public DNS, and verifies the traffic with **Wireshark**.

**Research question:** for the same domains and the same resolver, how does one-shot lookup time differ between the three transports on our network?

## How it works

```
User -> Streamlit dashboard (app.py) -> experiment runner -> DNS engine -> Google Public DNS
                                                                 |
                 charts, tables, CSV  <-  result rows  <---------+
```

- The dashboard collects input and shows results. It contains no DNS code.
- The backend sends one A-record query per attempt over each transport, times it with `time.perf_counter()`, and records one row per attempt.
- Every DoT and DoH attempt opens a fresh connection, so its time includes TLS setup. UDP has no handshake.
- Wireshark captures show the ports used and what an observer can read.

## Project structure

```
DNSLens/
  app.py                    Streamlit dashboard
  check.py                  One-domain, three-protocol check
  backend/
    dns_engine.py           One lookup over UDP, DoT or DoH
    experiment.py           run_experiment(): repetitions, rotation, CSV saving
  frontend/
    charts.py               Statistics and Plotly figures
    demo.py                 Demo rows (labelled DEMO DATA, never real results)
    wireshark_tab.py        Wireshark evidence tab
  wireshark/
    WIRESHARK_GUIDE.md      How to capture and what to show
    wireshark_demo.py       One lookup per protocol for a clean capture
    pcap_summary.py         Summarises a saved capture
  tests/                    Backend unit tests
  data/raw/                 Measurements and captures (kept local, see below)
  requirements.txt
```

## Setup

Use Python 3.11 or newer. Each computer creates its own `.venv`; never copy one between machines.

**macOS (Terminal)**
```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

**Windows (PowerShell)**
```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```
If PowerShell blocks activation: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`, then activate again.

## Run

```bash
python check.py                      # quick test: 1 domain x 3 protocols
python -m unittest discover -s tests -t .   # backend tests
python -m streamlit run app.py       # dashboard at http://localhost:8501
```

If the backend cannot be imported, the dashboard starts in **demo mode**. Demo rows are random placeholders and are labelled **DEMO DATA - NOT MEASURED**.

## Running the experiment

1. Close other apps and downloads. Use the same domains, timeout and repetitions for every run.
2. In the sidebar, enter 8 to 10 domains, 5 or more repetitions, and the network label, then run.
3. The backend writes the raw CSV to `data/raw/` as it runs. Do not edit it.
4. Use the **Charts** and **Compare runs** tabs to inspect and compare networks.

## Wireshark evidence

See `wireshark/WIRESHARK_GUIDE.md`. In short:

1. Capture on the Wi-Fi interface with the capture filter `host 8.8.8.8`.
2. Run `python wireshark/wireshark_demo.py example.com`.
3. Save the capture as `data/raw/capture_wifi.pcapng`.
4. Summarise it with `python wireshark/pcap_summary.py data/raw/capture_wifi.pcapng`, or open the dashboard's **Wireshark** tab.

## About the data in this repository

`data/raw/` is git-ignored by default so that personal captures are not published by accident. The official dataset and capture are submitted separately (or force-added with `git add -f`).

## Limitations

- One-shot timing: DoT and DoH include connection and TLS setup. This is not pure server processing time and not website load time.
- Google Public DNS may serve cached answers, so lookups are not guaranteed cold.
- Results apply only to the tested device, network, resolver and time window. They do not prove that any protocol is always faster or slower.
- Failed attempts stay in the raw data; a blocked port is a valid observation.

## Team

- Backend and networking: _name_
- Frontend and dashboard: _name_
