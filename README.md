# SOC Threat Hunting — Zeek Beaconing Analysis (SEC-HUNT-001)

[![CI](https://github.com/CarlosGutierrezR/soc-threat-hunting-zeek/actions/workflows/ci.yml/badge.svg)](https://github.com/CarlosGutierrezR/soc-threat-hunting-zeek/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

Hypothesis-driven threat hunt for command-and-control **beaconing** in Zeek
`conn` telemetry captured in a segmented home SOC lab (pfSense, Security Onion,
Wazuh, Active Directory). Connections are grouped, inter-arrival times are
measured, groups are ranked by timing regularity (coefficient of variation),
and every candidate gets a documented analyst verdict.

> **Result:** the hypothesis was investigated and **not confirmed**. The two most
> periodic groups were legitimate (IGMP multicast and DHCP). Periodicity is a
> prioritisation signal, not a detection.

**Contents:** [Quickstart](#quickstart-for-reviewers) ·
[Lab environment](#lab-environment) ·
[Step-by-step walkthrough](#step-by-step-walkthrough) ·
[Results](#results) · [Usage](#usage) · [Repository layout](#repository-layout) ·
[Limitations](#limitations-and-next-steps)

## Quickstart for reviewers

```bash
git clone https://github.com/CarlosGutierrezR/soc-threat-hunting-zeek.git
cd soc-threat-hunting-zeek
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
pytest                                               # unit + end-to-end tests
python -m src.cli --input samples/synthetic-conn.jsonl
```

No third-party runtime dependencies (standard library only). The bundled
sample is **synthetic** with known ground truth — see [`samples/README.md`](samples/README.md).
The real lab dataset is not published; its SHA-256 is recorded in the
[evidence manifest](evidence/evidence-manifest.md).

## What this project demonstrates

| Skill | Where |
|---|---|
| Building and validating a monitoring pipeline (sensor → Zeek → Elasticsearch) | [Walkthrough, steps 1–3](#step-by-step-walkthrough) |
| Hypothesis-driven hunting (scope, guardrails, verdict categories) | [`docs/hypothesis.md`](docs/hypothesis.md) |
| Statistical beaconing analysis on Zeek data | [`src/features.py`](src/features.py) |
| Analyst validation and false-positive handling | [`docs/analyst-validation.md`](docs/analyst-validation.md) |
| Evidence handling (frozen dataset, SHA-256, screenshots) | [`evidence/`](evidence) |
| Honest reporting of limitations | [`docs/limitations.md`](docs/limitations.md) |
| Testable, CI-checked Python | [`tests/`](tests), [`.github/workflows/ci.yml`](.github/workflows/ci.yml) |

## Lab environment

All systems run as virtual machines on a single VMware Workstation host.
pfSense segments the lab into isolated internal networks; the Security Onion
sensor monitors the endpoint segment.

```mermaid
flowchart LR
    subgraph EP["LAB_ENDPOINTS · 10.50.20.0/24"]
        W11["WIN11-EP-01<br/>Windows 11 endpoint<br/>10.50.20.22"]
    end
    FW["SOC-FW-01 · pfSense<br/>routing, filtering<br/>gateway + DHCP 10.50.20.254"]
    subgraph ID["IDENTITY · 10.50.30.0/24"]
        DC["DC01<br/>AD DS + DNS · soclab.test<br/>10.50.30.10"]
    end
    subgraph MGMT["SOC management · 10.50.10.0/24"]
        WZ["SOC-WAZUH-01<br/>Wazuh manager<br/>10.50.10.10"]
        SO["SOC-SECURITY-ONION-01<br/>Security Onion 3.3.0 (Evaluation)<br/>Zeek · Elasticsearch · Hunt<br/>10.50.10.30"]
    end

    W11 -- "DHCP 67/udp" --> FW
    FW -- "DNS 53/udp" --> DC
    FW -- "Wazuh agent 1514-1515/tcp" --> WZ
    EP -. "sensor monitors segment" .-> SO
```

| Component | Role in this hunt |
|---|---|
| `SOC-FW-01` (pfSense) | Inter-segment routing and filtering; DHCP for the endpoint segment (`10.50.20.254`) |
| `SOC-SECURITY-ONION-01` (Security Onion 3.3.0, Evaluation) | Network sensor: Zeek logs, Elasticsearch storage, Hunt UI |
| `WIN11-EP-01` | Investigated endpoint (`10.50.20.22`) |
| `DC01` | Active Directory Domain Services and DNS for `soclab.test` (`10.50.30.10`) |
| `SOC-WAZUH-01` | Wazuh manager; the endpoint's agent reports on `1514/tcp` and enrols on `1515/tcp` |

## Step-by-step walkthrough

Each step links the claim to the screenshot that supports it. All screenshots
are in [`evidence/screenshots/`](evidence/screenshots) and are described in
[`evidence/README.md`](evidence/README.md).

### 1. Verify the monitoring platform is healthy

The Security Onion grid reports node `onion` (Evaluation role, `10.50.10.30`,
version 3.3.0) with status **OK**, and Elastic Fleet shows both agents
(`FleetServer-onion`, `onion`) **Healthy**.

<p>
  <img src="evidence/screenshots/01_platform/01-security-onion-grid-health.png" width="49%" alt="Security Onion grid with node onion in OK status">
  <img src="evidence/screenshots/01_platform/02-elastic-fleet-agents-healthy.png" width="49%" alt="Elastic Fleet with two healthy agents">
</p>

### 2. Confirm the sensor sees the endpoint's traffic

`tcpdump` on the sensor interface shows packets from `10.50.20.22` (DNS to
`10.50.30.10`, TCP to `10.50.10.10`, ARP with the gateway) with 0 packets
dropped by the kernel. Zeek writes `conn.log` and `dns.log` in JSON under
`/nsm/zeek/logs/current/`.

<p>
  <img src="evidence/screenshots/02_telemetry/01-packet-visibility-and-zeek-current-logs.png" width="49%" alt="tcpdump output and Zeek current log directory">
  <img src="evidence/screenshots/02_telemetry/02-zeek-conn-and-dns-json-events.png" width="49%" alt="Raw Zeek conn.log and dns.log JSON events">
</p>

### 3. Confirm ingestion into Elasticsearch

The `logs-zeek-so` data stream exists with status **GREEN** and 90-day
retention, `_count` returns indexed Zeek documents, and the most recent
document is a `zeek.conn` event from `10.50.20.22`.

<p>
  <img src="evidence/screenshots/02_telemetry/03-elasticsearch-zeek-data-stream-green.png" width="32%" alt="logs-zeek-so data stream in GREEN status">
  <img src="evidence/screenshots/02_telemetry/04-elasticsearch-zeek-document-count.png" width="32%" alt="Elasticsearch count of Zeek documents">
  <img src="evidence/screenshots/02_telemetry/05-elasticsearch-latest-zeek-conn-event.png" width="32%" alt="Latest zeek.conn document">
</p>

### 4. Scope the hunt in Security Onion Hunt

Query `event.dataset:zeek.conn AND source.ip:10.50.20.22` isolates the
endpoint's connections. The timeline gives a first view of volume over time.

<p>
  <img src="evidence/screenshots/03_hunt/02-security-onion-hunt-win11-source-filter.png" width="49%" alt="Hunt filtered to source 10.50.20.22">
  <img src="evidence/screenshots/03_hunt/03-security-onion-hunt-timeline.png" width="49%" alt="Hunt timeline for the endpoint">
</p>

> The Hunt counts in these screenshots cover a rolling 24-hour window at the
> time of capture. They are context, not the analysed dataset (step 5).

### 5. Freeze the dataset

The endpoint's Zeek `conn` events were frozen into
`sec-hunt-001-zeek-conn-2026-10-08.jsonl` (5,541 events) and hashed with
SHA-256 so the analysis can be repeated on exactly the same data. The raw file
stays out of Git (`evidence/raw/` is ignored).

```bash
sha256sum evidence/raw/sec-hunt-001-zeek-conn-2026-10-08.jsonl
# 308d4f4e9c27f44f9a7d903e784136cb96d532ea02fa0448a13b2b5fe29c34e0
```

### 6. Compute periodicity features and rank candidates

```bash
python -m src.cli \
  --input evidence/raw/sec-hunt-001-zeek-conn-2026-10-08.jsonl \
  --output evidence/candidate-ranking.csv
```

Events are filtered to `10.50.20.22`, grouped by destination IP, destination
port and transport, and each group with at least 5 events gets mean
inter-arrival time, population standard deviation and
CV = σ / μ. Groups are ranked by ascending CV. Low CV means regular timing; it
does not mean malicious.

### 7. Validate each candidate with context

Every ranked group is checked against protocol, destination and lab
infrastructure context — see [`docs/analyst-validation.md`](docs/analyst-validation.md).

### 8. Record the verdict and limitations

Findings, verdict and limitations are recorded in
[`evidence/findings.md`](evidence/findings.md) and
[`docs/limitations.md`](docs/limitations.md).

## Results

| | |
|---|---|
| Hypothesis | A compromised endpoint may be beaconing periodically to external infrastructure. |
| Asset | `WIN11-EP-01` (`10.50.20.22`) |
| Dataset | 5,541 events · 5,475 from the endpoint · 13 groups · 7 with ≥ 5 events |
| Verdict | **No malicious beaconing confirmed.** |

| Rank | Destination | Events | Mean interval | CV | Verdict |
|---:|---|---:|---:|---:|---|
| 1 | `224.0.0.22` (IGMP, IP proto 2) | 5 | ≈ 3600 s | ≈ 0.00001 | Benign periodic — multicast group reports |
| 2 | `10.50.20.254:67/udp` (DHCP) | 5 | ≈ 3600 s | ≈ 0.00001 | Benign periodic — lease renewal with pfSense |
| 3 | `10.50.10.10:1514/tcp` | 1,385 | 11.7 s | 0.66 | Wazuh agent traffic — lab infrastructure |
| 4 | `239.255.255.250:1900/udp` | 8 | 2,040 s | 0.76 | SSDP multicast — not malicious from timing alone |
| 5 | `10.50.30.10:53/udp` | 3,772 | 4.3 s | 0.96 | DNS to DC01 — includes retries while DC01 was unavailable |
| 6 | `10.50.10.10:1515/tcp` | 276 | 58.4 s | 1.24 | Wazuh agent enrolment — lab infrastructure |
| 7 | `224.0.0.252:5355/udp` | 12 | 1,309 s | 1.31 | LLMNR multicast — not malicious from timing alone |

Source: [`evidence/candidate-ranking.csv`](evidence/candidate-ranking.csv).
The key lesson: a periodicity-only detector would have escalated DHCP and IGMP
first. Context is what turns a statistical candidate into a verdict.

## Usage

```
python -m src.cli --input PATH [--source-ip IP] [--min-events N] [--output CSV] [--top N]
```

| Option | Default | Description |
|---|---|---|
| `--input` | required | Zeek `conn.log` in JSON Lines format |
| `--source-ip` | `10.50.20.22` | Originator (`id.orig_h`) to hunt on |
| `--min-events` | `5` | Minimum connections per group |
| `--output` | none | Write the full ranking to CSV |
| `--top` | `20` | Candidates printed to the console |

## Repository layout

```
.
├── src/                 # pipeline: load, features, ranking, CLI
├── tests/               # unit tests + end-to-end test on the synthetic sample
├── samples/             # synthetic Zeek conn sample with ground truth
├── scripts/             # deterministic sample generator
├── docs/                # hypothesis, methodology, analyst validation, limitations
├── evidence/            # ranking, findings, manifest, screenshots (raw/ is git-ignored)
└── .github/workflows/   # CI: ruff + pytest on Python 3.10 and 3.12
```

## Data handling

- Only authorised, isolated lab telemetry was analysed.
- Raw telemetry (`evidence/raw/`) and packet captures are excluded from Git.
- Screenshots show private lab addressing only.
- The bundled sample is synthetic and uses RFC 5737 documentation addresses for external hosts.

## Limitations and next steps

Details in [`docs/limitations.md`](docs/limitations.md). In short: groups of
5 events can look deceptively regular; grouping by port is weak for non-TCP/UDP
protocols such as IGMP; one endpoint and a short window; no malicious ground
truth in the lab dataset; part of the traffic reflects lab outages (DC01
unavailable) rather than normal operation.

Planned next iteration:

- Controlled beacon from the lab (known ground truth) to measure detection.
- IP-protocol semantics and jitter-tolerant features (interval histogram / MAD).
- Enrichment with Zeek DNS, connection state, byte/duration patterns and asset role.

<details>
<summary>Troubleshooting notes</summary>

A `terms` aggregation on `destination.ip` over 24 hours returned HTTP 429
`circuit_breaking_exception` (parent breaker, ~570 MB limit) on the Evaluation
node. The breaker is reported as `TRANSIENT`.

<img src="evidence/screenshots/99_troubleshooting/01-elasticsearch-circuit-breaker.png" width="70%" alt="Elasticsearch circuit breaker exception">

</details>

## License

[MIT](LICENSE)
