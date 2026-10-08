# SOC Threat Hunting — Zeek Beaconing Analysis (SEC-HUNT-001)

[![CI](https://github.com/CarlosGutierrezR/soc-threat-hunting-zeek/actions/workflows/ci.yml/badge.svg)](https://github.com/CarlosGutierrezR/soc-threat-hunting-zeek/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

Hypothesis-driven threat hunt for command-and-control **beaconing** in Zeek
`conn` telemetry from a home SOC lab (Security Onion + Wazuh). Connections are
grouped, inter-arrival times are measured, groups are ranked by timing
regularity (coefficient of variation), and every candidate gets a documented
analyst verdict.

> **Result:** the hypothesis was investigated and **not confirmed**. The two most
> periodic groups were legitimate (DHCP and IGMP multicast). Periodicity is a
> prioritisation signal, not a detection.

## TL;DR for reviewers

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

## What this project demonstrates

| Skill | Where |
|---|---|
| Hypothesis-driven hunting (scope, guardrails, verdict categories) | [`docs/hypothesis.md`](docs/hypothesis.md) |
| Statistical beaconing analysis on Zeek data | [`src/features.py`](src/features.py) |
| Analyst validation and false-positive handling | [`docs/analyst-validation.md`](docs/analyst-validation.md) |
| Evidence handling (frozen dataset, SHA-256, provenance) | [`evidence/evidence-manifest.md`](evidence/evidence-manifest.md) |
| Honest reporting of limitations | [`docs/limitations.md`](docs/limitations.md) |
| Testable, CI-checked Python | [`tests/`](tests), [`.github/workflows/ci.yml`](.github/workflows/ci.yml) |

## Hunt summary

| | |
|---|---|
| Hypothesis | A compromised endpoint may be beaconing periodically to external infrastructure. |
| Asset | `WIN11-EP-01` (`10.50.20.22`) |
| Telemetry | Security Onion / Zeek `conn` (JSONL), frozen snapshot |
| Dataset | 5,541 events · 5,475 from the endpoint · 13 groups · 7 with ≥ 5 events |
| Method | Group by destination IP / port / transport → inter-arrival times → mean, population std, CV → rank by ascending CV |
| Verdict | No malicious beaconing confirmed. Top candidates benign periodic (IGMP `224.0.0.22`, DHCP `10.50.20.254:67/udp`). |

Full ranking: [`evidence/candidate-ranking.csv`](evidence/candidate-ranking.csv) ·
Findings: [`evidence/findings.md`](evidence/findings.md)

## Workflow

```
Zeek conn.log (JSONL)
  -> load + validate            src/load.py
  -> filter source endpoint     src/load.py
  -> group (dst IP, port, proto) src/features.py
  -> inter-arrival times, CV    src/features.py
  -> rank candidates            src/ranking.py
  -> contextual investigation   docs/analyst-validation.md
  -> analyst verdict            evidence/findings.md
```

CV = σ(intervals) / μ(intervals). Low CV means regular timing; it does not mean malicious.

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

Reproduce the SEC-HUNT-001 evidence (requires the raw dataset, which is not in Git):

```bash
python -m src.cli \
  --input evidence/raw/sec-hunt-001-zeek-conn-2026-10-08.jsonl \
  --output evidence/candidate-ranking.csv
```

Verify the raw file first against the SHA-256 in the
[evidence manifest](evidence/evidence-manifest.md).

## Repository layout

```
.
├── src/                 # pipeline: load, features, ranking, CLI
├── tests/               # unit tests + end-to-end test on the synthetic sample
├── samples/             # synthetic Zeek conn sample with ground truth
├── scripts/             # deterministic sample generator
├── docs/                # hypothesis, methodology, analyst validation, limitations
├── evidence/            # derived ranking, findings, evidence manifest (raw/ is git-ignored)
└── .github/workflows/   # CI: ruff + pytest on Python 3.10 and 3.12
```

## Data handling

- Only authorised SOC lab telemetry was analysed.
- Raw telemetry (`evidence/raw/`) and packet captures are excluded from Git.
- The bundled sample is synthetic and uses RFC 5737 documentation addresses for external hosts.

## Limitations and next steps

Key limitations (details in [`docs/limitations.md`](docs/limitations.md)):
small groups (5 events) yield deceptively low CV; grouping by port is weak for
non-TCP/UDP protocols such as IGMP; one endpoint and a short window; no
malicious ground truth in the lab dataset.

Planned next iteration:

- Controlled beacon in the lab (known ground truth) to measure detection.
- Add IP-protocol semantics and jitter-tolerant features (e.g. interval histogram / MAD).
- Enrich with Zeek DNS, byte/duration patterns and asset role.

## License

[MIT](LICENSE)
