# SOC Threat Hunting — Zeek Beaconing Analysis

Hypothesis-driven threat hunting project using Zeek network telemetry to identify and investigate periodic outbound communication candidates.

## Project status

Initial hypothesis and repository baseline.

No hunting result is claimed yet.

## Operational problem

A SOC may have no conclusive alert indicating command-and-control activity even though compromised endpoints are communicating periodically with external infrastructure.

This project investigates whether statistically periodic communication patterns can surface useful hunting candidates without treating periodicity alone as proof of malicious behavior.

## Objective

Analyze Zeek connection telemetry, calculate periodicity features, rank candidate communication patterns, enrich them with context, and document an analyst verdict.

## Hunt hypothesis

A compromised endpoint may be establishing periodic outbound communications consistent with beaconing behavior.

See:

`docs/hypothesis.md`

## Planned data source

Primary:

- Zeek connection telemetry.

Contextual sources may include:

- Zeek DNS telemetry.
- Asset information.
- Protocol and destination port.
- Connection duration and byte volume.

## Safety and analysis principles

- Only authorized SOC lab telemetry will be used.
- Periodicity alone is not considered evidence of malicious activity.
- Statistical candidates require analyst validation.
- Legitimate periodic traffic will be included as comparison data.
- Findings, false candidates and limitations will be documented.

## Planned workflow

Zeek telemetry
-> normalization
-> grouping
-> inter-arrival analysis
-> statistical feature calculation
-> candidate ranking
-> contextual investigation
-> analyst verdict

## Repository roadmap

Planned components:

- `docs/` — hypothesis, methodology, validation and limitations.
- `src/` — loading, feature engineering, ranking and CLI modules.
- `tests/` — feature and edge-case validation.
- `samples/` — sanitized Zeek sample data.
- `evidence/` — findings and candidate ranking evidence.

## Current limitations

- No dataset has been selected yet.
- No time window has been defined yet.
- No ranking algorithm has been implemented yet.
- No hunting conclusion has been produced yet.
## SEC-HUNT-001 Results

SEC-HUNT-001 analyzed Zeek connection telemetry for periodic outbound communication from `WIN11-EP-01`.

### Observed dataset

- 5,541 Zeek connection events
- 5,475 events originating from the investigated endpoint
- 13 destination/port/protocol groups
- 7 groups with at least five observations

The workflow calculates inter-arrival times, mean interval, population standard deviation, and coefficient of variation (CV), then ranks groups by timing regularity.

The strongest periodic candidates were legitimate network/infrastructure traffic, including DHCP. This demonstrates that periodicity is a hunting signal and not a malicious classification by itself.

No malicious beaconing was confirmed in this dataset.

### Run

    python -m src.features
    python -m src.ranking
    python -m pytest -q

### Project structure

- `src/load.py` - Zeek JSONL ingestion and source filtering
- `src/features.py` - grouping and periodicity features
- `src/ranking.py` - candidate ranking and CSV output
- `tests/` - automated tests
- `docs/hypothesis.md` - hunt hypothesis
- `docs/methodology.md` - methodology
- `docs/analyst-validation.md` - analyst validation
- `docs/limitations.md` - limitations
- `evidence/candidate-ranking.csv` - derived ranking
- `evidence/findings.md` - findings
- `evidence/evidence-manifest.md` - evidence provenance

Raw Zeek telemetry is intentionally excluded from Git.

