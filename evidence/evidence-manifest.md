# Evidence Manifest

## Raw dataset

File:

`sec-hunt-001-zeek-conn-2026-10-08.jsonl`

Raw location:

`evidence/raw/`

The raw dataset is intentionally excluded from Git.

Events:

5,541

SHA-256:

`308d4f4e9c27f44f9a7d903e784136cb96d532ea02fa0448a13b2b5fe29c34e0`

## Integrity check

    sha256sum evidence/raw/sec-hunt-001-zeek-conn-2026-10-08.jsonl
    # PowerShell: Get-FileHash evidence\raw\sec-hunt-001-zeek-conn-2026-10-08.jsonl -Algorithm SHA256

## Derived evidence

- `candidate-ranking.csv` — generated with
  `python -m src.cli --input evidence/raw/sec-hunt-001-zeek-conn-2026-10-08.jsonl --output evidence/candidate-ranking.csv`
- `findings.md`
- `../docs/analyst-validation.md`

## Not evidence

`samples/synthetic-conn.jsonl` is synthetic test data and is not part of this hunt.

## Source

Security Onion / Zeek connection telemetry.

## Investigated endpoint

WIN11-EP-01

10.50.20.22
