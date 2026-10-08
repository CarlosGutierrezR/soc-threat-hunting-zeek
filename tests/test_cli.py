"""End-to-end tests on the synthetic sample (known ground truth)."""

import csv

from src.cli import main


def test_pipeline_surfaces_beacon_and_benign_dhcp(synthetic_sample, tmp_path, capsys):
    output = tmp_path / "ranking.csv"

    assert main(["--input", str(synthetic_sample), "--output", str(output)]) == 0

    with output.open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    ranked = [(r["destination_ip"], r["destination_port"]) for r in rows]

    # Benign DHCP is the most periodic group: periodicity alone is not a verdict.
    assert ranked[0] == ("10.50.20.254", "67")
    # The simulated beacon (with jitter) is the next candidate.
    assert ranked[1] == ("203.0.113.50", "443")
    assert float(rows[1]["coefficient_variation"]) < 0.1
    # Other source host and below-threshold group are excluded.
    assert ("203.0.113.99", "8443") not in ranked
    assert ("192.0.2.10", "123") not in ranked
    assert "NOT a verdict" in capsys.readouterr().out


def test_missing_input_returns_error(tmp_path, capsys):
    assert main(["--input", str(tmp_path / "missing.jsonl")]) == 2
    assert "not found" in capsys.readouterr().err
