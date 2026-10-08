"""Candidate ranking and CSV export."""

from __future__ import annotations

import csv
from pathlib import Path

FIELDNAMES = [
    "rank",
    "destination_ip",
    "destination_port",
    "protocol",
    "event_count",
    "mean_interval_seconds",
    "std_interval_seconds",
    "coefficient_variation",
]


def rank_candidates(features: list[dict]) -> list[dict]:
    """Sort by ascending CV (undefined CV last), then by descending event count.

    A low rank means regular timing only; it is not a maliciousness score.
    """

    def sort_key(item: dict) -> tuple[float, int]:
        cv = item["coefficient_variation"]
        return (cv if cv is not None else float("inf"), -item["event_count"])

    return sorted(features, key=sort_key)


def write_csv(candidates: list[dict], output_path: Path | str) -> None:
    """Write ranked candidates to ``output_path`` (parent dirs are created)."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDNAMES)
        writer.writeheader()
        for rank, candidate in enumerate(candidates, start=1):
            writer.writerow({"rank": rank, **candidate})
