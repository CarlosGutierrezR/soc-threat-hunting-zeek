import csv
from pathlib import Path

from .features import (
    DATASET_PATH,
    MIN_EVENTS,
    SOURCE_IP,
    calculate_features,
    filter_source,
    group_connections,
)

from .load import load_events

REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_PATH = REPO_ROOT / "evidence" / "candidate-ranking.csv"


def rank_candidates(features: list[dict]) -> list[dict]:
    return sorted(
        features,
        key=lambda item: (
            (
                item["coefficient_variation"]
                if item["coefficient_variation"] is not None
                else float("inf")
            ),
            -item["event_count"],
        ),
    )


def write_csv(candidates: list[dict], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "rank",
        "destination_ip",
        "destination_port",
        "protocol",
        "event_count",
        "mean_interval_seconds",
        "std_interval_seconds",
        "coefficient_variation",
    ]

    with output_path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()

        for rank, candidate in enumerate(candidates, start=1):
            row = {"rank": rank, **candidate}
            writer.writerow(row)


if __name__ == "__main__":
    events = load_events(DATASET_PATH)
    source_events = filter_source(events, SOURCE_IP)

    groups = group_connections(source_events)
    features = calculate_features(groups, MIN_EVENTS)
    ranked = rank_candidates(features)

    write_csv(ranked, OUTPUT_PATH)

    print(f"Dataset events: {len(events)}")
    print(f"Source events: {len(source_events)}")
    print(f"Candidate groups: {len(ranked)}")
    print(f"Ranking written to: {OUTPUT_PATH}")

