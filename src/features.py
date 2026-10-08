from collections import defaultdict
from pathlib import Path
from statistics import mean, pstdev

from .load import load_events, filter_source

REPO_ROOT = Path(__file__).resolve().parent.parent
DATASET_PATH = (
    REPO_ROOT / "evidence" / "raw" / "sec-hunt-001-zeek-conn-2026-10-08.jsonl"
)

SOURCE_IP = "10.50.20.22"
MIN_EVENTS = 5


def group_connections(events: list[dict]) -> dict[tuple, list[float]]:
    groups = defaultdict(list)

    for event in events:
        destination_ip = event.get("id.resp_h")
        destination_port = event.get("id.resp_p")
        protocol = event.get("proto")
        timestamp = event.get("ts")

        if (
            destination_ip is None
            or destination_port is None
            or protocol is None
            or timestamp is None
        ):
            continue

        key = (
            destination_ip,
            destination_port,
            protocol,
        )

        groups[key].append(float(timestamp))

    return dict(groups)


def calculate_intervals(timestamps: list[float]) -> list[float]:
    ordered = sorted(timestamps)

    return [ordered[index] - ordered[index - 1] for index in range(1, len(ordered))]


def calculate_features(
    groups: dict[tuple, list[float]],
    min_events: int = MIN_EVENTS,
) -> list[dict]:

    results = []

    for key, timestamps in groups.items():
        if len(timestamps) < min_events:
            continue

        intervals = calculate_intervals(timestamps)

        if not intervals:
            continue

        interval_mean = mean(intervals)
        interval_std = pstdev(intervals)

        if interval_mean == 0:
            coefficient_variation = None
        else:
            coefficient_variation = interval_std / interval_mean

        destination_ip, destination_port, protocol = key

        results.append(
            {
                "destination_ip": destination_ip,
                "destination_port": destination_port,
                "protocol": protocol,
                "event_count": len(timestamps),
                "mean_interval_seconds": interval_mean,
                "std_interval_seconds": interval_std,
                "coefficient_variation": coefficient_variation,
            }
        )

    return results


if __name__ == "__main__":
    events = load_events(DATASET_PATH)
    source_events = filter_source(events, SOURCE_IP)

    groups = group_connections(source_events)
    features = calculate_features(groups)

    ranked = sorted(
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

    print(f"Dataset events: {len(events)}")
    print(f"Source events: {len(source_events)}")
    print(f"Connection groups: {len(groups)}")
    print(f"Groups with >= {MIN_EVENTS} events: {len(features)}")
    print()
    print("Top periodicity candidates:")
    print()

    for candidate in ranked[:20]:
        print(
            f'{candidate["destination_ip"]}:'
            f'{candidate["destination_port"]}/'
            f'{candidate["protocol"]} '
            f'count={candidate["event_count"]} '
            f'mean={candidate["mean_interval_seconds"]:.2f}s '
            f'std={candidate["std_interval_seconds"]:.2f}s '
            f'cv={candidate["coefficient_variation"]:.4f}'
        )

