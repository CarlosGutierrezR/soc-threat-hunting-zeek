"""Connection grouping and inter-arrival periodicity features."""

from __future__ import annotations

from collections import defaultdict
from statistics import mean, pstdev

DEFAULT_MIN_EVENTS = 5

GroupKey = tuple[str, int, str]


def group_connections(events: list[dict]) -> dict[GroupKey, list[float]]:
    """Group event timestamps by (destination IP, destination port, protocol).

    Events missing any of the required Zeek fields are skipped.
    """
    groups: dict[GroupKey, list[float]] = defaultdict(list)

    for event in events:
        destination_ip = event.get("id.resp_h")
        destination_port = event.get("id.resp_p")
        protocol = event.get("proto")
        timestamp = event.get("ts")

        if None in (destination_ip, destination_port, protocol, timestamp):
            continue

        groups[(destination_ip, destination_port, protocol)].append(
            float(timestamp)
        )

    return dict(groups)


def calculate_intervals(timestamps: list[float]) -> list[float]:
    """Return inter-arrival times (seconds) of the chronologically sorted input."""
    ordered = sorted(timestamps)
    return [later - earlier for earlier, later in zip(ordered, ordered[1:], strict=False)]


def calculate_features(
    groups: dict[GroupKey, list[float]],
    min_events: int = DEFAULT_MIN_EVENTS,
) -> list[dict]:
    """Compute periodicity features for groups with at least ``min_events``.

    Features: event count, mean inter-arrival time, population standard
    deviation and coefficient of variation (CV = std / mean). CV is ``None``
    when the mean interval is zero (all timestamps identical).
    """
    if min_events < 2:
        raise ValueError("min_events must be >= 2 to compute intervals")

    results = []

    for (destination_ip, destination_port, protocol), timestamps in groups.items():
        if len(timestamps) < min_events:
            continue

        intervals = calculate_intervals(timestamps)
        interval_mean = mean(intervals)
        interval_std = pstdev(intervals)
        coefficient_variation = (
            None if interval_mean == 0 else interval_std / interval_mean
        )

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
