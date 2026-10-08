"""Generate a small, deterministic, SYNTHETIC Zeek conn.log sample.

The output is not lab telemetry. It exists so reviewers can run the
pipeline end to end without access to the excluded raw dataset.

Ground truth (see samples/README.md):
- 203.0.113.50:443/tcp  -> simulated beacon, 300 s interval, +/-10 % jitter
- 10.50.20.254:67/udp   -> benign DHCP renewal, 3600 s
- 10.50.30.10:53/udp    -> benign DNS, irregular
- 10.50.10.10:1514/tcp  -> benign Wazuh agent traffic, irregular
- 198.51.100.7:443/tcp  -> benign browsing bursts, irregular
- 10.50.20.30 (other source) -> must be excluded by source filtering

Usage:
    python scripts/generate_synthetic_sample.py [--output PATH]
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path

SEED = 42
START_TS = 1_790_000_000.0  # fixed epoch for reproducibility
DURATION = 6 * 3600  # 6 hours
SOURCE_IP = "10.50.20.22"
OTHER_SOURCE_IP = "10.50.20.30"


def _event(rng, ts, orig_h, orig_p, resp_h, resp_p, proto, service):
    return {
        "ts": round(ts, 6),
        "uid": f"CSYN{rng.getrandbits(48):012x}",
        "id.orig_h": orig_h,
        "id.orig_p": orig_p,
        "id.resp_h": resp_h,
        "id.resp_p": resp_p,
        "proto": proto,
        "service": service,
        "duration": round(rng.uniform(0.01, 2.0), 6),
        "orig_bytes": rng.randint(40, 1500),
        "resp_bytes": rng.randint(40, 4000),
        "conn_state": "SF",
        "synthetic": True,
    }


def generate(seed: int = SEED) -> list[dict]:
    rng = random.Random(seed)
    events: list[dict] = []
    end = START_TS + DURATION

    # Simulated beacon: 300 s +/- 10 % uniform jitter.
    ts = START_TS + 17.0
    while ts < end:
        events.append(_event(rng, ts, SOURCE_IP, rng.randint(49152, 65535),
                             "203.0.113.50", 443, "tcp", "ssl"))
        ts += 300.0 * rng.uniform(0.9, 1.1)

    # DHCP renewal every hour (near-perfect periodicity, benign).
    for hour in range(6):
        events.append(_event(rng, START_TS + 5.0 + hour * 3600 + rng.uniform(0, 0.05),
                             SOURCE_IP, 68, "10.50.20.254", 67, "udp", "dhcp"))

    # Irregular benign traffic: exponential inter-arrival times.
    irregular = [
        ("10.50.30.10", 53, "udp", "dns", 60.0),
        ("10.50.10.10", 1514, "tcp", None, 45.0),
        ("198.51.100.7", 443, "tcp", "ssl", 240.0),
    ]
    for resp_h, resp_p, proto, service, mean_gap in irregular:
        ts = START_TS + rng.uniform(0, mean_gap)
        while ts < end:
            events.append(_event(rng, ts, SOURCE_IP, rng.randint(49152, 65535),
                                 resp_h, resp_p, proto, service))
            ts += rng.expovariate(1.0 / mean_gap)

    # Different source host with its own beacon-like pattern (must be filtered out).
    ts = START_TS
    while ts < end:
        events.append(_event(rng, ts, OTHER_SOURCE_IP, rng.randint(49152, 65535),
                             "203.0.113.99", 8443, "tcp", None))
        ts += 600.0

    # Too-small group (below min_events threshold).
    for offset in (100.0, 2000.0, 9000.0):
        events.append(_event(rng, START_TS + offset, SOURCE_IP, 50000,
                             "192.0.2.10", 123, "udp", "ntp"))

    events.sort(key=lambda item: item["ts"])
    return events


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "samples" / "synthetic-conn.jsonl",
    )
    args = parser.parse_args()

    events = generate()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="\n") as handle:
        for event in events:
            handle.write(json.dumps(event, separators=(",", ":")) + "\n")
    print(f"Wrote {len(events)} synthetic events to {args.output}")


if __name__ == "__main__":
    main()
