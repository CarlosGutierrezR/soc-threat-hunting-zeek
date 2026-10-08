"""Command-line entry point for the SEC-HUNT-001 periodicity workflow.

Examples:
    python -m src.cli --input samples/synthetic-conn.jsonl
    python -m src.cli --input evidence/raw/<file>.jsonl \
        --output evidence/candidate-ranking.csv
"""

from __future__ import annotations

import argparse
import ipaddress
import sys
from pathlib import Path

from .features import DEFAULT_MIN_EVENTS, calculate_features, group_connections
from .load import filter_source, load_events
from .ranking import rank_candidates, write_csv

DEFAULT_SOURCE_IP = "10.50.20.22"  # WIN11-EP-01 in the SOC lab


def _ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid IP address: {value}") from exc


def _min_events(value: str) -> int:
    number = int(value)
    if number < 2:
        raise argparse.ArgumentTypeError("--min-events must be >= 2")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m src.cli",
        description="Rank Zeek conn.log groups by inter-arrival periodicity (CV).",
    )
    parser.add_argument(
        "--input", required=True, type=Path, help="Zeek conn.log in JSONL format"
    )
    parser.add_argument(
        "--source-ip",
        type=_ip,
        default=DEFAULT_SOURCE_IP,
        help=f"originator IP to hunt on (default: {DEFAULT_SOURCE_IP})",
    )
    parser.add_argument(
        "--min-events",
        type=_min_events,
        default=DEFAULT_MIN_EVENTS,
        help=f"minimum events per group (default: {DEFAULT_MIN_EVENTS})",
    )
    parser.add_argument(
        "--output", type=Path, help="optional CSV path for the full ranking"
    )
    parser.add_argument(
        "--top", type=int, default=20, help="candidates to print (default: 20)"
    )
    return parser


def format_candidate(rank: int, candidate: dict) -> str:
    cv = candidate["coefficient_variation"]
    cv_text = "n/a" if cv is None else f"{cv:.4f}"
    return (
        f"{rank:>3}. {candidate['destination_ip']}:"
        f"{candidate['destination_port']}/{candidate['protocol']} "
        f"count={candidate['event_count']} "
        f"mean={candidate['mean_interval_seconds']:.2f}s "
        f"std={candidate['std_interval_seconds']:.2f}s "
        f"cv={cv_text}"
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        events = load_events(args.input)
    except FileNotFoundError:
        print(f"error: input file not found: {args.input}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    source_events = filter_source(events, args.source_ip)
    groups = group_connections(source_events)
    ranked = rank_candidates(calculate_features(groups, args.min_events))

    print(f"Dataset events:            {len(events)}")
    print(f"Events from {args.source_ip:<14} {len(source_events)}")
    print(f"Connection groups:         {len(groups)}")
    print(f"Groups with >= {args.min_events} events:   {len(ranked)}")
    print()
    print("Top periodicity candidates (low CV = regular timing, NOT a verdict):")
    for rank, candidate in enumerate(ranked[: args.top], start=1):
        print(format_candidate(rank, candidate))

    if args.output:
        write_csv(ranked, args.output)
        print()
        print(f"Ranking written to: {args.output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
