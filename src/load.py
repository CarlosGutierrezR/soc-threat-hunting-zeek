"""Zeek conn.log (JSON Lines) ingestion and source filtering."""

from __future__ import annotations

import json
from pathlib import Path


def load_events(path: Path | str) -> list[dict]:
    """Load Zeek JSONL events from ``path``.

    Blank lines are ignored. Malformed JSON or non-object lines raise
    ``ValueError`` with the offending line number so that evidence
    integrity problems are never silently skipped.
    """
    path = Path(path)
    events: list[dict] = []

    with path.open("r", encoding="utf-8-sig") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"{path}: invalid JSON on line {line_number}: {exc.msg}"
                ) from exc

            if not isinstance(event, dict):
                raise ValueError(
                    f"{path}: line {line_number} is not a JSON object"
                )

            events.append(event)

    return events


def filter_source(events: list[dict], source_ip: str) -> list[dict]:
    """Return only events whose originator (``id.orig_h``) is ``source_ip``."""
    return [event for event in events if event.get("id.orig_h") == source_ip]
