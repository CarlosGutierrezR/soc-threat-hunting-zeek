from pathlib import Path
import json

REPO_ROOT = Path(__file__).resolve().parent.parent
DATASET_PATH = (
    REPO_ROOT / "evidence" / "raw" / "sec-hunt-001-zeek-conn-2026-10-08.jsonl"
)


def load_events(path: Path) -> list[dict]:
    events = []

    with open(path, "r", encoding="utf-8") as archivo:
        for linea in archivo:
            linea = linea.strip()

            if not linea:
                continue

            event = json.loads(linea)
            events.append(event)

    return events


def filter_source(events: list[dict], source_ip: str) -> list[dict]:
    filtered = []

    for event in events:
        if event.get("id.orig_h") == source_ip:
            filtered.append(event)

    return filtered


if __name__ == "__main__":
    events = load_events(DATASET_PATH)
    win11_events = filter_source(events, "10.50.20.22")

    print(f"Dataset: {DATASET_PATH}")
    print(f"Eventos cargados: {len(events)}")
    print(f"Eventos desde 10.50.20.22: {len(win11_events)}")

    if events:
        print(f"Primer UID: {events[0].get('uid')}")
        print(f"Último UID: {events[-1].get('uid')}")
