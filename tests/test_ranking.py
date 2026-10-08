import csv

from src.ranking import FIELDNAMES, rank_candidates, write_csv


def _candidate(ip, cv, count):
    return {
        "destination_ip": ip,
        "destination_port": 443,
        "protocol": "tcp",
        "event_count": count,
        "mean_interval_seconds": 60.0,
        "std_interval_seconds": 1.0,
        "coefficient_variation": cv,
    }


def test_rank_orders_by_cv_then_event_count_and_puts_undefined_last():
    ranked = rank_candidates(
        [
            _candidate("a", None, 100),
            _candidate("b", 0.5, 10),
            _candidate("c", 0.1, 5),
            _candidate("d", 0.1, 50),
        ]
    )

    assert [c["destination_ip"] for c in ranked] == ["d", "c", "b", "a"]


def test_write_csv(tmp_path):
    output = tmp_path / "nested" / "ranking.csv"

    write_csv([_candidate("a", 0.1, 5), _candidate("b", 0.2, 5)], output)

    with output.open(encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))

    assert list(rows[0].keys()) == FIELDNAMES
    assert [r["rank"] for r in rows] == ["1", "2"]
