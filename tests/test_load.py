import pytest

from src.load import filter_source, load_events


def test_load_events_skips_blank_lines(tmp_path):
    path = tmp_path / "conn.jsonl"
    path.write_text('{"uid": "a"}\n\n{"uid": "b"}\n', encoding="utf-8")

    assert [e["uid"] for e in load_events(path)] == ["a", "b"]


def test_load_events_accepts_utf8_bom(tmp_path):
    path = tmp_path / "conn.jsonl"
    path.write_bytes(b'\xef\xbb\xbf{"uid": "a"}\n')

    assert load_events(path) == [{"uid": "a"}]


def test_load_events_reports_malformed_line(tmp_path):
    path = tmp_path / "conn.jsonl"
    path.write_text('{"uid": "a"}\n{broken\n', encoding="utf-8")

    with pytest.raises(ValueError, match="line 2"):
        load_events(path)


def test_load_events_rejects_non_object(tmp_path):
    path = tmp_path / "conn.jsonl"
    path.write_text("[1, 2]\n", encoding="utf-8")

    with pytest.raises(ValueError, match="not a JSON object"):
        load_events(path)


def test_filter_source():
    events = [{"id.orig_h": "10.0.0.5"}, {"id.orig_h": "10.0.0.6"}, {}]

    assert filter_source(events, "10.0.0.5") == [{"id.orig_h": "10.0.0.5"}]
