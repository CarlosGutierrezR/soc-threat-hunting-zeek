import pytest

from src.features import calculate_features, calculate_intervals, group_connections


def test_calculate_intervals():
    assert calculate_intervals([10.0, 20.0, 30.0, 40.0]) == [10.0, 10.0, 10.0]


def test_calculate_intervals_sorts_input():
    assert calculate_intervals([30.0, 10.0, 20.0]) == [10.0, 10.0]


def test_calculate_intervals_single_timestamp():
    assert calculate_intervals([5.0]) == []


def test_constant_interval_has_zero_cv():
    groups = {("10.0.0.1", 443, "tcp"): [0.0, 10.0, 20.0, 30.0, 40.0]}

    result = calculate_features(groups, min_events=5)

    assert len(result) == 1
    assert result[0]["mean_interval_seconds"] == 10.0
    assert result[0]["std_interval_seconds"] == 0.0
    assert result[0]["coefficient_variation"] == 0.0


def test_known_cv_value():
    # intervals 10 and 30 -> mean 20, pstdev 10, CV 0.5
    groups = {("10.0.0.1", 443, "tcp"): [0.0, 10.0, 40.0]}

    result = calculate_features(groups, min_events=3)

    assert result[0]["coefficient_variation"] == pytest.approx(0.5)


def test_group_below_minimum_is_removed():
    groups = {("10.0.0.1", 443, "tcp"): [0.0, 10.0, 20.0]}

    assert calculate_features(groups, min_events=5) == []


def test_identical_timestamps_give_undefined_cv():
    groups = {("10.0.0.1", 443, "tcp"): [7.0] * 5}

    result = calculate_features(groups, min_events=5)

    assert result[0]["coefficient_variation"] is None


def test_min_events_below_two_is_rejected():
    with pytest.raises(ValueError):
        calculate_features({}, min_events=1)


def test_group_connections_skips_incomplete_events():
    events = [
        {"id.resp_h": "10.0.0.1", "id.resp_p": 443, "proto": "tcp", "ts": 1.0},
        {"id.resp_h": "10.0.0.1", "id.resp_p": 443, "proto": "tcp", "ts": "2.5"},
        {"id.resp_h": "10.0.0.1", "id.resp_p": 443, "proto": "tcp"},  # no ts
        {"id.resp_p": 53, "proto": "udp", "ts": 3.0},  # no destination
    ]

    groups = group_connections(events)

    assert groups == {("10.0.0.1", 443, "tcp"): [1.0, 2.5]}


def test_port_zero_is_not_treated_as_missing():
    events = [{"id.resp_h": "224.0.0.22", "id.resp_p": 0, "proto": "unknown_transport", "ts": 1.0}]

    assert ("224.0.0.22", 0, "unknown_transport") in group_connections(events)
