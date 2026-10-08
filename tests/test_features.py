from src.features import calculate_intervals, calculate_features


def test_calculate_intervals():
    timestamps = [10.0, 20.0, 30.0, 40.0]

    result = calculate_intervals(timestamps)

    assert result == [10.0, 10.0, 10.0]


def test_calculate_intervals_sorts_input():
    timestamps = [30.0, 10.0, 20.0]

    result = calculate_intervals(timestamps)

    assert result == [10.0, 10.0]


def test_constant_interval_has_zero_cv():
    groups = {
        ("10.0.0.1", 443, "tcp"): [
            0.0,
            10.0,
            20.0,
            30.0,
            40.0,
        ]
    }

    result = calculate_features(groups, min_events=5)

    assert len(result) == 1
    assert result[0]["mean_interval_seconds"] == 10.0
    assert result[0]["std_interval_seconds"] == 0.0
    assert result[0]["coefficient_variation"] == 0.0


def test_group_below_minimum_is_removed():
    groups = {
        ("10.0.0.1", 443, "tcp"): [
            0.0,
            10.0,
            20.0,
        ]
    }

    result = calculate_features(groups, min_events=5)

    assert result == []
