from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def synthetic_sample() -> Path:
    return REPO_ROOT / "samples" / "synthetic-conn.jsonl"
