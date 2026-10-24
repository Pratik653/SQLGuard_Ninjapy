from __future__ import annotations

import pytest

from sqlguard_ninja.benchmarking.dataset import DatasetError, load_case_file, load_dataset
from tests.conftest import DATASET_PATH


def test_dataset_loads_and_has_stats():
    ds = load_dataset(DATASET_PATH)
    stats = ds.stats()
    assert stats["evaluations"] == len(ds.cases) > 0
    assert set(stats["by_dialect"]) <= {"postgres", "sqlite", "mysql"}
    assert len(ds.fingerprint) == 16


def test_expansion_per_dialect(tmp_path):
    f = tmp_path / "c.yaml"
    f.write_text(
        "cases:\n- id: X-1\n  sql: SELECT 1\n  dialects: [postgres, sqlite]\n"
        "  category: t\n  expected: allow\n  explanation: e\n"
    )
    cases = load_case_file(f, {"tenant_id": 1})
    assert [c.id for c in cases] == ["X-1@postgres", "X-1@sqlite"]
    assert cases[0].context == {"tenant_id": 1}


def test_per_dialect_override(tmp_path):
    f = tmp_path / "c.yaml"
    f.write_text(
        "cases:\n- id: X-1\n  sql: SELECT 1\n  dialects: [postgres, sqlite]\n  category: t\n"
        "  expected: deny\n  reason: unauthorized_table\n  explanation: e\n"
        "  expected_by_dialect: {sqlite: allow}\n"
    )
    pg, lite = load_case_file(f, {})
    assert pg.expected.value == "deny" and lite.expected.value == "allow"
    assert lite.reason.value == "none" and lite.classification.value == "benign"


@pytest.mark.parametrize(
    "body",
    [
        "  expected: allow\n  reason: write_statement\n",  # allow with a reason
        "  expected: deny\n",  # deny without reason
        "  expected: deny\n  reason: cost\n  classification: benign\n",
    ],
)
def test_inconsistent_labels_rejected(tmp_path, body):
    f = tmp_path / "c.yaml"
    f.write_text(
        "cases:\n- id: X-1\n  sql: SELECT 1\n  dialects: [postgres]\n  category: t\n"
        f"  explanation: e\n{body}"
    )
    if "classification: benign" in body:
        # classification conflicting with the decision is corrected, not silently kept
        (case,) = load_case_file(f, {})
        assert case.classification.value != "benign"
    else:
        with pytest.raises(DatasetError):
            load_case_file(f, {})
