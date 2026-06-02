"""
Integration test for the `code-execution` Semgrep rule.

Runs Semgrep against tests/fixtures/vulnerable_sample.py and asserts:
- the rule fires on exec(), compile(), pickle.load(), and pickle.loads()
- the rule does NOT fire on re.compile() or ordinary code
- every finding carries ERROR severity
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
RULE_PATH = REPO_ROOT / "rules" / "custom" / "code_execution.yml"
FIXTURE_PATH = REPO_ROOT / "tests" / "fixtures" / "vulnerable_sample.py"

RULE_ID = "code-execution"

VULN_MARKERS = [
    "CE-VULN-EXEC",
    "CE-VULN-PICKLE-LOADS",
    "CE-VULN-PICKLE-LOAD",
    "CE-VULN-COMPILE",
]
SAFE_MARKERS = [
    "CE-SAFE-RE-COMPILE",
    "CE-SAFE-NORMAL",
]


def _read_lines_with_marker(marker: str) -> list[int]:
    """Return 1-indexed line numbers of fixture lines containing `marker`."""
    lines = FIXTURE_PATH.read_text(encoding="utf-8").splitlines()
    return [i + 1 for i, line in enumerate(lines) if marker in line]


@pytest.fixture(scope="module")
def semgrep_findings() -> list[dict]:
    if shutil.which("semgrep") is None:
        pytest.skip("semgrep binary not available")
    proc = subprocess.run(
        [
            "semgrep",
            "--config",
            str(RULE_PATH),
            str(FIXTURE_PATH),
            "--json",
            "--quiet",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"semgrep failed: {proc.returncode}\n{proc.stderr}")
    data = json.loads(proc.stdout or "{}")
    return [
        r for r in data.get("results", [])
        if r.get("check_id", "").endswith(RULE_ID)
    ]


def _firing_lines(findings: list[dict]) -> set[int]:
    return {f["start"]["line"] for f in findings}


@pytest.mark.parametrize("marker", VULN_MARKERS)
def test_rule_fires_on_code_execution(semgrep_findings: list[dict], marker: str) -> None:
    label_line = _read_lines_with_marker(marker)[0]
    fired = _firing_lines(semgrep_findings)
    assert any(label_line < line <= label_line + 3 for line in fired), (
        f"expected {marker} call to fire near line {label_line}, got {fired}"
    )


@pytest.mark.parametrize("marker", SAFE_MARKERS)
def test_rule_does_not_fire_on_safe(semgrep_findings: list[dict], marker: str) -> None:
    label_line = _read_lines_with_marker(marker)[0]
    fired = _firing_lines(semgrep_findings)
    assert not any(label_line < line <= label_line + 3 for line in fired), (
        f"safe call at ~{label_line} ({marker}) must NOT fire; got {fired}"
    )


def test_rule_has_error_severity(semgrep_findings: list[dict]) -> None:
    assert semgrep_findings, "rule produced no findings at all"
    for f in semgrep_findings:
        assert f.get("extra", {}).get("severity") == "ERROR"
