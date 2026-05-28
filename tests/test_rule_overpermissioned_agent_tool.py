"""
Integration test for the AI-generated-code rule
`overpermissioned-agent-tool`.

Runs Semgrep against the shared vulnerable_sample fixture and asserts:
- the rule fires on AI-GEN-1a / 1b / 1c lines
- the rule does NOT fire on the SAFE FileManagementToolkit(root_dir=...) line
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
RULE_PATH = REPO_ROOT / "rules" / "custom" / "ai-generated" / "overpermissioned_agent_tool.yml"
FIXTURE_PATH = REPO_ROOT / "tests" / "fixtures" / "vulnerable_sample.py"

RULE_ID = "overpermissioned-agent-tool"


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


def test_rule_fires_on_shelltool(semgrep_findings: list[dict]) -> None:
    label_line = _read_lines_with_marker("AI-GEN-1a")[0]
    fired = _firing_lines(semgrep_findings)
    assert any(label_line < line <= label_line + 5 for line in fired), (
        f"expected ShellTool() to fire near line {label_line}, got {fired}"
    )


def test_rule_fires_on_pythonrepltool(semgrep_findings: list[dict]) -> None:
    label_line = _read_lines_with_marker("AI-GEN-1b")[0]
    fired = _firing_lines(semgrep_findings)
    assert any(label_line < line <= label_line + 5 for line in fired), (
        f"expected PythonREPLTool() to fire near line {label_line}, got {fired}"
    )


def test_rule_fires_on_filemanagementtoolkit_without_root_dir(
    semgrep_findings: list[dict],
) -> None:
    label_line = _read_lines_with_marker("AI-GEN-1c")[0]
    fired = _firing_lines(semgrep_findings)
    assert any(label_line < line <= label_line + 5 for line in fired), (
        f"expected FileManagementToolkit() to fire near line {label_line}, "
        f"got {fired}"
    )


def test_rule_fires_on_pythonastrepltool(semgrep_findings: list[dict]) -> None:
    label_line = _read_lines_with_marker("AI-GEN-1d")[0]
    fired = _firing_lines(semgrep_findings)
    assert any(label_line < line <= label_line + 5 for line in fired), (
        f"expected PythonAstREPLTool() to fire near line {label_line}, "
        f"got {fired}"
    )


def test_rule_does_not_fire_on_safe_filemanagementtoolkit(
    semgrep_findings: list[dict],
) -> None:
    safe_label_line = _read_lines_with_marker("SAFE: FileManagementToolkit")[0]
    fired = _firing_lines(semgrep_findings)
    assert not any(safe_label_line < line <= safe_label_line + 3 for line in fired), (
        f"FileManagementToolkit(root_dir=...) at ~{safe_label_line} must NOT "
        f"fire; got {fired}"
    )


def test_rule_has_error_severity(semgrep_findings: list[dict]) -> None:
    assert semgrep_findings, "rule produced no findings at all"
    for f in semgrep_findings:
        assert f.get("extra", {}).get("severity") == "ERROR"
