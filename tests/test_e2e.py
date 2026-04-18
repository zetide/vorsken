# tests/test_e2e.py
"""
E2E tests: full pipeline from Semgrep findings → Policy Gate verdict.
Claude API is mocked to avoid external calls.
"""
import json
import pytest
from unittest.mock import patch
from pathlib import Path

from stacksecai.policy_gate import compute_verdict
from stacksecai.config import PolicyConfig, load_config
from stacksecai.gate import main as gate_main


# ── fixtures ──────────────────────────────────────────────────────────────

FINDINGS_ERROR = [
    {
        "check_id": "rules.custom.hardcoded-password",
        "path": "app/config.py",
        "start": {"line": 10},
        "extra": {"severity": "ERROR"},
    }
]

FINDINGS_WARNING = [
    {
        "check_id": "rules.custom.ssrf-via-requests",
        "path": "app/client.py",
        "start": {"line": 22},
        "extra": {"severity": "WARNING"},
    }
]

MOCK_CLAUDE_HIGH = ("HIGH",   "Hardcoded credential detected.", [], [])
MOCK_CLAUDE_LOW  = ("LOW",    "No significant risk detected.",  [], [])
MOCK_CLAUDE_MED  = ("MEDIUM", "Potential SSRF risk.",           [], [])


# ── E2E-1: Semgrep ERROR + Claude HIGH → BLOCK ────────────────────────────

def test_e2e_block_semgrep_error_and_claude_high():
    verdict = compute_verdict(FINDINGS_ERROR, "HIGH")
    assert verdict == "BLOCK"


# ── E2E-2: No findings + Claude LOW → PASS ───────────────────────────────

def test_e2e_pass_no_findings_low_severity(tmp_path):
    result_file = tmp_path / "empty.json"
    result_file.write_text(
        json.dumps({"results": [], "errors": []}),
        encoding="utf-8",
    )
    with patch(
        "stacksecai.gate.analyze_with_claude",
        return_value=MOCK_CLAUDE_LOW,
    ):
        rc = gate_main([str(result_file), "--no-comment"])
    assert rc == 0  # PASS


# ── E2E-3: Semgrep WARNING + Claude MEDIUM → FLAG ────────────────────────

def test_e2e_flag_warning_and_claude_medium():
    verdict = compute_verdict(FINDINGS_WARNING, "MEDIUM")
    assert verdict == "FLAG"


# ── E2E-4: rule_overrides BLOCK 強制 ─────────────────────────────────────

def test_e2e_block_via_rule_override():
    cfg = PolicyConfig(
        block_on=[],
        flag_on=[],
        severity_block=[],
        severity_flag=[],
        rule_overrides={"hardcoded-password": "BLOCK"},
    )
    # Semgrep WARNING のみ → 通常は FLAG だが override で BLOCK
    findings = [
        {
            "check_id": "rules.custom.hardcoded-password",
            "path": "app/config.py",
            "start": {"line": 5},
            "extra": {"severity": "WARNING"},
        }
    ]
    verdict = compute_verdict(findings, "LOW", config=cfg)
    assert verdict == "BLOCK"


# ── E2E-5: CLI --severity override → PASS ────────────────────────────────

def test_e2e_cli_severity_override_pass(tmp_path):
    result_file = tmp_path / "empty.json"
    result_file.write_text(
        json.dumps({"results": [], "errors": []}),
        encoding="utf-8",
    )
    rc = gate_main([str(result_file), "--severity", "LOW", "--no-comment"])
    assert rc == 0  # PASS