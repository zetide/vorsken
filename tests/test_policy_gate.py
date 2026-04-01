"""
Tests for Policy Gate verdict logic.
"""
import pytest
from src.stacksecai.policy_gate import compute_verdict


def make_finding(severity: str) -> dict:
    return {"extra": {"severity": severity}, "check_id": "test-rule", "path": "test.py", "start": {"line": 1}}


# --- BLOCK cases ---
def test_semgrep_error_gives_block():
    assert compute_verdict([make_finding("ERROR")], "LOW") == "BLOCK"

def test_claude_critical_gives_block():
    assert compute_verdict([], "CRITICAL") == "BLOCK"

def test_claude_high_gives_block():
    assert compute_verdict([], "HIGH") == "BLOCK"

# --- FLAG cases ---
def test_semgrep_warning_gives_flag():
    assert compute_verdict([make_finding("WARNING")], "LOW") == "FLAG"

def test_claude_medium_gives_flag():
    assert compute_verdict([], "MEDIUM") == "FLAG"

# --- PASS cases ---
def test_no_findings_gives_pass():
    assert compute_verdict([], "PASS") == "PASS"

def test_claude_low_no_semgrep_gives_pass():
    assert compute_verdict([], "LOW") == "PASS"

# --- Priority: Semgrep ERROR + Claude LOW → BLOCK (Semgrep wins) ---
def test_semgrep_error_overrides_claude_low():
    assert compute_verdict([make_finding("ERROR")], "LOW") == "BLOCK"
