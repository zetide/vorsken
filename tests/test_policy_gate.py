"""
Tests for Policy Gate verdict logic.
"""
import pytest

from src.stacksecai.config import PolicyConfig
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


# ---------------------------------------------------------------------------
# block_on / flag_on coverage of OWASP-derived Semgrep severities.
#
# Custom OWASP rules emit Semgrep `extra.severity` of CRITICAL / HIGH / MEDIUM
# (alongside the classic ERROR / WARNING). These configs isolate the
# Semgrep-severity axis (severity_block / severity_flag emptied, Claude
# severity neutral) so the verdict is driven purely by block_on / flag_on.
# ---------------------------------------------------------------------------

# Repo default sets, with the Claude-severity axis disabled for isolation.
SEMGREP_ONLY = PolicyConfig(
    block_on=["ERROR", "CRITICAL", "HIGH"],
    flag_on=["WARNING", "MEDIUM"],
    severity_block=[],
    severity_flag=[],
)


@pytest.mark.parametrize("severity", ["ERROR", "CRITICAL", "HIGH"])
def test_block_on_severities_give_block(severity):
    assert compute_verdict([make_finding(severity)], "INFO", config=SEMGREP_ONLY) == "BLOCK"


@pytest.mark.parametrize("severity", ["WARNING", "MEDIUM"])
def test_flag_on_severities_give_flag(severity):
    assert compute_verdict([make_finding(severity)], "INFO", config=SEMGREP_ONLY) == "FLAG"


@pytest.mark.parametrize("severity", ["LOW", "INFO"])
def test_out_of_set_severities_give_pass(severity):
    assert compute_verdict([make_finding(severity)], "INFO", config=SEMGREP_ONLY) == "PASS"


def test_empty_findings_give_pass():
    assert compute_verdict([], "INFO", config=SEMGREP_ONLY) == "PASS"


# --- Case-insensitive comparison (notation variants like "High" → "HIGH") ---
@pytest.mark.parametrize("severity", ["High", "high", "hIgH"])
def test_block_on_is_case_insensitive_on_finding_side(severity):
    assert compute_verdict([make_finding(severity)], "INFO", config=SEMGREP_ONLY) == "BLOCK"


def test_block_on_is_case_insensitive_on_config_side():
    cfg = PolicyConfig(
        block_on=["Error", "High"],
        flag_on=["Warning", "Medium"],
        severity_block=[],
        severity_flag=[],
    )
    assert compute_verdict([make_finding("HIGH")], "INFO", config=cfg) == "BLOCK"
    assert compute_verdict([make_finding("ERROR")], "INFO", config=cfg) == "BLOCK"
    assert compute_verdict([make_finding("MEDIUM")], "INFO", config=cfg) == "FLAG"


# --- Shipped default (PolicyConfig()) must gate OWASP severities correctly ---
@pytest.mark.parametrize("severity", ["ERROR", "CRITICAL", "HIGH"])
def test_default_config_blocks_owasp_severities(severity):
    # Claude severity kept neutral so BLOCK is proven to come from block_on.
    assert compute_verdict([make_finding(severity)], "INFO", config=PolicyConfig()) == "BLOCK"


def test_default_config_flags_owasp_medium():
    assert compute_verdict([make_finding("MEDIUM")], "INFO", config=PolicyConfig()) == "FLAG"
