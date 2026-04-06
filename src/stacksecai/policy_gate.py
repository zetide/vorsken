# src/stacksecai/policy_gate.py
from __future__ import annotations
from .config import PolicyConfig, load_config

EXIT_CODES = {"BLOCK": 1, "FLAG": 0, "PASS": 0}


def compute_verdict(
    findings: list,
    claude_severity: str,
    config: PolicyConfig | None = None,
) -> str:
    if config is None:
        config = load_config()

    sev = claude_severity.upper()

    # 1. Semgrep severity check
    semgrep_severities = {
        f.get("extra", {}).get("severity", "").upper()
        for f in findings
    }
    if semgrep_severities & set(config.block_on):
        return "BLOCK"

    # 2. Claude severity check
    if sev in config.severity_block:
        return "BLOCK"

    # 3. FLAG checks
    if semgrep_severities & set(config.flag_on):
        return "FLAG"
    if sev in config.severity_flag:
        return "FLAG"

    return "PASS"