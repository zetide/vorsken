# src/stacksecai/policy_gate.py
from __future__ import annotations
from .config import PolicyConfig, load_config

EXIT_CODES = {"BLOCK": 1, "FLAG": 0, "PASS": 0}

_VERDICT_RANK = {"BLOCK": 2, "FLAG": 1, "PASS": 0}


def _rule_override_verdict(findings: list, overrides: dict[str, str]) -> str | None:
    """
    rule_overrides の中で最も厳しい verdict を返す。
    マッチしなければ None。
    """
    best = None
    for f in findings:
        rule_id = f.get("check_id", "").split(".")[-1]  # 末尾のルール名だけ比較
        full_id = f.get("check_id", "")
        for key in (rule_id, full_id):
            if key in overrides:
                action = overrides[key]
                if best is None or _VERDICT_RANK[action] > _VERDICT_RANK[best]:
                    best = action
    return best


def compute_verdict(
    findings: list,
    claude_severity: str,
    config: PolicyConfig | None = None,
) -> str:
    if config is None:
        config = load_config()

    sev = claude_severity.upper()

    # 1. Semgrep severity → BLOCK
    semgrep_severities = {
        f.get("extra", {}).get("severity", "").upper()
        for f in findings
    }
    if semgrep_severities & set(config.block_on):
        return "BLOCK"

    # 2. Claude severity → BLOCK
    if sev in config.severity_block:
        return "BLOCK"

    # 3. rule_overrides（個別ルール上書き）
    override = _rule_override_verdict(findings, config.rule_overrides)
    if override == "BLOCK":
        return "BLOCK"

    # 4. FLAG checks
    if semgrep_severities & set(config.flag_on):
        return "FLAG"
    if sev in config.severity_flag:
        return "FLAG"
    if override == "FLAG":
        return "FLAG"

    return "PASS"