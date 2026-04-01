"""
Policy Gate: Core verdict logic for stacksecai.
Returns BLOCK / FLAG / PASS based on Semgrep + Claude results.
"""

SEMGREP_BLOCK_SEVERITIES = {"ERROR"}
SEMGREP_FLAG_SEVERITIES = {"WARNING"}
CLAUDE_BLOCK_LABELS = {"CRITICAL", "HIGH"}
CLAUDE_FLAG_LABELS = {"MEDIUM"}


def compute_verdict(semgrep_findings: list, claude_verdict: str) -> str:
    """
    Args:
        semgrep_findings: list of Semgrep result dicts (JSON output)
        claude_verdict:   string from Claude e.g. "CRITICAL" / "HIGH" / "MEDIUM" / "LOW" / "PASS"
    Returns:
        "BLOCK" | "FLAG" | "PASS"
    """
    severities = {f.get("extra", {}).get("severity", "").upper() for f in semgrep_findings}

    if severities & SEMGREP_BLOCK_SEVERITIES or claude_verdict.upper() in CLAUDE_BLOCK_LABELS:
        return "BLOCK"
    if severities & SEMGREP_FLAG_SEVERITIES or claude_verdict.upper() in CLAUDE_FLAG_LABELS:
        return "FLAG"
    return "PASS"


VERDICT_EMOJI = {
    "BLOCK": "🚫",
    "FLAG":  "⚠️",
    "PASS":  "✅",
}

EXIT_CODES = {
    "BLOCK": 1,
    "FLAG":  0,
    "PASS":  0,
}
