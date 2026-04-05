from typing import Any, Dict, List


def compute_verdict(findings: List[Dict[str, Any]], claude_severity: str) -> str:
    """
    findings: Semgrepの結果リスト
    claude_severity: Claudeが判定したseverity文字列 ("CRITICAL", "HIGH", "MEDIUM", "LOW", "PASS")
    戻り値: "BLOCK" / "FLAG" / "PASS"
    """
    has_error = any(
        r.get("extra", {}).get("severity", "").upper() == "ERROR"
        for r in findings
    )
    has_warning = any(
        r.get("extra", {}).get("severity", "").upper() == "WARNING"
        for r in findings
    )

    # BLOCK の条件（Semgrep ERROR が最優先）
    if has_error:
        return "BLOCK"
    if claude_severity.upper() in ("CRITICAL", "HIGH"):
        return "BLOCK"

    # FLAG の条件
    if has_warning:
        return "FLAG"
    if claude_severity.upper() == "MEDIUM":
        return "FLAG"

    return "PASS"