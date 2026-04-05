"""
stacksecai Policy Gate - main entrypoint.
Called by action.yml composite step.
"""
import os
import sys

from .semgrep_runner import run_semgrep
from .claude_analyzer import analyze_with_claude
from .policy_gate import compute_verdict, EXIT_CODES
from .pr_commenter import post_pr_comment, VERDICT_BADGE


def main():
    rules_path     = os.environ.get("SEMGREP_RULES", "rules/custom")
    target_path    = os.environ.get("TARGET_PATH", ".")
    block_on_error = os.environ.get("BLOCK_ON_ERROR", "true").lower() == "true"

    print("🔍 Running Semgrep...")
    findings = run_semgrep(rules_path, target_path)
    print(f"  Found {len(findings)} finding(s)")

    print("🤖 Analyzing with Claude...")
    claude_severity, summary, details = analyze_with_claude(findings)  # ← 変更
    print(f"  Claude severity: {claude_severity}")

    verdict = compute_verdict(findings, claude_severity)                # ← 変更
    badge   = VERDICT_BADGE.get(verdict, verdict)
    print(f"\n{badge} Policy Gate verdict: {verdict}")

    # Set GitHub Actions output
    with open(os.environ.get("GITHUB_OUTPUT", "/dev/null"), "a", encoding="utf-8") as f:
        f.write(f"verdict={verdict}\n")

    post_pr_comment(verdict, findings, claude_severity, summary, details)  # ← 変更

    sys.exit(EXIT_CODES.get(verdict, 0) if block_on_error else 0)


if __name__ == "__main__":
    main()