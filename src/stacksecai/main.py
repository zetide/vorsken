# src/stacksecai/main.py
"""
stacksecai Policy Gate - main entrypoint.
Called by action.yml composite step.
"""
import os
import sys

from .claude_analyzer import analyze_with_claude
from .config import load_config
from .policy_gate import EXIT_CODES, compute_verdict
from .pr_commenter import VERDICT_BADGE, post_pr_comment
from .semgrep_runner import run_semgrep


def main():
    rules_path     = os.environ.get("SEMGREP_RULES", "rules/custom")
    target_path    = os.environ.get("TARGET_PATH", ".")
    config_path    = os.environ.get("CONFIG_PATH", ".stacksecai.yml")
    block_on_error = os.environ.get("BLOCK_ON_ERROR", "true").lower() == "true"

    config = load_config(config_path)

    print("🔍 Running Semgrep...")
    findings = run_semgrep(rules_path, target_path)
    print(f"  Found {len(findings)} finding(s)")

    print("🤖 Analyzing with Claude...")
    claude_severity, summary, details, block_reasons = analyze_with_claude(findings)
    print(f"  Claude severity: {claude_severity}")

    verdict = compute_verdict(findings, claude_severity, config=config)
    badge   = VERDICT_BADGE.get(verdict, verdict)
    print(f"\n{badge} Policy Gate verdict: {verdict}")

    with open(os.environ.get("GITHUB_OUTPUT", "/dev/null"), "a", encoding="utf-8") as f:
        f.write(f"verdict={verdict}\n")

    post_pr_comment(verdict, findings, claude_severity, summary, details)

    sys.exit(EXIT_CODES.get(verdict, 0) if block_on_error else 0)


if __name__ == "__main__":
    main()