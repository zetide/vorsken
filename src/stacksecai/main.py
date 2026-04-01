"""
stacksecai Policy Gate — main entrypoint.
Called by action.yml composite step.
"""
import os
import sys
from .semgrep_runner import run_semgrep
from .claude_analyzer import analyze_with_claude
from .policy_gate import compute_verdict, EXIT_CODES, VERDICT_EMOJI
from .pr_commenter import post_pr_comment


def main():
    rules_path  = os.environ.get("SEMGREP_RULES", "rules/custom")
    target_path = os.environ.get("TARGET_PATH", ".")
    block_on_error = os.environ.get("BLOCK_ON_ERROR", "true").lower() == "true"

    print("🔍 Running Semgrep...")
    findings = run_semgrep(rules_path, target_path)
    print(f"  Found {len(findings)} finding(s)")

    print("🤖 Analyzing with Claude...")
    claude_verdict, explanation = analyze_with_claude(findings)
    print(f"  Claude verdict: {claude_verdict}")

    verdict = compute_verdict(findings, claude_verdict)
    emoji   = VERDICT_EMOJI[verdict]
    print(f"\n{emoji} Policy Gate verdict: {verdict}")

    # Set GitHub Actions output
    with open(os.environ.get("GITHUB_OUTPUT", "/dev/null"), "a") as f:
        f.write(f"verdict={verdict}\n")

    post_pr_comment(verdict, findings, explanation)

    if verdict == "BLOCK" and block_on_error:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
