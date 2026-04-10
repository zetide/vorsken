# src/stacksecai/gate.py
"""
CLI entrypoint: python -m stacksecai.gate <result.json> [--severity HIGH]
Reads a pre-generated Semgrep JSON result and runs it through the Policy Gate.
"""
import argparse
import json
import sys
from pathlib import Path

from .claude_analyzer import analyze_with_claude
from .policy_gate import compute_verdict
from .pr_commenter import VERDICT_BADGE, format_pr_comment


def load_findings(path: str) -> list:
    p = Path(path)
    if not p.exists():
        print(f"[ERROR] File not found: {path}", file=sys.stderr)
        sys.exit(2)
    with open(p, encoding="utf-8-sig") as f:   # utf-8-sig = BOM自動スキップ
        data = json.load(f)
    return data.get("results", [])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m stacksecai.gate",
        description="Run StackSecAI Policy Gate on a Semgrep JSON result.",
    )
    parser.add_argument("result_json", help="Path to semgrep --json output file")
    parser.add_argument(
        "--severity",
        default=None,
        help="Override Claude severity (CRITICAL/HIGH/MEDIUM/LOW/INFO). "
             "Skips Claude API call if set.",
    )
    parser.add_argument(
        "--no-comment",
        action="store_true",
        help="Print comment to stdout instead of posting to GitHub.",
    )
    args = parser.parse_args(argv)

    # 1. Load findings
    findings = load_findings(args.result_json)
    print(f"📋 Loaded {len(findings)} finding(s) from {args.result_json}")

    # 2. Claude analysis (or override)
    if args.severity:
        claude_severity = args.severity.upper()
        summary         = f"Severity manually set to {claude_severity}."
        details: list[dict] = []
        print(f"⚡ Severity override: {claude_severity}")
    else:
        print("🤖 Analyzing with Claude...")
        claude_severity, summary, details = analyze_with_claude(findings)
        print(f"   Claude severity: {claude_severity}")

    # 3. Compute verdict
    verdict = compute_verdict(findings, claude_severity)
    badge   = VERDICT_BADGE.get(verdict, verdict)
    print(f"\n{badge} Policy Gate verdict: {verdict}")

    # 4. Format comment
    comment = format_pr_comment(verdict, findings, claude_severity, summary, details)

    if args.no_comment:
        print("\n--- PR Comment Preview ---")
        print(comment)
    else:
        print("\n[INFO] Use --no-comment to preview, or set GITHUB_TOKEN to post.")

    # 5. Exit code
    return 1 if verdict == "BLOCK" else 0


if __name__ == "__main__":
    sys.exit(main())