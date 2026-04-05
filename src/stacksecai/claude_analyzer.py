# src/stacksecai/claude_analyzer.py
"""
Claude Analyzer: sends Semgrep findings to Claude API and returns severity + summary.
"""
import json
import os
import time

import anthropic

MAX_RETRIES = 3
RETRY_DELAY = 2  # seconds

SYSTEM_PROMPT = """\
You are a security-focused code reviewer embedded in a CI/CD policy gate.
Analyze the provided Semgrep findings and respond ONLY with a JSON object.
Do NOT include prose, markdown fences, or any text outside the JSON.

Output schema:
{
  "severity": "CRITICAL | HIGH | MEDIUM | LOW | INFO",
  "summary": "<one-sentence risk summary>",
  "findings": [
    {
      "rule_id": "<semgrep rule id>",
      "line": <int or null>,
      "explanation": "<why this is a security risk>",
      "fix": "<concrete remediation in one sentence>"
    }
  ]
}

Severity selection criteria:
- CRITICAL : exploitable RCE, auth bypass, exposed private keys
- HIGH     : SSRF, SQL/command injection, hardcoded credentials
- MEDIUM   : insecure defaults, weak crypto, overly permissive CORS
- LOW      : code quality risks with minor security implications
- INFO     : informational, no direct exploitability
"""

USER_PROMPT_TEMPLATE = """\
<semgrep_findings>
{findings_text}
</semgrep_findings>

Evaluate the findings above and return JSON only.
"""


def _build_findings_text(findings: list) -> str:
    if not findings:
        return "No findings detected."
    lines = []
    for f in findings:
        sev   = f.get("extra", {}).get("severity", "UNKNOWN")
        rule  = f.get("check_id", "unknown")
        path  = f.get("path", "unknown")
        line  = f.get("start", {}).get("line", "?")
        lines.append(f"- [{sev}] {rule}: {path}:{line}")
    return "\n".join(lines)


def analyze_with_claude(findings: list) -> tuple[str, str, list]:
    """
    Args:
        findings: list of Semgrep finding dicts
    Returns:
        (severity, summary, detailed_findings)
        e.g. ("HIGH", "Hardcoded credential detected.", [...])
    """
    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
    findings_text = _build_findings_text(findings)
    user_content  = USER_PROMPT_TEMPLATE.format(findings_text=findings_text)

    for attempt in range(MAX_RETRIES):
        try:
            message = client.messages.create(
                model="claude-haiku-4-5",
                max_tokens=512,
                system=SYSTEM_PROMPT,
                messages=[
                    {"role": "user",    "content": user_content},
                    {"role": "assistant", "content": "{"},  # JSON prefill
                ],
            )
            raw  = "{" + message.content[0].text.strip()
            data = json.loads(raw)

            severity = data.get("severity", "INFO").upper()
            summary  = data.get("summary", "No summary available.")
            details  = data.get("findings", [])
            return severity, summary, details

        except (json.JSONDecodeError, KeyError):
            # Claude returned non-JSON — fall back to safe default
            if attempt == MAX_RETRIES - 1:
                return "INFO", "Claude response could not be parsed.", []
            time.sleep(RETRY_DELAY * (attempt + 1))

        except Exception as e:
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY * (attempt + 1))
            else:
                raise RuntimeError(
                    f"Claude API failed after {MAX_RETRIES} attempts: {e}"
                )