"""
Claude Analyzer: sends Semgrep findings to Claude API and returns verdict label.
Ported from playground/ - includes retry/error handling.
"""
import os
import time
import anthropic

MAX_RETRIES = 3
RETRY_DELAY = 2  # seconds

SYSTEM_PROMPT = """You are a security code reviewer.
Given Semgrep findings from a pull request, respond with ONE of:
CRITICAL / HIGH / MEDIUM / LOW / PASS
Then provide a brief explanation (1-2 sentences)."""


def analyze_with_claude(findings: list) -> tuple[str, str]:
    """
    Args:
        findings: list of Semgrep finding dicts
    Returns:
        (verdict_label, explanation) e.g. ("HIGH", "Hardcoded credential detected.")
    """
    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

    findings_text = "\n".join(
        f"- [{f.get('extra',{}).get('severity','?')}] {f.get('check_id','?')}: "
        f"{f.get('path','?')}:{f.get('start',{}).get('line','?')}"
        for f in findings
    ) or "No findings."

    for attempt in range(MAX_RETRIES):
        try:
            message = client.messages.create(
                model="claude-opus-4-5",
                max_tokens=256,
                messages=[{
                    "role": "user",
                    "content": f"Review these Semgrep findings:\n{findings_text}"
                }],
                system=SYSTEM_PROMPT,
            )
            response = message.content[0].text.strip()
            lines = response.split("\n", 1)
            verdict = lines[0].strip().upper()
            explanation = lines[1].strip() if len(lines) > 1 else ""
            return verdict, explanation
        except Exception as e:
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY * (attempt + 1))
            else:
                raise RuntimeError(f"Claude API failed after {MAX_RETRIES} attempts: {e}")
