# src/stacksecai/claude_analyzer.py
"""
Claude Analyzer: sends Semgrep findings to Claude API and returns severity + summary.
"""
from __future__ import annotations

import json
import logging
import os

import anthropic
import httpx
from anthropic.types import TextBlock
from tenacity import (
    before_sleep_log,
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from stacksecai.config import (
    CLAUDE_TIMEOUT_CONNECT,
    CLAUDE_TIMEOUT_READ,
    CLAUDE_TIMEOUT_TOTAL,
    CLAUDE_TIMEOUT_WRITE,
)

logger = logging.getLogger(__name__)

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
        sev  = f.get("extra", {}).get("severity", "UNKNOWN")
        rule = f.get("check_id", "unknown")
        path = f.get("path", "unknown")
        line = f.get("start", {}).get("line", "?")
        lines.append(f"- [{sev}] {rule}: {path}:{line}")
    return "\n".join(lines)

# ── Claude クライアント（モジュールトップレベル）──────────────
# 遅延初期化（import 時ではなく初回呼び出し時に生成）
_client: anthropic.Anthropic | None = None

def _get_client() -> anthropic.Anthropic:
    global _client
    if _client is None:
        _client = anthropic.Anthropic(
            api_key=os.environ["ANTHROPIC_API_KEY"],
            timeout=httpx.Timeout(
                timeout=CLAUDE_TIMEOUT_TOTAL,
                connect=CLAUDE_TIMEOUT_CONNECT,
                read=CLAUDE_TIMEOUT_READ,
                write=CLAUDE_TIMEOUT_WRITE,
            ),
            max_retries=0,
        )
    return _client

_RETRYABLE = (
    anthropic.RateLimitError,
    anthropic.APIConnectionError,
    anthropic.APITimeoutError,
)

@retry(
    retry=retry_if_exception_type(_RETRYABLE),
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=30),
    before_sleep=before_sleep_log(logger, logging.WARNING),
    reraise=True,
)
def _call_claude(**kwargs):
    return _get_client().messages.create(**kwargs)  # client → _get_client()
# ─────────────────────────────────────────────────────────────

def analyze_with_claude(findings: list) -> tuple[str, str, list]:
    """
    Args:
        findings: list of Semgrep finding dicts
    Returns:
        (severity, summary, detailed_findings)
        e.g. ("HIGH", "Hardcoded credential detected.", [...])
    """
    
    findings_text = _build_findings_text(findings)
    user_content  = USER_PROMPT_TEMPLATE.format(findings_text=findings_text)

    try:
        message = _call_claude(
            model="claude-haiku-4-5",
            max_tokens=512,
            system=SYSTEM_PROMPT,
            messages=[
                {"role": "user",      "content": user_content},
                {"role": "assistant", "content": "{"},
            ],
        )
        block = message.content[0]
        if not isinstance(block, TextBlock):  # pragma: no cover
            raise ValueError(f"Unexpected block type: {type(block)}")  # pragma: no cover

        raw  = "{" + block.text.strip()
        data = json.loads(raw)

        severity = data.get("severity", "INFO").upper()
        summary  = data.get("summary", "No summary available.")
        details: list[dict] = data.get("findings", [])
        return severity, summary, details

    except (json.JSONDecodeError, KeyError, ValueError):
        return "INFO", "Claude response could not be parsed.", []