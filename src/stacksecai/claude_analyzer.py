# src/stacksecai/claude_analyzer.py
"""
Claude Analyzer: sends Semgrep findings to Claude API and returns verdict + summary.
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
from stacksecai.log_filter import SensitiveFilter

logger = logging.getLogger(__name__)
logger.addFilter(SensitiveFilter())  # mask sensitive values in logs

MAX_RETRIES = 3
RETRY_DELAY = 2  # seconds

SYSTEM_PROMPT = (
    "You are a security-focused code reviewer embedded in a CI/CD policy gate "
    "for API security analysis.\n\n"
    "Analyze the provided Semgrep findings and respond ONLY with a valid JSON object.\n"
    "Do NOT include prose, markdown fences, or any text outside the JSON.\n"
    "ALL text fields in your response MUST be written in English.\n\n"
    "Verdict Rules:\n"
    "- BLOCK : Any finding with severity CRITICAL or HIGH\n"
    "- FLAG  : Any finding with severity MEDIUM, or LOW findings involving auth/secrets\n"
    "- PASS  : No findings, or only INFO-level noise\n\n"
    "Output Schema (strict, no extra keys):\n"
    '{"verdict":"BLOCK|FLAG|PASS","summary":"<English summary>",'
    '"findings":[{"rule_id":"<id>","owasp_category":"<API1:2023... or N/A>",'
    '"severity":"CRITICAL|HIGH|MEDIUM|LOW|INFO",'
    '"message":"<English description>","recommendation":"<English fix>"}],'
    '"block_reasons":["<rule_id>"]}\n\n'
    "Notes:\n"
    "- block_reasons must be [] when verdict is FLAG or PASS.\n"
    "- findings must be [] when verdict is PASS.\n"
    "- Do NOT hallucinate findings. Only report what Semgrep detected.\n"
)

USER_PROMPT_TEMPLATE = """## Semgrep Findings (JSON)

```json
{findings_text}
```

Evaluate the above findings and return the verdict JSON as specified.
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


# 笏笏 Claude client (lazy initialization) 笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏笏
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
    return _get_client().messages.create(**kwargs)


def analyze_with_claude(findings: list) -> tuple[str, str, list, list]:
    """
    Args:
        findings: list of Semgrep finding dicts
    Returns:
        (verdict, summary, detailed_findings, block_reasons)
        e.g. ("BLOCK", "Hardcoded credential detected.", [...], ["rule-id"])
    """
    findings_text = _build_findings_text(findings)
    user_content  = USER_PROMPT_TEMPLATE.format(findings_text=findings_text)

    try:
        message = _call_claude(
            model="claude-haiku-4-5",
            max_tokens=1024,
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

        verdict       = data.get("verdict", "INFO").upper()
        summary       = data.get("summary", "No summary available.")
        details: list[dict] = data.get("findings", [])
        block_reasons: list[str] = data.get("block_reasons", [])
        print(f"  Claude details raw: {json.dumps(details, ensure_ascii=False)}")
        return verdict, summary, details, block_reasons

    except Exception:
        logger.warning("analyze_with_claude error", exc_info=True)
        return "INFO", "Claude response could not be parsed.", [], []
