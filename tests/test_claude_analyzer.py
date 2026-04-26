# tests/test_claude_analyzer.py
"""Tests for claude_analyzer — new schema: (verdict, summary, findings, block_reasons)"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from anthropic import (
    APIConnectionError,
    APITimeoutError,
    AuthenticationError,
    RateLimitError,
)
from anthropic.types import TextBlock

import stacksecai.claude_analyzer as mod


# ─── helpers ──────────────────────────────────────────────────────────────────

def _make_block(text: str) -> MagicMock:
    block = MagicMock(spec=TextBlock)
    block.text = text
    return block


def _make_message(text: str) -> MagicMock:
    msg = MagicMock()
    msg.content = [_make_block(text)]
    return msg


def _response(verdict="PASS", summary="OK", findings=None, block_reasons=None) -> str:
    """prefill パターン用: raw = "{" + block.text で復元される"""
    data = {
        "verdict": verdict,
        "summary": summary,
        "findings": findings or [],
        "block_reasons": block_reasons or [],
    }
    full = json.dumps(data)
    return full[1:]  # "{" を除いた残り


# ─── SYSTEM_PROMPT ────────────────────────────────────────────────────────────

class TestSystemPrompt:
    def test_is_string(self):
        assert isinstance(mod.SYSTEM_PROMPT, str) and len(mod.SYSTEM_PROMPT) > 0

    def test_english_instruction(self):
        assert "English" in mod.SYSTEM_PROMPT

    def test_verdict_values(self):
        for v in ("BLOCK", "FLAG", "PASS"):
            assert v in mod.SYSTEM_PROMPT

    def test_owasp_reference(self):
        assert "owasp_category" in mod.SYSTEM_PROMPT or "OWASP" in mod.SYSTEM_PROMPT

    def test_no_hallucinate(self):
        assert "hallucinate" in mod.SYSTEM_PROMPT.lower()

    def test_json_only(self):
        assert "JSON" in mod.SYSTEM_PROMPT

    def test_block_reasons(self):
        assert "block_reasons" in mod.SYSTEM_PROMPT

    def test_syntax_ok(self):
        import ast, inspect
        ast.parse(inspect.getsource(mod))


# ─── USER_PROMPT_TEMPLATE ─────────────────────────────────────────────────────

class TestUserPromptTemplate:
    def test_has_placeholder(self):
        assert "{findings_text}" in mod.USER_PROMPT_TEMPLATE

    def test_format(self):
        result = mod.USER_PROMPT_TEMPLATE.format(findings_text="test-finding")
        assert "test-finding" in result


# ─── analyze_with_claude: 正常系 ──────────────────────────────────────────────

class TestAnalyzeHappyPath:

    @patch("stacksecai.claude_analyzer._call_claude")
    def test_block_verdict(self, mock_call):
        mock_call.return_value = _make_message(_response(
            verdict="BLOCK",
            summary="Hardcoded credential detected.",
            findings=[{
                "rule_id": "hardcoded-api-key",
                "owasp_category": "API8:2023 - Security Misconfiguration",
                "severity": "HIGH",
                "description": "Hardcoded API key found in source code.",
                "risk": "Attacker can authenticate as the service and access protected resources.",
                "fix": "Remove hardcoded key. Use environment variable: api_key = os.environ['API_KEY']",
                "line": 0,
            }],
            block_reasons=["hardcoded-api-key"],
        ))
        verdict, summary, findings, block_reasons = mod.analyze_with_claude(
            [{"check_id": "hardcoded-api-key"}]
        )
        assert verdict == "BLOCK"
        assert summary != ""
        assert len(findings) == 1
        assert findings[0]["rule_id"] == "hardcoded-api-key"
        assert findings[0]["owasp_category"] == "API8:2023 - Security Misconfiguration"
        assert block_reasons == ["hardcoded-api-key"]

    @patch("stacksecai.claude_analyzer._call_claude")
    def test_flag_verdict(self, mock_call):
        mock_call.return_value = _make_message(_response(
            verdict="FLAG",
            summary="Medium severity SSRF risk.",
            findings=[{
                "rule_id": "ssrf-risk",
                "owasp_category": "API7:2023 - Server Side Request Forgery",
                "severity": "MEDIUM",
                "description": "Possible SSRF via user-controlled URL.",
                "risk": "Attacker can make the server issue requests to internal services.",
                "fix": "Validate and whitelist URLs against an allowlist before making requests.",
                "line": 0,
            }],
        ))
        verdict, summary, findings, block_reasons = mod.analyze_with_claude(
            [{"check_id": "ssrf-risk"}]
        )
        assert verdict == "FLAG"
        assert block_reasons == []
        assert findings[0]["severity"] == "MEDIUM"

    @patch("stacksecai.claude_analyzer._call_claude")
    def test_pass_verdict(self, mock_call):
        mock_call.return_value = _make_message(_response(
            verdict="PASS", summary="No issues found."
        ))
        verdict, summary, findings, block_reasons = mod.analyze_with_claude([])
        assert verdict == "PASS"
        assert findings == []
        assert block_reasons == []

    @patch("stacksecai.claude_analyzer._call_claude")
    def test_verdict_uppercased(self, mock_call):
        mock_call.return_value = _make_message(_response(verdict="block"))
        verdict, _, _, _ = mod.analyze_with_claude([{}])
        assert verdict == "BLOCK"

    @patch("stacksecai.claude_analyzer._call_claude")
    def test_multiple_findings(self, mock_call):
        mock_call.return_value = _make_message(_response(
            verdict="BLOCK",
            findings=[
                {"rule_id": "eval-injection", "owasp_category": "N/A",
                 "severity": "CRITICAL", "description": "eval() called with user input.",
                 "risk": "Attacker can execute arbitrary code on the server.",
                 "fix": "Remove eval(). Use a safe alternative such as ast.literal_eval().",
                 "line": 0},
                {"rule_id": "sql-injection", "owasp_category": "N/A",
                 "severity": "HIGH", "description": "SQL query built with string concatenation.",
                 "risk": "Attacker can read, modify, or delete arbitrary database records.",
                 "fix": "Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id = %s', (user_id,))",
                 "line": 0},
            ],
            block_reasons=["eval-injection", "sql-injection"],
        ))
        verdict, _, findings, block_reasons = mod.analyze_with_claude([{}, {}])
        assert verdict == "BLOCK"
        assert len(findings) == 2
        assert len(block_reasons) == 2

    @patch("stacksecai.claude_analyzer._call_claude")
    def test_owasp_na(self, mock_call):
        mock_call.return_value = _make_message(_response(
            verdict="FLAG",
            findings=[{
                "rule_id": "subprocess-shell-true", "owasp_category": "N/A",
                "severity": "MEDIUM", "description": "subprocess called with shell=True.",
                "risk": "Attacker can inject shell commands via unsanitized input.",
                "fix": "Pass arguments as a list instead: subprocess.run(['cmd', arg], shell=False)",
                "line": 0,
            }],
        ))
        _, _, findings, _ = mod.analyze_with_claude([{}])
        assert findings[0]["owasp_category"] == "N/A"


# ─── analyze_with_claude: フォールバック ──────────────────────────────────────

class TestAnalyzeFallback:

    @patch("stacksecai.claude_analyzer._call_claude")
    def test_invalid_json_fallback(self, mock_call):
        mock_call.return_value = _make_message("this is not valid json}")
        verdict, summary, findings, block_reasons = mod.analyze_with_claude([{}])
        assert verdict == "INFO"
        assert findings == []
        assert block_reasons == []

    @patch("stacksecai.claude_analyzer._call_claude")
    def test_non_textblock_fallback(self, mock_call):
        msg = MagicMock()
        msg.content = [MagicMock()]  # spec=TextBlock なし
        mock_call.return_value = msg
        verdict, summary, findings, block_reasons = mod.analyze_with_claude([{}])
        assert verdict == "INFO"
        assert findings == []

    @patch("stacksecai.claude_analyzer._call_claude")
    def test_rate_limit_fallback(self, mock_call):
        mock_call.side_effect = RateLimitError(
            message="rate limited",
            response=MagicMock(status_code=429, headers={}),
            body=None,
        )
        verdict, summary, findings, block_reasons = mod.analyze_with_claude([{}])
        assert verdict == "INFO"
        assert findings == []

    @patch("stacksecai.claude_analyzer._call_claude")
    def test_auth_error_fallback(self, mock_call):
        mock_call.side_effect = AuthenticationError(
            message="invalid api key",
            response=MagicMock(status_code=401, headers={}),
            body=None,
        )
        verdict, _, findings, _ = mod.analyze_with_claude([{}])
        assert verdict == "INFO"


# ─── _call_claude: リトライ ───────────────────────────────────────────────────

class TestCallClaudeRetry:

    @patch("stacksecai.claude_analyzer._get_client")
    def test_rate_limit_retries_3(self, mock_get_client):
        client = MagicMock()
        mock_get_client.return_value = client
        client.messages.create.side_effect = RateLimitError(
            message="rate limited",
            response=MagicMock(status_code=429, headers={}),
            body=None,
        )
        with pytest.raises(RateLimitError):
            mod._call_claude(model="claude-haiku-4-5", max_tokens=512,
                             system="sys", messages=[{"role": "user", "content": "t"}])
        assert client.messages.create.call_count == mod.MAX_RETRIES

    @patch("stacksecai.claude_analyzer._get_client")
    def test_connection_error_retries(self, mock_get_client):
        client = MagicMock()
        mock_get_client.return_value = client
        client.messages.create.side_effect = APIConnectionError(
            message="conn failed", request=MagicMock()
        )
        with pytest.raises(APIConnectionError):
            mod._call_claude(model="claude-haiku-4-5", max_tokens=512,
                             system="sys", messages=[{"role": "user", "content": "t"}])
        assert client.messages.create.call_count == mod.MAX_RETRIES

    @patch("stacksecai.claude_analyzer._get_client")
    def test_timeout_retries(self, mock_get_client):
        client = MagicMock()
        mock_get_client.return_value = client
        client.messages.create.side_effect = APITimeoutError(request=MagicMock())
        with pytest.raises(APITimeoutError):
            mod._call_claude(model="claude-haiku-4-5", max_tokens=512,
                             system="sys", messages=[{"role": "user", "content": "t"}])
        assert client.messages.create.call_count == mod.MAX_RETRIES

    @patch("stacksecai.claude_analyzer._get_client")
    def test_auth_error_no_retry(self, mock_get_client):
        client = MagicMock()
        mock_get_client.return_value = client
        client.messages.create.side_effect = AuthenticationError(
            message="invalid key",
            response=MagicMock(status_code=401, headers={}),
            body=None,
        )
        with pytest.raises(AuthenticationError):
            mod._call_claude(model="claude-haiku-4-5", max_tokens=512,
                             system="sys", messages=[{"role": "user", "content": "t"}])
        assert client.messages.create.call_count == 1

    @patch("stacksecai.claude_analyzer._get_client")
    def test_success_on_second_attempt(self, mock_get_client):
        client = MagicMock()
        mock_get_client.return_value = client
        good = _make_message(_response(verdict="PASS"))
        client.messages.create.side_effect = [
            RateLimitError(
                message="rate limited",
                response=MagicMock(status_code=429, headers={"retry-after": "0"}),
                body=None,
            ),
            good,
        ]
        result = mod._call_claude(model="claude-haiku-4-5", max_tokens=512,
                                  system="sys", messages=[{"role": "user", "content": "t"}])
        assert result is good
        assert client.messages.create.call_count == 2


# ─── _get_client ──────────────────────────────────────────────────────────────

class TestGetClient:

    def test_creates_instance(self):
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "sk-ant-test-dummy"}):
            mod._client = None
            client = mod._get_client()
            assert client is not None

    def test_caches_instance(self):
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "sk-ant-test-dummy"}):
            mod._client = None
            c1 = mod._get_client()
            c2 = mod._get_client()
            assert c1 is c2


# ─── _build_findings_text ─────────────────────────────────────────────────────

class TestBuildFindingsText:

    def test_empty_returns_string(self):
        result = mod._build_findings_text([])
        assert isinstance(result, str)

    def test_single_finding_has_rule_id(self):
        finding = {
            "check_id": "hardcoded-password",
            "path": "src/app.py",
            "start": {"line": 42},
            "extra": {"message": "Password found", "severity": "HIGH"},
        }
        result = mod._build_findings_text([finding])
        assert "hardcoded-password" in result or "app.py" in result

    def test_multiple_findings_all_included(self):
        findings = [
            {"check_id": f"rule-{i}", "path": "app.py",
             "start": {"line": i}, "extra": {"message": "msg", "severity": "HIGH"}}
            for i in range(3)
        ]
        result = mod._build_findings_text(findings)
        for i in range(3):
            assert f"rule-{i}" in result
