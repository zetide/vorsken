# tests/test_claude_analyzer.py
import json
from unittest.mock import MagicMock, patch

import anthropic
import pytest
from anthropic.types import TextBlock
from tenacity import wait_none

import stacksecai.claude_analyzer as mod
from stacksecai.claude_analyzer import analyze_with_claude


# ── ヘルパー ──────────────────────────────────────────────────

def _mock_message(response_body: str) -> MagicMock:
    """`"{" + block.text` で完全な JSON になるモックレスポンス"""
    block = MagicMock(spec=TextBlock)  # isinstance(block, TextBlock) → True
    block.text = response_body         # 先頭 "{" は analyze_with_claude 側で付加
    msg = MagicMock()
    msg.content = [block]
    return msg


def _valid_body() -> str:
    """"{" を除いた有効な JSON ボディ"""
    data = {
        "severity": "HIGH",
        "summary": "Hardcoded credential detected.",
        "findings": [
            {"rule_id": "hardcoded-password", "line": 10, "explanation": "risk", "fix": "fix it"}
        ],
    }
    return json.dumps(data)[1:]  # 先頭の "{" を除く


# ── フィクスチャ ──────────────────────────────────────────────

@pytest.fixture(autouse=True)
def no_retry_wait():
    """テスト中はバックオフ待機をゼロにする（2〜30秒待たない）"""
    original = mod._call_claude.retry.wait
    mod._call_claude.retry.wait = wait_none()
    yield
    mod._call_claude.retry.wait = original


@pytest.fixture()
def mock_client():
    """_get_client() が返すモッククライアントを差し替え"""
    with patch("stacksecai.claude_analyzer._get_client") as p:
        client = MagicMock()
        p.return_value = client
        yield client


# ── 正常系 ────────────────────────────────────────────────────

def test_analyze_returns_severity_and_summary(mock_client):
    mock_client.messages.create.return_value = _mock_message(_valid_body())
    severity, summary, findings = analyze_with_claude([{"check_id": "rule.test"}])
    assert severity == "HIGH"
    assert "credential" in summary
    assert len(findings) == 1


def test_analyze_empty_findings_no_error(mock_client):
    body = json.dumps({"severity": "INFO", "summary": "No issues.", "findings": []})[1:]
    mock_client.messages.create.return_value = _mock_message(body)
    severity, summary, findings = analyze_with_claude([])
    assert severity == "INFO"
    assert findings == []


# ── JSON パースエラー ─────────────────────────────────────────

def test_invalid_json_returns_fallback():
    with patch("stacksecai.claude_analyzer._call_claude") as mock_call:
        block = MagicMock(spec=TextBlock)
        block.text = "not valid json at all}"
        msg = MagicMock()
        msg.content = [block]
        mock_call.return_value = msg
        severity, summary, findings = analyze_with_claude([])
    assert severity == "INFO"
    assert summary == "Claude response could not be parsed."
    assert findings == []


# ── リトライ系（_RETRYABLE 対象）────────────────────────────────

def test_rate_limit_retries_3_times(mock_client):
    mock_client.messages.create.side_effect = anthropic.RateLimitError(
        message="rate limited", response=MagicMock(), body={}
    )
    with pytest.raises(anthropic.RateLimitError):
        analyze_with_claude([])
    assert mock_client.messages.create.call_count == 3


def test_connection_error_retries_3_times(mock_client):
    mock_client.messages.create.side_effect = anthropic.APIConnectionError(
        request=MagicMock()
    )
    with pytest.raises(anthropic.APIConnectionError):
        analyze_with_claude([])
    assert mock_client.messages.create.call_count == 3


def test_timeout_retries_3_times(mock_client):
    mock_client.messages.create.side_effect = anthropic.APITimeoutError(
        request=MagicMock()
    )
    with pytest.raises(anthropic.APITimeoutError):
        analyze_with_claude([])
    assert mock_client.messages.create.call_count == 3


def test_succeeds_on_second_attempt(mock_client):
    """1回失敗→2回目で成功するケース"""
    mock_client.messages.create.side_effect = [
        anthropic.APIConnectionError(request=MagicMock()),
        _mock_message(_valid_body()),
    ]
    severity, summary, _ = analyze_with_claude([])
    assert severity == "HIGH"
    assert mock_client.messages.create.call_count == 2


# ── リトライしない例外（4xx クライアントエラー）──────────────────

def test_auth_error_does_not_retry(mock_client):
    """AuthenticationError は即失敗（リトライなし）"""
    mock_client.messages.create.side_effect = anthropic.AuthenticationError(
        message="invalid key", response=MagicMock(), body={}
    )
    with pytest.raises(anthropic.AuthenticationError):
        analyze_with_claude([])
    assert mock_client.messages.create.call_count == 1