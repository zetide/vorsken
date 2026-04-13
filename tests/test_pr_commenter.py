# tests/test_pr_commenter.py
import os
from unittest.mock import MagicMock, call, patch

import pytest

from stacksecai.pr_commenter import (
    COMMENT_MARKER,
    _find_existing_comment,
    format_pr_comment,
    post_pr_comment,
)

# ── ヘルパー ──────────────────────────────────────────────────

def _mock_resp(json_data, status_code=200):
    m = MagicMock()
    m.status_code = status_code
    m.json.return_value = json_data
    m.raise_for_status = MagicMock()
    return m


ENV = {
    "GITHUB_TOKEN":      "test-token",
    "GITHUB_REPOSITORY": "owner/repo",
    "PR_NUMBER":         "42",
}

# ── format_pr_comment ─────────────────────────────────────────

def test_format_contains_marker():
    result = format_pr_comment("PASS", [], "LOW", "No issues.", [])
    assert COMMENT_MARKER in result


def test_format_block_verdict():
    result = format_pr_comment("BLOCK", [], "HIGH", "Risk found.", [])
    assert "BLOCK" in result


def test_format_with_semgrep_findings():
    findings = [{"check_id": "rule.test", "extra": {"severity": "ERROR"},
                 "path": "app.py", "start": {"line": 10}}]
    result = format_pr_comment("BLOCK", findings, "HIGH", "Risk.", [])
    assert "test" in result        # split(".")[-1] で末尾のみ表示される
    assert "app.py" in result      # パスも確認
    assert "ERROR" in result       # severity も確認


def test_format_with_claude_details():
    details = [{"rule_id": "sql-injection", "line": 5,
                "explanation": "risk", "fix": "use ORM"}]
    result = format_pr_comment("FLAG", [], "MEDIUM", "SQL risk.", details)
    assert "sql-injection" in result


# ── _find_existing_comment ────────────────────────────────────

def test_find_existing_returns_id():
    headers = {}
    comments = [{"id": 99, "body": f"## PASS — {COMMENT_MARKER}"}]
    with patch("requests.get", return_value=_mock_resp(comments)):
        result = _find_existing_comment("https://api.github.com/test", headers)
    assert result == 99


def test_find_existing_returns_none_when_empty():
    with patch("requests.get", return_value=_mock_resp([])):
        result = _find_existing_comment("https://api.github.com/test", {})
    assert result is None


def test_find_existing_returns_none_when_no_match():
    comments = [{"id": 1, "body": "unrelated comment"}]
    with patch("requests.get", return_value=_mock_resp(comments)):
        result = _find_existing_comment("https://api.github.com/test", {})
    assert result is None


# ── post_pr_comment（新規投稿） ──────────────────────────────────

def test_post_new_comment_when_no_existing(monkeypatch):
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)

    with patch("requests.get",  return_value=_mock_resp([])) as mock_get, \
         patch("requests.post", return_value=_mock_resp({"id": 1})) as mock_post, \
         patch("requests.patch") as mock_patch:
        post_pr_comment("PASS", [], "LOW", "ok", [])

    mock_post.assert_called_once()
    mock_patch.assert_not_called()


# ── post_pr_comment（既存コメント更新）────────────────────────────

def test_update_existing_comment_when_found(monkeypatch):
    for k, v in ENV.items():
        monkeypatch.setenv(k, v)

    existing = [{"id": 55, "body": f"## BLOCK — {COMMENT_MARKER}"}]
    with patch("requests.get",  return_value=_mock_resp(existing)), \
         patch("requests.patch", return_value=_mock_resp({"id": 55})) as mock_patch, \
         patch("requests.post") as mock_post:
        post_pr_comment("PASS", [], "LOW", "fixed", [])

    mock_patch.assert_called_once()
    mock_post.assert_not_called()
    # PATCH URL に comment ID が含まれているか確認
    patch_url = mock_patch.call_args[0][0]
    assert "55" in patch_url