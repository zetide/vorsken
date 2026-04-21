# tests/test_main.py
import sys
import pytest
from unittest.mock import patch, MagicMock
from stacksecai.main import main


MOCK_FINDINGS = [{"check_id": "rules.custom.hardcoded-password",
                   "path": "app/config.py",
                   "start": {"line": 5},
                   "extra": {"severity": "ERROR"}}]


def _run_main(findings, severity, verdict, block_on_error="true", tmp_path=None):
    env = {
        "ANTHROPIC_API_KEY": "test-key",
        "SEMGREP_RULES":     "rules/custom",
        "TARGET_PATH":       ".",
        "BLOCK_ON_ERROR":    block_on_error,
        "GITHUB_OUTPUT":     str(tmp_path / "out.txt") if tmp_path else "/dev/null",
        "GITHUB_TOKEN":      "test-token",
        "GITHUB_REPOSITORY": "org/repo",
        "PR_NUMBER":         "1",
    }
    with patch("stacksecai.main.run_semgrep",        return_value=findings), \
         patch("stacksecai.main.analyze_with_claude", return_value=(severity, "summary", [], [])), \
         patch("stacksecai.main.post_pr_comment"), \
         patch.dict("os.environ", env):
        return main()


def test_main_block_exits_1(tmp_path):
    with pytest.raises(SystemExit) as exc:
        _run_main(MOCK_FINDINGS, "HIGH", "BLOCK", tmp_path=tmp_path)
    assert exc.value.code == 1


def test_main_pass_exits_0(tmp_path):
    with pytest.raises(SystemExit) as exc:
        _run_main([], "LOW", "PASS", tmp_path=tmp_path)
    assert exc.value.code == 0


def test_main_block_on_error_false_exits_0(tmp_path):
    with pytest.raises(SystemExit) as exc:
        _run_main(MOCK_FINDINGS, "HIGH", "BLOCK", block_on_error="false", tmp_path=tmp_path)
    assert exc.value.code == 0


def test_main_writes_github_output(tmp_path):
    with pytest.raises(SystemExit):
        _run_main([], "LOW", "PASS", tmp_path=tmp_path)
    output = (tmp_path / "out.txt").read_text(encoding="utf-8")
    assert "verdict=PASS" in output