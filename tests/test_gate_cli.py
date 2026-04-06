# tests/test_gate_cli.py を修正
import json
import pytest
from stacksecai.gate import main

RESULT_JSON       = "result.json"
EMPTY_RESULT_JSON = "tests/fixtures/empty_result.json"

def test_cli_block_with_severity_override():
    rc = main([RESULT_JSON, "--severity", "HIGH", "--no-comment"])
    assert rc == 1  # Semgrep ERROR あり → BLOCK

def test_cli_block_semgrep_error_ignores_low_severity():
    """Semgrep ERROR が存在する場合 Claude LOW でも BLOCK になること"""
    rc = main([RESULT_JSON, "--severity", "LOW", "--no-comment"])
    assert rc == 1  # Semgrep ERROR 優先 → BLOCK

def test_cli_pass_with_no_findings():
    """findings ゼロ + Claude LOW → PASS"""
    rc = main([EMPTY_RESULT_JSON, "--severity", "LOW", "--no-comment"])
    assert rc == 0  # PASS → exit 0

def test_cli_missing_file():
    with pytest.raises(SystemExit) as exc:
        main(["nonexistent.json", "--severity", "LOW"])
    assert exc.value.code == 2