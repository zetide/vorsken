import pytest
from src.stacksecai.semgrep_runner import run_semgrep


def test_run_semgrep_on_fixture_returns_findings():
    findings = run_semgrep(
        rules_path="rules/",
        target_path=".",
        include="tests/fixtures/**",
        output_path=None,
    )
    assert len(findings) > 0