import pytest
from src.stacksecai.semgrep_runner import run_semgrep


@pytest.mark.xfail(reason="Semgrep exit code 7 (rule configuration to be fixed later)")
def test_run_semgrep_on_fixture_returns_findings():
    findings = run_semgrep(
        rules_path="rules/",
        target_path=".",
        include="tests/fixtures/**",
        output_path=None,
    )
    assert len(findings) > 0