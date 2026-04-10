import json
import shutil
from unittest.mock import MagicMock, patch

import pytest

from stacksecai.semgrep_runner import run_semgrep


def _mock_result(returncode=0, stdout=''):
    m = MagicMock()
    m.returncode = returncode
    m.stdout = stdout
    m.stderr = ''
    return m


@pytest.mark.skip(reason='integration test: requires real semgrep rules and fixtures')
def test_run_semgrep_on_fixture_returns_findings():
    findings = run_semgrep(
        rules_path='rules/',
        target_path='.',
        include='tests/fixtures/**',
        output_path=None,
    )
    assert len(findings) > 0


def test_run_semgrep_with_output_path(tmp_path):
    findings = [{'check_id': 'rule.test'}]
    output_file = tmp_path / 'semgrep-results.json'
    output_file.write_text(json.dumps({'results': findings}), encoding='utf-8')

    with patch('subprocess.run', return_value=_mock_result(0)) as mock_sub:
        result = run_semgrep(
            rules_path='rules/',
            target_path=str(tmp_path),
            output_path='semgrep-results.json',
        )

    assert result == findings
    called_cmd = mock_sub.call_args[0][0]
    assert '--output' in called_cmd


def test_run_semgrep_raises_on_bad_returncode():
    with patch('subprocess.run', return_value=_mock_result(returncode=2, stdout='')):
        with pytest.raises(RuntimeError, match='Semgrep failed with code 2'):
            run_semgrep(output_path=None)


def test_run_semgrep_reads_from_file(tmp_path):
    findings = [{'check_id': 'rule.file-read'}]
    output_file = tmp_path / 'semgrep-results.json'
    output_file.write_text(json.dumps({'results': findings}), encoding='utf-8')

    with patch('subprocess.run', return_value=_mock_result(0)):
        result = run_semgrep(
            target_path=str(tmp_path),
            output_path='semgrep-results.json',
        )

    assert result == findings
