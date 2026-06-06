# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-06-07

### Added

- `overpermissioned-agent-tool` rule: flags LangChain file/agent toolkits (e.g. `FileManagementToolkit`) instantiated without a `root_dir` scope, which grants the agent the full filesystem (`ERROR`, OWASP LLM Top 10)
- `sql-injection` rule: flags SQL built from a dynamically constructed string (f-string, concatenation, `str.format()`, or `%` formatting) and passed to `execute()` / `executemany()` (`ERROR`, CWE-89)
- `code-execution` rule: blocks `exec()`, `compile()`, `pickle.load()`, and `pickle.loads()` (`ERROR`, CWE-94 / CWE-502)
- `dangerous-ai-kwargs` rule: blocks `trust_remote_code=True`, `allow_dangerous_code=True`, and `allow_dangerous_deserialization=True` on any call (`ERROR`, OWASP LLM Top 10 / LLM06)

### Changed

- Default policy `block_on` / `flag_on` widened to recognize OWASP severities: `block_on` is now `[ERROR, CRITICAL, HIGH]` and `flag_on` `[WARNING, MEDIUM]`, with case-insensitive comparison, so HIGH/CRITICAL Semgrep findings BLOCK on their own instead of falling through to PASS
- `subprocess-shell-true` rewritten as `pattern-either` covering `subprocess.run` / `Popen` / `call` / `check_call` / `check_output` with `shell=True`, restoring OS command-injection detection (`ERROR`, CWE-78)
- Replaced the dedicated `api1_bola.yml` rule: its f-string SQL pattern was relabeled and moved into the generic `sql-injection` rule (BOLA / CWE-639 → SQL injection / CWE-89); API1 (BOLA) now has no dedicated Semgrep rule and is left to Claude's contextual review
- Rebranded user-facing strings, author metadata, and positioning from StackSecAI to vorsken
- **Default config file renamed from `.stacksecai.yml` to `.vorsken.yml`.** Existing users with a `.stacksecai.yml` must rename it to `.vorsken.yml` (or point `CONFIG_PATH` at it). The previous filename is no longer read.

## [0.2.6] - 2026-04-27

### Added

- OWASP API Security Top 10 (2023) detection via Semgrep custom rules (API1–API10)
- `vulnerable_sample.py` fixture covering all 10 OWASP API risk categories
- `block_reasons` field in Claude AI analysis output
- `owasp_category` classification in policy gate findings
- English-enforced output from Claude AI (SYSTEM_PROMPT redesign)
- PR comment deduplication via update-or-create pattern
- Sensitive data masking in logs via `SensitiveFilter`
- Retry logic with exponential backoff via `tenacity` (RateLimitError, APIConnectionError, APITimeoutError)
- HTTP timeout configuration via `httpx.Timeout` (total=120s / connect=5s)
- `.stacksecai.yml` config file support for policy customization
- `outputs.verdict` exposed via `$GITHUB_OUTPUT` for downstream workflow steps
- `branding` (shield / red) in `action.yml` for GitHub Marketplace

### Changed

- `analyze_with_claude` return value expanded to 4-tuple: `(verdict, summary, findings, block_reasons)`
- `semgrep-rules` input default set to `${{ github.action_path }}/rules/custom`

### Fixed

- `gate.py` unpack bug caused by 3-tuple → 4-tuple migration

## [0.1.0] - 2026-03-31

### Added

- Initial proof-of-concept: Semgrep + Claude AI end-to-end pipeline
- Policy Gate verdict system: BLOCK / FLAG / PASS
- GitHub Actions composite action (`action.yml`)
- pytest infrastructure with 80% coverage requirement
- ruff lint and mypy type checking in CI
