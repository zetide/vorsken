# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- `semgrep-rules` input default changed to `${{ github.action_path }}/rules/custom`
- Author unified to `vorsken` across `action.yml` and README
- All commits, issues, and PR operations switched to English

### Fixed

- `gate.py` unpack bug caused by 3-tuple → 4-tuple migration

## [0.1.0] - 2026-03-31

### Added

- Initial proof-of-concept: Semgrep + Claude AI end-to-end pipeline
- Policy Gate verdict system: BLOCK / FLAG / PASS
- GitHub Actions composite action (`action.yml`)
- pytest infrastructure with 80% coverage requirement
- ruff lint and mypy type checking in CI
