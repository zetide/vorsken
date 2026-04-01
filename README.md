# stacksecai — Policy Gate for GitHub PRs

[![CI](https://github.com/rilvak/stacksecai/actions/workflows/ci.yml/badge.svg)](https://github.com/rilvak/stacksecai/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> Enforce security policies on every pull request using **Semgrep + Claude AI**.
> Returns a clear **BLOCK / FLAG / PASS** verdict — before code reaches main.

## Quick Start

```yaml
# .github/workflows/security-gate.yml
name: Security Gate
on: [pull_request]

jobs:
  policy-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: rilvak/stacksecai@v0.1
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

## Verdict Logic

| Verdict | Trigger | PR Effect |
|---------|---------|-----------|
| 🚫 BLOCK | Semgrep `ERROR` or Claude `CRITICAL/HIGH` | Fails required check (blocks merge) |
| ⚠️ FLAG  | Semgrep `WARNING` or Claude `MEDIUM`      | Comment only, merge allowed |
| ✅ PASS  | No findings                               | Green check |

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `anthropic-api-key` | ✅ | — | Anthropic API key |
| `semgrep-rules` | ❌ | `rules/custom` | Path to Semgrep rules |
| `block-on-error` | ❌ | `true` | Exit 1 on BLOCK verdict |
| `github-token` | ❌ | `github.token` | For PR comments |

## Built-in Rules

- `eval-injection` — eval() usage (ERROR)
- `subprocess-shell-true` — shell injection risk (ERROR)
- `hardcoded-password` — credentials in code (ERROR)
- `ssrf-via-requests` — unvalidated URL in requests (WARNING)

## Part of [Rilvak](https://rilvak.dev) security platform.
