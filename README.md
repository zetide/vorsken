# StackSecAI Policy Gate

> **Enforce API security policies on every PR — automatically.**
> Semgrep detects vulnerabilities. Claude AI explains them in plain English. Your merge is blocked before bad code ships.

[![CI](https://github.com/stacksecai/stacksecai-dev/actions/workflows/ci.yml/badge.svg)](https://github.com/stacksecai/stacksecai-dev/actions/workflows/ci.yml)
[![codecov](https://img.shields.io/badge/coverage-100%25-brightgreen)](https://github.com/stacksecai/stacksecai-dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![OWASP API Top10](https://img.shields.io/badge/OWASP%20API-Top10%202023-blue)](https://owasp.org/API-Security/)

---

## What It Does

StackSecAI Policy Gate is a GitHub Action that acts as a **security policy enforcement layer** on pull requests.

```
PR opened / updated
  └─▶ Semgrep scans changed files with OWASP API Top10 rules
        └─▶ Claude AI analyzes findings and generates an English report
              └─▶ Verdict posted as a PR comment: BLOCK / FLAG / PASS
                    └─▶ BLOCK verdict fails the required check → merge is prevented
```

**Why this, not just Semgrep alone?**
Semgrep gives you rule IDs and line numbers. StackSecAI adds Claude AI context:
what the vulnerability means, which OWASP category it maps to, and a concrete fix suggestion — all in the PR comment, without leaving GitHub.

---

## Quick Start

### 1. Add the workflow file

Create `.github/workflows/stacksecai.yml` in your repository:

```yaml
name: StackSecAI Policy Gate

on:
  pull_request:
    branches: [main]

jobs:
  policy-gate:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write # required to post PR comments
      contents: read

    steps:
      - uses: actions/checkout@v4

      - uses: stacksecai/stacksecai-dev@v1
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

### 2. Add your Anthropic API key

Go to **Settings → Secrets and variables → Actions** and add:

```
ANTHROPIC_API_KEY = sk-ant-...
```

### 3. Open a pull request

That's it. StackSecAI will automatically scan, analyze, and comment on every PR.

---

## PR Comment Example

```
## 🚨 StackSecAI Policy Gate — BLOCK

**Summary:** A hardcoded API key and an SSRF vulnerability were detected.
Merge is blocked until these issues are resolved.

| Severity | Rule | OWASP Category | Recommendation |
|----------|------|----------------|----------------|
| 🔴 HIGH | hardcoded-api-key | API8:2023 Security Misconfiguration | Move credentials to environment variables. |
| 🔴 HIGH | ssrf-requests | API7:2023 SSRF | Validate and allowlist external URLs before requests. |
```

---

## Configuration

Create `.stacksecai.yml` in your repository root to customize behavior:

```yaml
policy:
  block_on: ["CRITICAL", "HIGH"]
  flag_on: ["MEDIUM"]

claude:
  model: "claude-haiku-4-5" # or claude-sonnet-4-5 for deeper analysis

rules:
  overrides:
    - rule_id: "hardcoded-password"
      action: "BLOCK"
```

### All inputs

| Input               | Required | Default           | Description                     |
| ------------------- | -------- | ----------------- | ------------------------------- |
| `anthropic-api-key` | ✅       | —                 | Anthropic API key for Claude    |
| `github-token`      | —        | `github.token`    | GitHub token for PR comments    |
| `semgrep-rules`     | —        | `rules/custom`    | Path to Semgrep rules directory |
| `target-path`       | —        | `.`               | Path to scan                    |
| `config-path`       | —        | `.stacksecai.yml` | Path to config file             |
| `block-on-error`    | —        | `true`            | Exit code 1 on BLOCK verdict    |

### Output

| Output    | Description                 |
| --------- | --------------------------- |
| `verdict` | `BLOCK` \| `FLAG` \| `PASS` |

---

## OWASP API Security Top 10 (2023) Coverage

| #     | Risk                                            | Rule File                                          | Status |
| ----- | ----------------------------------------------- | -------------------------------------------------- | ------ |
| API1  | Broken Object Level Authorization               | `api1_bola.yml`                                    | ✅     |
| API2  | Broken Authentication                           | `api2_broken_auth.yml`                             | ✅     |
| API3  | Broken Object Property Level Authorization      | `api3_mass_assignment.yml`                         | ✅     |
| API4  | Unrestricted Resource Consumption               | `api4_resource_limit.yml`                          | ✅     |
| API5  | Broken Function Level Authorization             | `api5_func_authz.yml`                              | ✅     |
| API6  | Unrestricted Access to Sensitive Business Flows | `api6_business_flow.yml`                           | ✅     |
| API7  | Server Side Request Forgery (SSRF)              | `ssrf.yml`                                         | ✅     |
| API8  | Security Misconfiguration                       | `api8_debug_mode.yml`, `api8_hardcoded_secret.yml` | ✅     |
| API9  | Improper Inventory Management                   | `api9_inventory.yml`                               | ✅     |
| API10 | Unsafe Consumption of APIs                      | `api10_unsafe_api.yml`                             | ✅     |

---

## Local Development

```bash
git clone https://github.com/stacksecai/stacksecai-dev.git
cd stacksecai-dev
pip install -e .

# Run tests
pytest --cov -v

# Lint and type check
ruff check src/
mypy src/stacksecai --ignore-missing-imports

# Run Semgrep manually
semgrep --config rules/custom tests/fixtures/vulnerable_sample.py
```

---

## Requirements

- Python 3.11+
- [Anthropic API key](https://console.anthropic.com/)
- GitHub Actions runner (ubuntu-latest recommended)

---

## License

MIT — see [LICENSE](LICENSE).

---

## About

Built by [@vorsken](https://github.com/vorsken) as the first OSS module of **StackSecAI** —
a security observability platform for API-first teams.

> _"Shift security left — before the merge, not after the breach."_
