# CLAUDE.md

This file provides project context for Claude Code working on the vorsken repository.

## Project Overview

**vorsken** is a GitHub Action that enforces security policy gates on Pull Requests using Semgrep + Claude AI.

- Public repo: https://github.com/zetide/vorsken
- Marketplace: `vorsken-policy-gate` (current: v0.2.6)
- Tagline: "The policy gate between AI-generated code and your main branch."
- License: MIT
- Parent brand: **zetide** (stealth)
- Developer brand: **vorsken**

**Legacy naming (internal only):** the working directory `stacksecai-dev` and the package path `src/stacksecai/` keep their old names. **DO NOT rename them** — import paths, CI, and the Marketplace contract depend on them. All public-facing strings, comments, and docs say "vorsken".

**User config file:** the authoritative config filename is **`.vorsken.yml`** (what `README.md` and `action.yml` use). The GitHub Action passes `CONFIG_PATH=.vorsken.yml`. Treat `.vorsken.yml` as the only real config. (A stray `.stacksecai.yml` previously sat at the repo root as dead weight; it is not read through the Action.)

## Repository Structure

```
stacksecai-dev/                    # repo root (legacy name, kept stable)
├── src/stacksecai/                # main package (legacy name, kept stable)
│   ├── main.py                    # entry point
│   ├── claude_analyzer.py         # Claude API + retry + JSON parsing
│   ├── semgrep_runner.py          # Semgrep execution
│   ├── gate.py                    # policy gate CLI
│   ├── policy_gate.py             # BLOCK/FLAG/PASS decision logic
│   ├── pr_commenter.py            # PR comment posting (update-or-create)
│   ├── log_filter.py              # API key masking filter
│   └── config.py                  # .vorsken.yml loader
├── tests/                         # mirrors src/, cov target 100%
│   └── fixtures/
│       └── vulnerable_sample.py   # OWASP API Top10 vulnerable patterns
├── rules/
│   └── custom/                    # Semgrep custom rules (14 active)
│       └── ai-generated/          # AI-generated-code rules (new in v0.3.0)
├── action.yml                     # GitHub Action definition (Marketplace contract)
└── .vorsken.yml                   # user-facing config example
```

**Ignore repo-root scratch files** (`*.ps1`, `fix_*.py`, `*_fixed.py`, `*_old.*`, `output/`). These are legacy scratch, not part of the Action, and are not referenced by `action.yml` or `pyproject.toml`.

## Bash Commands

```powershell
# Setup
pip install -e .

# Tests (Windows: MUST prefix with $env:PYTHONUTF8=1)
$env:PYTHONUTF8=1; pytest --cov -v

# Single test
$env:PYTHONUTF8=1; pytest tests/test_claude_analyzer.py -v

# Lint
ruff check src/

# Type check
mypy src/stacksecai --ignore-missing-imports

# Semgrep run (manual)
semgrep --config rules/custom tests/fixtures/vulnerable_sample.py
```

**IMPORTANT (Windows):** Always prefix `pytest` with `$env:PYTHONUTF8=1; ` — otherwise tests fail on unicode handling. Do NOT edit files via inline `python -c` in PowerShell; write a `.py` file and run it.

## Architecture

### Policy Gate flow

```
PR push → semgrep (custom rules) → findings sent to Claude API
       → BLOCK/FLAG/PASS verdict → PR comment (update-or-create)
```

### Critical contract: `analyze_with_claude` return type

Returns a **4-tuple**: `(verdict, summary, findings, block_reasons)`.

Any code that destructures this MUST handle exactly 4 values. Past production bugs were caused by 3-tuple unpacking after the contract changed. This is now stable.

### Claude API design

- `_get_client()` lazy-initializes (do NOT read env vars at import time)
- `_call_claude()` uses `@retry` from tenacity
- Retry only on: `RateLimitError`, `APIConnectionError`, `APITimeoutError`
- Do NOT retry on `AuthenticationError` or other 4xx
- `SensitiveFilter` (in `log_filter.py`) masks `sk-ant-***` from logs
- SYSTEM_PROMPT uses `()` string concatenation, NOT triple-quoted strings (BOM/encoding safety on Windows)

### PR comment dedup

- Marker: `COMMENT_MARKER = "vorsken Policy Gate"`
- Existing comment found → PATCH (update)
- No existing comment → POST (create)
- Pagination: 100 per page

## Code Style

- **Language target:** Python 3.11 (CI), 3.14.3 (local OK)
- **All new comments, log messages, and Claude prompts:** English. (Some legacy files still contain non-English comments; do not add new ones. A full sweep is not required for the current task.)
- **No emojis** in code or comments
- **Ruff + mypy strict:** all changes must pass `ruff check` and `mypy --ignore-missing-imports`
- **Test coverage:** maintain **100%** (current state). CI fail-under is 80%, but do not regress.
- **Imports:** stdlib → third-party → local, separated by blank lines
- **Docstrings:** Google style, English

## Testing Rules

- All tests live in `tests/`, mirroring `src/` structure
- Use `unittest.mock` for external services
- Mock Claude API at the `_call_claude` boundary, not at the SDK level
- CI must stay green. If a change breaks CI, fix or revert before moving on.

## Adding New Rules

- AI-generated-code rules live under `rules/custom/ai-generated/`.
- Each new rule needs:
  - the `.yml` file in `rules/custom/ai-generated/`
  - 2+ vulnerable patterns in `tests/fixtures/vulnerable_sample.py`, labelled with a comment `# AI-GEN-{n}`
  - a test assertion that the rule fires on those fixtures
  - a `metadata` field describing the pattern, suitable for PR-comment context
- Keep `severity` consistent with the policy mapping (ERROR → BLOCK, WARNING → FLAG).

## Workflow Rules

- **Default branch policy:** small fixes may push directly to `main` (single-developer project). **New rule development goes on a feature branch — currently `feat/ai-generated-rules`.**
- **Claude Code does NOT self-merge to `main`.** Open work as a draft PR or leave it on the feature branch; **TAKA reviews and merges.**
- **Commits:** Conventional Commits in English (e.g., `feat: add overpermissioned_agent_tool rule`)
- **Versioning:** SemVer via git tags (current: `v0.2.6`). The `version` field in `pyproject.toml` is stale (`0.1.0`); **git tags are the source of truth — do NOT bump `pyproject.toml`.**
- **Release:** GitHub Releases with CHANGELOG entry

## Critical Constraints

**YOU MUST:**

1. Keep all existing rules in `rules/custom/` (OWASP API Top10 + general). Do NOT deprecate or remove any.
2. Preserve the `analyze_with_claude` 4-tuple return contract.
3. Use `()` string concatenation for SYSTEM_PROMPT (never triple-quotes).
4. Run `$env:PYTHONUTF8=1` before any pytest invocation on Windows.
5. Match the existing English-only convention in all new code, comments, and prompts.
6. Maintain 100% test coverage on new code.

**DO NOT:**

1. Rename the `stacksecai-dev` directory or `src/stacksecai/` package (import / CI / Marketplace stability).
2. Read environment variables at import time (use lazy initialization).
3. Retry on `AuthenticationError` or other 4xx (only retry on rate-limit / connection / timeout).
4. Use triple-quoted strings for SYSTEM_PROMPT.
5. Add new dependencies without explicit approval from TAKA.
6. Modify the `action.yml` interface without approval (breaks Marketplace consumers).
7. Self-merge to `main` — TAKA reviews and merges.

## References

- `README.md` — user-facing docs (do not regress unless asked)
- `CHANGELOG.md` — Keep a Changelog format
- `pyproject.toml` — dependencies and tool config (note: `version` field is stale; use git tags)
- `action.yml` — GitHub Action interface (Marketplace contract)
- `.vorsken.yml` — user-facing config example
