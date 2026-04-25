# src/stacksecai/config.py
"""
Loads .vorsken.yml config. Falls back to defaults if file not found.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml  # PyYAML

# ── Claude API タイムアウト定数 ──────────────────────────────
CLAUDE_TIMEOUT_TOTAL:   float = 120.0  # 全体上限（秒）
CLAUDE_TIMEOUT_CONNECT: float = 5.0    # 接続確立
CLAUDE_TIMEOUT_READ:    float = 90.0   # レスポンス受信
CLAUDE_TIMEOUT_WRITE:   float = 10.0   # リクエスト送信
# ─────────────────────────────────────────────────────────────

DEFAULT_CONFIG = {
    "policy": {
        "block_on": ["ERROR"],
        "flag_on":  ["WARNING"],
    },
    "claude": {
        "model":          "claude-haiku-4-5",
        "severity_block": ["CRITICAL", "HIGH"],
        "severity_flag":  ["MEDIUM"],
    },
    "rules": {
        "overrides": [],
    },
}


@dataclass
class PolicyConfig:
    block_on:        list[str] = field(default_factory=lambda: ["ERROR"])
    flag_on:         list[str] = field(default_factory=lambda: ["WARNING"])
    claude_model:    str       = "claude-haiku-4-5"
    severity_block:  list[str] = field(default_factory=lambda: ["CRITICAL", "HIGH"])
    severity_flag:   list[str] = field(default_factory=lambda: ["MEDIUM"])
    rule_overrides:  dict[str, str] = field(default_factory=dict)
    # rule_overrides: {"hardcoded-password": "BLOCK", ...}

def load_config(config_path: str = ".vorsken.yml") -> PolicyConfig:
    p = Path(config_path)
    if not p.exists():
        return PolicyConfig()  # all defaults

    with open(p, encoding="utf-8-sig") as f:
        raw = yaml.safe_load(f) or {}

    policy = raw.get("policy", {})
    claude = raw.get("claude", {})
    rules  = raw.get("rules",  {})

    overrides = {
        o["rule_id"]: o["action"].upper()
        for o in rules.get("overrides", [])
        if "rule_id" in o and "action" in o
    }

    return PolicyConfig(
        block_on       = [s.upper() for s in policy.get("block_on", ["ERROR"])],
        flag_on        = [s.upper() for s in policy.get("flag_on",  ["WARNING"])],
        claude_model   = claude.get("model", "claude-haiku-4-5"),
        severity_block = [s.upper() for s in claude.get("severity_block", ["CRITICAL", "HIGH"])],
        severity_flag  = [s.upper() for s in claude.get("severity_flag",  ["MEDIUM"])],
        rule_overrides = overrides,
    )
