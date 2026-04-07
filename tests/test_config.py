# tests/test_config.py
import pytest
from stacksecai.config import load_config, PolicyConfig


def test_default_config_when_no_file():
    cfg = load_config("nonexistent.yml")
    assert cfg.block_on       == ["ERROR"]
    assert cfg.flag_on        == ["WARNING"]
    assert cfg.severity_block == ["CRITICAL", "HIGH"]
    assert cfg.severity_flag  == ["MEDIUM"]
    assert cfg.rule_overrides == {}


def test_load_custom_config(tmp_path):
    yml = tmp_path / ".stacksecai.yml"
    yml.write_text("""
policy:
  block_on: ["ERROR", "WARNING"]
  flag_on:  []
claude:
  model: "claude-opus-4-5"
  severity_block: ["CRITICAL"]
  severity_flag:  ["HIGH", "MEDIUM"]
rules:
  overrides:
    - rule_id: "hardcoded-password"
      action: "BLOCK"
""", encoding="utf-8")

    cfg = load_config(str(yml))
    assert "WARNING"            in cfg.block_on
    assert cfg.claude_model     == "claude-opus-4-5"
    assert cfg.severity_block   == ["CRITICAL"]
    assert "HIGH"               in cfg.severity_flag
    assert cfg.rule_overrides   == {"hardcoded-password": "BLOCK"}


def test_compute_verdict_respects_custom_config():
    from stacksecai.policy_gate import compute_verdict
    from stacksecai.config import PolicyConfig

    # WARNING を BLOCK 扱いにするカスタム設定
    cfg = PolicyConfig(block_on=["ERROR", "WARNING"], flag_on=[])
    findings = [{"extra": {"severity": "WARNING"}}]
    assert compute_verdict(findings, "LOW", config=cfg) == "BLOCK"


def test_compute_verdict_default_config():
    from stacksecai.policy_gate import compute_verdict
    findings = [{"extra": {"severity": "WARNING"}}]
    # デフォルト: WARNING → FLAG
    assert compute_verdict(findings, "LOW") == "FLAG"

def test_rule_override_block():
    """rule_overrides で BLOCK が強制されること"""
    from stacksecai.policy_gate import compute_verdict
    from stacksecai.config import PolicyConfig

    cfg = PolicyConfig(
        block_on=[],           # Semgrep ERROR でも通常はBLOCKしない設定
        flag_on=[],
        severity_block=[],     # Claude も BLOCK しない設定
        severity_flag=[],
        rule_overrides={"hardcoded-password": "BLOCK"},
    )
    findings = [{"check_id": "rules.custom.hardcoded-password",
                 "extra": {"severity": "WARNING"}}]
    assert compute_verdict(findings, "LOW", config=cfg) == "BLOCK"


def test_rule_override_flag_downgrades_error():
    """ERROR finding でも rule_overrides FLAG なら FLAG になること"""
    from stacksecai.policy_gate import compute_verdict
    from stacksecai.config import PolicyConfig

    cfg = PolicyConfig(
        block_on=[],           # ERRORをBLOCKしない
        flag_on=[],
        severity_block=[],
        severity_flag=[],
        rule_overrides={"eval-injection": "FLAG"},
    )
    findings = [{"check_id": "rules.custom.eval-injection",
                 "extra": {"severity": "ERROR"}}]
    assert compute_verdict(findings, "LOW", config=cfg) == "FLAG"


def test_rule_override_no_match_returns_pass():
    """マッチするルールがなければ通常判定（PASS）になること"""
    from stacksecai.policy_gate import compute_verdict
    from stacksecai.config import PolicyConfig

    cfg = PolicyConfig(
        block_on=[], flag_on=[],
        severity_block=[], severity_flag=[],
        rule_overrides={"other-rule": "BLOCK"},
    )
    findings = [{"check_id": "rules.custom.eval-injection",
                 "extra": {"severity": "WARNING"}}]
    assert compute_verdict(findings, "LOW", config=cfg) == "PASS"