# tests/test_log_filter.py
import logging

from stacksecai.log_filter import SensitiveFilter


def _make_record(msg: str) -> logging.LogRecord:
    record = logging.LogRecord(
        name="test", level=logging.WARNING,
        pathname="", lineno=0, msg=msg,
        args=(), exc_info=None,
    )
    return record


class TestSensitiveFilter:
    def setup_method(self):
        self.f = SensitiveFilter()

    def test_masks_anthropic_api_key(self):
        record = _make_record("key=sk-ant-api03-ABCDEFabcdef1234567890")
        self.f.filter(record)
        assert "sk-ant-api03" not in record.msg
        assert "sk-ant-***" in record.msg

    def test_masks_generic_sk_token(self):
        record = _make_record("Authorization: sk-abc123XYZabc123XYZabc")
        self.f.filter(record)
        assert "sk-abc123" not in record.msg

    def test_masks_bearer_token(self):
        record = _make_record("header: Bearer eyJhbGciOiJIUzI1NiJ9.secret")
        self.f.filter(record)
        assert "eyJhbGciOiJIUzI1NiJ9" not in record.msg
        assert "Bearer ***" in record.msg

    def test_plain_message_unchanged(self):
        msg = "Retrying after RateLimitError"
        record = _make_record(msg)
        self.f.filter(record)
        assert record.msg == msg

    def test_masks_args_tuple(self):
        record = _make_record("key=%s")
        record.args = ("sk-ant-api03-secret1234567890",)
        self.f.filter(record)
        assert "sk-ant-api03-secret" not in str(record.args)

    def test_always_returns_true(self):
        """Filter は削除せず常に通過させる"""
        record = _make_record("sk-ant-api03-shouldbemaskednot dropped")
        assert self.f.filter(record) is True