# src/stacksecai/log_filter.py
"""
Logging filter that masks sensitive values (API keys, tokens) in log output.
"""
from __future__ import annotations

import logging
import re

# Anthropic APIキーのパターン: sk-ant-api03-xxxxxxxxxx
_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"sk-ant-[A-Za-z0-9\-_]{10,}"), "sk-ant-***"),
    (re.compile(r"sk-[A-Za-z0-9\-_]{20,}"),      "sk-***"),   # 汎用トークン
    (re.compile(r"Bearer\s+\S+"),                 "Bearer ***"),
]


class SensitiveFilter(logging.Filter):
    """ログメッセージ内の機密文字列を *** に置換する Filter。"""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = self._mask(str(record.msg))
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    k: self._mask(str(v)) for k, v in record.args.items()
                }
            else:
                record.args = tuple(self._mask(str(a)) for a in record.args)
        return True  # 常に通過（削除でなくマスク）

    @staticmethod
    def _mask(text: str) -> str:
        for pattern, replacement in _PATTERNS:
            text = pattern.sub(replacement, text)
        return text