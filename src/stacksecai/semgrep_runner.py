"""
Semgrep runner: executes Semgrep and returns parsed findings.

playground の GitHub Actions 相当のコマンド:
  semgrep --config rules/ --include="src/**" --json --output semgrep-results.json || true
"""

import json
import subprocess
from pathlib import Path


def run_semgrep(
    rules_path: str = "rules/",
    target_path: str = ".",
    include: str = "src/**",
    output_path: str | None = "semgrep-results.json",
) -> list:
    """
    Run Semgrep with given rules on target path.

    Args:
        rules_path:   --config に渡すパス (例: "rules/")
        target_path:  スキャン対象ルート (例: ".")
        include:      --include パターン (例: "src/**")
        output_path:  --output で書き出すJSONパス。Noneならファイル出力しない。

    Returns:
        findings: Semgrep JSON の "results" のリスト
    """
    cmd = [
        "semgrep",
        "--config",
        rules_path,
        "--include",
        include,
        "--json",
    ]

    if output_path:
        cmd.extend(["--output", output_path])

    # GitHub Actions と同じく:
    # - exit code 0: 問題なし
    # - exit code 1: findingsあり
    # それ以外のコードはエラーとして扱う
    result = subprocess.run(
        cmd,
        cwd=target_path,
        capture_output=True,
        text=True,
        encoding="utf-8",   # ← 追加
        errors="replace",   # ← 追加（不正バイト対策）
    )

    if result.returncode not in (0, 1):
        raise RuntimeError(
            f"Semgrep failed with code {result.returncode}:\n{result.stderr}"
        )

    # 出力元を決める：--output を指定した場合はファイル、それ以外は stdout
    if output_path and Path(target_path, output_path).exists():
        with open(Path(target_path, output_path), "r", encoding="utf-8") as f:
            data = json.load(f)
    else:
        # --output を使わない / 何らかの理由でファイルがない場合
        data = json.loads(result.stdout or "{}")  # pragma: no cover

    return data.get("results", [])