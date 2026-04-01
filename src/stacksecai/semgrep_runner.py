"""
Semgrep runner: executes Semgrep and returns parsed findings.
Ported from playground/ - add your E2E logic here.
"""
import subprocess
import json
import os


def run_semgrep(rules_path: str, target_path: str) -> list:
    """
    Run Semgrep with given rules on target path.
    Returns list of finding dicts.
    """
    cmd = [
        "semgrep",
        "--config", rules_path,
        "--json",
        target_path,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode not in (0, 1):
        raise RuntimeError(f"Semgrep error: {result.stderr}")

    data = json.loads(result.stdout)
    return data.get("results", [])
