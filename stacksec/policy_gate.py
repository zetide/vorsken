import json
from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass
class PolicyResult:
    blocked: bool
    blocking_findings: List[Dict[str, Any]]

    def summary(self) -> str:
        if self.blocked:
            lines = ["Policy Gate: BLOCK"]
            for f in self.blocking_findings:
                loc = f.get("start", {})
                lines.append(
                    f"  - {f['check_id']} at {f['path']}:{loc.get('line')}"
                )
            return "\n".join(lines)
        return "Policy Gate: ALLOW"


def evaluate(json_text: str) -> PolicyResult:
    data: Dict[str, Any] = json.loads(json_text)
    blocking = [
        r for r in data.get("results", [])
        if r.get("extra", {}).get("severity", "").upper() == "ERROR"
    ]
    return PolicyResult(blocked=bool(blocking), blocking_findings=blocking)