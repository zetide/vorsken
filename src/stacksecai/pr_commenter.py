"""
PR Commenter: posts Policy Gate verdict as a GitHub PR comment.
"""
import os
import requests
from .policy_gate import VERDICT_EMOJI


def post_pr_comment(verdict: str, semgrep_findings: list, explanation: str) -> None:
    token   = os.environ["GITHUB_TOKEN"]
    repo    = os.environ["GITHUB_REPOSITORY"]
    pr_num  = os.environ["PR_NUMBER"]

    emoji = VERDICT_EMOJI.get(verdict, "❓")
    finding_lines = "\n".join(
        f"- `{f.get('check_id','?')}` → {f.get('path','?')}:{f.get('start',{}).get('line','?')}"
        for f in semgrep_findings
    ) or "_No findings._"

    body = f"""## stacksecai Policy Gate {emoji} `{verdict}`

**Claude Assessment:** {explanation}

**Semgrep Findings:**
{finding_lines}

---
<sub>Powered by [stacksecai](https://rilvak.dev) · Policy Gate v0.1</sub>"""

    url = f"https://api.github.com/repos/{repo}/issues/{pr_num}/comments"
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}
    resp = requests.post(url, json={"body": body}, headers=headers)
    resp.raise_for_status()
