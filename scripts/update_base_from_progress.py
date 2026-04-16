import re
import yaml
from pathlib import Path

STATUS_ICON = {
    "done":  "✅",
    "doing": "🔄",
    "todo":  "⬜",
}

def build_month2_table(month2_tasks: list) -> str:
    header = (
        "| #   | タスク | 状態 |\n"
        "| --- | ------ | ---- |\n"
    )
    rows = ""
    for i, task in enumerate(month2_tasks, start=1):
        icon = STATUS_ICON.get(task["status"], "⬜")
        rows += f"| {i}   | {task['title']} | {icon} |\n"
    return header + rows

def update_section(md: str, section_marker: str, new_table: str) -> str:
    pattern = rf"({re.escape(section_marker)}.*?\n)((?:\|.*\n)+)"
    replacement = rf"\1{new_table}"
    return re.sub(pattern, replacement, md, flags=re.DOTALL)

def main():
    root = Path(__file__).parent.parent
    yaml_path = root / "ssai_progress.yaml"
    md_path   = root / "stacksecai_project_base.md"

    data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
    md   = md_path.read_text(encoding="utf-8")

    new_table = build_month2_table(data["month2_tasks"])
    md = update_section(md, "## 10. Month 2 進捗", new_table)

    md_path.write_text(md, encoding="utf-8")
    print("✅ stacksecai_project_base.md を更新しました")

if __name__ == "__main__":
    main()