# stacksecai-dev プロジェクトベースファイル

> 新スレ開始時に必ず共有するドキュメント。このファイルを読めば現状と次のアクションがわかる。

---

## 1. プロジェクト概要

### 1行定義

> "A GitHub Actions OSS that auto-comments API vulnerability findings on PRs using Semgrep + Claude AI"

### 背景

セキュリティSaaS「StackSecAI（仮称）」を個人開発中。
3レイヤー構成（AI Code / API Runtime / Compliance）の最初のOSS。

### コンセプト

「ポリシーゲート」= Semgrep + Claude API で PR の変更を **BLOCK / FLAG / PASS** で評価する GitHub Action。
Anthropic の auto-fix の「前段でポリシーを強制する層」として差別化。
海外向け・英語ドキュメント・MIT ライセンス。

---

## 2. リポジトリ情報

| 項目               | 内容                                         |
| ------------------ | -------------------------------------------- |
| リポジトリ         | https://github.com/stacksecai/stacksecai-dev |
| ローカルパス       | C:\dev\stacksecai-dev                        |
| Python（ローカル） | 3.14.3                                       |
| Python（CI）       | 3.11                                         |
| パッケージ構成     | src/stacksecai/ 以下                         |
| ブランチ運用       | main ブランチへ直 push（現状）               |

---

## 3. 技術スタック

| カテゴリ     | 内容                                           |
| ------------ | ---------------------------------------------- |
| 言語         | Python                                         |
| 静的解析     | Semgrep                                        |
| AI解析       | Claude API（anthropic SDK）                    |
| CI           | GitHub Actions（ruff → mypy → pytest --cov）   |
| リトライ     | tenacity（Exponential backoff）                |
| タイムアウト | httpx.Timeout（total=120s / connect=5s）       |
| ロギング     | logging + SensitiveFilter（APIキーマスキング） |
| テスト       | pytest / pytest-cov / unittest.mock            |
| Lint         | ruff                                           |
| 型チェック   | mypy                                           |

---

## 4. ファイル構成

```
stacksecai-dev/
├── src/stacksecai/
│   ├── __init__.py
│   ├── main.py              # エントリーポイント
│   ├── claude_analyzer.py   # Claude API呼び出し・JSON解析・tenacityリトライ
│   ├── semgrep_runner.py    # Semgrep実行
│   ├── gate.py              # ポリシーゲート CLI
│   ├── policy_gate.py       # 判定ロジック（BLOCK/FLAG/PASS）
│   ├── pr_commenter.py      # PRコメント投稿（重複抑制・update-or-create）
│   ├── log_filter.py        # APIキーマスキング用 logging.Filter
│   └── config.py            # 設定読み込み（.stacksecai.yml）
├── tests/
│   ├── test_claude_analyzer.py
│   ├── test_config.py
│   ├── test_e2e.py
│   ├── test_gate_cli.py
│   ├── test_log_filter.py
│   ├── test_main.py
│   ├── test_policy_gate.py
│   ├── test_pr_commenter.py
│   ├── test_semgrep_runner.py
│   └── fixtures/
├── rules/                   # Semgrepカスタムルール
│   └── （eval / subprocess / ssrf / hardcoded_pw 他）
├── .github/workflows/       # CI定義
├── pyproject.toml
└── .stacksecai.yml          # ポリシー設定ファイル（ユーザー設定）
```

---

## 5. 主要な設計ポイント

### Policy Gate 判定フロー

```
PR push
  └→ Semgrep 実行（カスタムルール）
       └→ findings を Claude API に送信
            └→ BLOCK / FLAG / PASS を判定
                 └→ PR にコメント投稿（重複時は更新）
```

### Claude API 設計

- `_get_client()` 遅延初期化（import時に環境変数を読まない）
- `_call_claude()` に `@retry` デコレータ（tenacity）
- リトライ対象：`RateLimitError` / `APIConnectionError` / `APITimeoutError` のみ
- `AuthenticationError` など 4xx は即失敗（リトライなし）
- `SensitiveFilter` で `sk-ant-***` をログからマスキング

### PRコメント重複抑制

- `COMMENT_MARKER = "StackSecAI Policy Gate"` で既存コメントを検索
- 既存あり → `PATCH`（更新）、なし → `POST`（新規）
- 100件ページネーション対応

### .stacksecai.yml 設定例

```yaml
policy:
  block_on: ["ERROR"]
  flag_on: ["WARNING"]
claude:
  model: "claude-haiku-4-5"
  severity_block: ["CRITICAL", "HIGH"]
  severity_flag: ["MEDIUM"]
rules:
  overrides:
    - rule_id: "hardcoded-password"
      action: "BLOCK"
```

---

## 6. 開発環境セットアップ

```powershell
# リポジトリクローン
git clone https://github.com/stacksecai/stacksecai-dev.git
cd stacksecai-dev

# 依存インストール
pip install -e .

# 動作確認
python -c "from stacksecai.claude_analyzer import analyze_with_claude; print('OK')"

# テスト実行
pytest --cov -v

# Lint / 型チェック
ruff check src/
mypy src/stacksecai --ignore-missing-imports
```

### 必要な環境変数

```
ANTHROPIC_API_KEY   # Claude API キー
GITHUB_TOKEN        # GitHub Actions で自動設定
GITHUB_REPOSITORY   # GitHub Actions で自動設定（owner/repo）
PR_NUMBER           # GitHub Actions で設定
```

### VSCode 設定（.vscode/settings.json）

```json
{
  "python.analysis.extraPaths": ["src"]
}
```

---

## 7. CI 構成（GitHub Actions）

```
ruff check src/
  ↓
mypy src/stacksecai --ignore-missing-imports
  ↓
pytest --cov（fail-under=80）
```

---

## 8. pyproject.toml dependencies（主要）

```toml
dependencies = [
    "anthropic",
    "httpx>=0.28.1",
    "pyyaml",
    "requests",
    "semgrep",
    "tenacity>=9.1.4",
]
```

---

## 9. 6ヶ月ロードマップ

| Month     | テーマ           | 主なアウトプット                                  | 状態      |
| --------- | ---------------- | ------------------------------------------------- | --------- |
| M1（3月） | 学習・土台       | Semgrep+Claude E2E動作確認                        | ✅ 完了   |
| M2（4月） | コアロジック実装 | OWASP API Top10対応・Python本実装・英語README初稿 | 🔄 進行中 |
| M3（5月） | OSS公開          | GitHub public公開・Actions Marketplace登録申請    | ⬜        |
| M4（6月） | 品質向上         | テスト強化・誤検知チューニング・Issue対応         | ⬜        |
| M5（7月） | 差別化機能       | SBOM連携 or API固有ルール追加                     | ⬜        |
| M6（8月） | v1.0リリース     | v1.0タグ・dev.to記事・スター獲得施策              | ⬜        |

### 最小リリース条件（Must）

```
✅ GitHub Actions上でゼロ設定で動く
✅ OWASP API Top10の主要項目を検出できる
✅ Claude AIが英語で文脈付きコメントをPRに投稿する
✅ READMEで使い方がわかる（英語）
✅ MITライセンス
```

---

## 10. Month 2 進捗

### M2 やること

| #   | タスク | 状態 |
| --- | ------ | ---- |
| 1   | Claudeプロンプトを英語出力に統一 | ⬜ |
| 2   | vulnerable_sample.py に OWASP Top10 全10項目追加 | ⬜ |
| 3   | 各項目対応 Semgrep ルール（rules/）整備 | ⬜ |
| 4   | エラーハンドリング・ロギング強化（本番品質） | ✅ |
| 5   | README.md 英語初稿 | ⬜ |
| 6   | コミット・Issue・PR運用を英語に統一 | ⬜ |
