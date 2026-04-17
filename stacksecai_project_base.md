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
│       └── vulnerable_sample.py   # OWASP API Top10 サンプル脆弱コード
├── rules/
│   └── custom/              # Semgrepカスタムルール（OWASP API Top10対応）
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
- `analyze_with_claude` 戻り値: `(verdict, summary, findings, block_reasons)` 4タプル
- SYSTEM_PROMPT は `()` 連結文字列（triple-quote 禁止・BOM対策）

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
$env:PYTHONUTF8=1; pytest --cov -v

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

### Windows 開発注意

- `$env:PYTHONUTF8=1` を設定してから pytest を実行すること
- ファイル編集は PowerShell インライン `python -c` 不可 → `.py` ファイル経由で実行

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

| #   | タスク                                           | 状態             |
| --- | ------------------------------------------------ | ---------------- |
| 1   | Claudeプロンプトを英語出力に統一                 | ✅ 完了（Day15） |
| 2   | vulnerable_sample.py に OWASP Top10 全10項目追加 | ✅ 完了（Day16） |
| 3   | 各項目対応 Semgrep ルール（rules/）整備          | ✅ 完了（Day16） |
| 4   | エラーハンドリング・ロギング強化（本番品質）     | ✅ W2完了        |
| 5   | README.md 英語初稿                               | ⬜ Day17         |
| 6   | コミット・Issue・PR運用を英語に統一              | ⬜ Day17         |

### M2 Week 別サマリー

**Week1（Day1-7）**: playground → stacksecai-dev 移植・Policy Gate実装

**Week2（Day8-14）**: 品質・信頼性強化

- pytest-cov・ruff・mypy 導入
- Claude APIタイムアウト（httpx.Timeout）設定
- tenacity リトライ強化
- SensitiveFilter（APIキーマスキング）
- PRコメント重複抑制（update-or-create）
- カバレッジ 80% → **100%**・テスト数 33 → **59**

**Week3（Day15-16）**: OSS公開準備

- SYSTEM_PROMPT 英語出力強制・owasp_category / block_reasons 追加
- analyze_with_claude 4タプル化・30テスト・カバレッジ 100%
- vulnerable_sample.py OWASP API Top10 全10項目追加
- rules/custom/ 対応ルール10本整備・Semgrep 11 findings 確認

### M2 技術メモ（Day15〜）

- `analyze_with_claude` 戻り値: `(verdict, summary, findings, block_reasons)` 4タプル
- SYSTEM_PROMPT: `owasp_category` / `block_reasons` 追加・英語出力強制
- `test_claude_analyzer.py`: 30テスト・`claude_analyzer.py` カバレッジ 100%
- Windows 開発注意: `$env:PYTHONUTF8=1` を設定すること
- SYSTEM_PROMPT は `()` 連結文字列（triple-quote 禁止・BOM対策）
- Semgrep: `vulnerable_sample.py` で 11 findings / 全10項目検出確認済み
- `pattern-regex` を使うと複数行 `execute()` やネストデコレータも検出可能

---

## 11. Week 3 プラン（Day15-21）

テーマ：**OSS公開準備**

| Day      | テーマ                                           | 主なタスク                                              |
| -------- | ------------------------------------------------ | ------------------------------------------------------- |
| Day15 ✅ | Claudeプロンプト英語化 + 文字化けクリーンアップ  | SYSTEM_PROMPT刷新・新スキーマ・30テスト・cov100%        |
| Day16 ✅ | OWASP API Top10 サンプルコード + ルール整備       | vulnerable_sample.py + rules/custom/ 10本・11 findings  |
| Day17    | README.md 英語初稿                               | What/How/QuickStart/Config/Coverage table               |
| Day18-19 | action.yml 整備・E2E確認                         | Marketplace 公開要件確認・E2E テスト                    |
| Day20    | バッファ + Week4スコープ確定                     | CHANGELOG・MIT確認・英語運用切り替え                    |

### Week3 終了時ゴール

```
✅ 全コードが英語コメント・英語出力
✅ OWASP API Top10 全10項目をサンプル+ルールで検出できる
✅ README.md 英語初稿完成
✅ action.yml が Marketplace 公開要件を満たしている
→ Week4 で public 公開ボタンを押せる状態
```

---

## 12. OWASP API Security Top10（2023）対応状況

| #     | リスク                                          | Semgrep ルール            | 状態 |
| ----- | ----------------------------------------------- | ------------------------- | ---- |
| API1  | Broken Object Level Authorization               | api1_bola.yml             | ✅   |
| API2  | Broken Authentication                           | api2_broken_auth.yml      | ✅   |
| API3  | Broken Object Property Level Authorization      | api3_mass_assignment.yml  | ✅   |
| API4  | Unrestricted Resource Consumption               | api4_resource_limit.yml   | ✅   |
| API5  | Broken Function Level Authorization             | api5_func_authz.yml       | ✅   |
| API6  | Unrestricted Access to Sensitive Business Flows | api6_business_flow.yml    | ✅   |
| API7  | Server Side Request Forgery（SSRF）             | ssrf.yml                  | ✅   |
| API8  | Security Misconfiguration                       | api8_debug_mode.yml       | ✅   |
|       |                                                 | api8_hardcoded_secret.yml | ✅   |
| API9  | Improper Inventory Management                   | api9_inventory.yml        | ✅   |
| API10 | Unsafe Consumption of APIs                      | api10_unsafe_api.yml      | ✅   |
| -     | Hardcoded credentials                           | hardcoded_password.yml    | ✅   |
| -     | Eval / Code injection                           | eval_injection.yml        | ✅   |
| -     | Command injection                               | subprocess_injection.yml  | ✅   |

---

## 13. 新スレ開始時のテンプレート

新しいスレを開始するときは、このファイルに加えて以下を貼る：

```
【stacksecai-dev 開発引き継ぎ】

■ プロジェクトベースファイル
（このファイルの内容）

■ 前回スレの終了状態
    完了したDay: DayXX
    次のDay: DayXX
    現在のカバレッジ: XX%
    テスト数: XX
    CI状態: ✅ / ❌

■ 今日のゴール
DayXX開始
```

---

## 14. 毎日の運用フロー

### 開発中
- 普通に DayXX を進める
- Notion 用まとめ・ベースファイル更新は1日の終わりにまとめてやる

### 1日の終わりにやること

スレッドの最後にひと言言うだけでOK：

```
今日のNotion用まとめとYAML更新パッチを出して
```

このチャットが返すもの：
1. Notion 用の今日のまとめ
2. `stacksecai_project_base.md` の before/after パッチ

### パッチを受け取ったあと

1. `stacksecai_project_base.md` の該当セクションをコピペで更新
2. `git add stacksecai_project_base.md`
3. `git commit -m "docs: update project base DayXX"`
4. `git push`

### status の値

| 値     | 意味         | アイコン |
| ------ | ------------ | -------- |
| todo   | 未着手       | ⬜       |
| doing  | 進行中       | 🔄       |
| done   | 完了         | ✅       |
