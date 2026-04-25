# stacksecai-dev プロジェクトベースファイル

> 新スレ開始時に必ず共有するドキュメント。このファイルを読めば現状と次のアクションがわかる。

---

## 1. プロジェクト概要

### 1行定義

> "A GitHub Actions OSS that auto-comments API vulnerability findings on PRs using Semgrep + Claude AI"

### 背景

セキュリティSaaS「StackSecAI」を個人開発中。
開発者ブランド：**vorsken**（GitHub Org・ドメイン取得済み）
親ブランド候補：**zetide**（OSS公開時に再検討予定・非公開）
3レイヤー構成（AI Code / API Runtime / Compliance）の最初のOSS。

### コンセプト

「ポリシーゲート」= Semgrep + Claude API で PR の変更を **BLOCK / FLAG / PASS** で評価する GitHub Action。
Anthropic の auto-fix の「前段でポリシーを強制する層」として差別化。
海外向け・英語ドキュメント・MIT ライセンス。

---

## 2. リポジトリ情報

| 項目               | 内容                                                 |
| ------------------ | ---------------------------------------------------- |
| リポジトリ         | https://github.com/vorsken/stacksecai-dev            |
| ローカルパス       | C:\dev\stacksecai-dev                                |
| Python（ローカル） | 3.14.3                                               |
| Python（CI）       | 3.11                                                 |
| パッケージ構成     | src/stacksecai/ 以下                                 |
| ブランチ運用       | main ブランチへ直 push（現状）                       |
| Org transfer       | ✅ 完了（Day22）stacksecai org → zetide org 移管済み |
| Marketplace        | ✅ 公開済み（Day23）vorsken-policy-gate              |
| Public リポジトリ  | https://github.com/zetide/vorsken                    |
| テストリポジトリ   | https://github.com/zetide/vorsken-test               |
| 最新バージョン     | v0.2.5                                               |

### ブランド・Org 方針

| 項目           | 内容                                                       |
| -------------- | ---------------------------------------------------------- |
| 開発者ブランド | **vorsken**（GitHub Org・ドメイン取得済み・非公開）        |
| 親ブランド候補 | **zetide**（OSS公開時に再検討・非公開）                    |
| 現アカウント   | mip-ai（変更なし）                                         |
| repo transfer  | ✅ 完了（Day22）`stacksecai` org → `vorsken` org へ移管    |
| transfer 備考  | GitHub の自動リダイレクトあり・CI/CD・Secrets 引き継ぎ済み |

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
git clone https://github.com/vorsken/stacksecai-dev.git
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
| 5   | README.md 英語初稿                               | ✅ 完了（Day17） |
| 6   | コミット・Issue・PR運用を英語に統一              | ✅ 完了（Day17） |
| 7   | action.yml Marketplace 公開要件整備              | ✅ 完了（Day18） |
| 8   | CHANGELOG.md 英語初稿作成                        | ✅ 完了（Day19） |
| 9   | LICENSE copyright vorsken に統一                 | ✅ 完了（Day19） |

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

**Week3（Day17）**: READMEおよびブランド整備

- README.md 英語版完成・上書き（`Built by vorsken` クレジット）
- `action.yml` / README の author を `rilvak` → `vorsken` に更新
- `gate.py` アンパックバグ修正（`block_reasons` 4値化）
- `tests/test_e2e.py` MOCK*CLAUDE*\* 全3定数を4値タプルに更新
- CI グリーン確認済み ✅

**Week3（Day18）**: action.yml 整備・E2E確認

- `semgrep-rules` デフォルトを `${{ github.action_path }}/rules/custom` に変更
- `outputs.verdict` → `$GITHUB_OUTPUT` 連携確認
- E2Eテスト 5/5 パス・全テスト 79 passed / カバレッジ 100% ✅

**Week3（Day19）**: OSS公開準備（ドキュメント整備）

- CHANGELOG.md 作成（Keep a Changelog 形式・英語）
- LICENSE copyright を `rilvak` → `vor

**Week4（Day23）**: GitHub Marketplace 正式公開 & E2E動作確認

- action.yml スマートクォート修正（v0.2.1）
- Semgrep ルールパス解決修正・GITHUB_ACTION_PATH フォールバック（v0.2.3）
- analyze_with_claude アンパック 3→4 修正（v0.2.4）
- semgrep_runner include パターン `src/**` → `**` 変更（v0.2.5）
- PRコメント権限（pull-requests: write）追加
- ANTHROPIC_API_KEY input名ハイフン統一
- GitHub Marketplace 正式公開（vorsken-policy-gate）✅
- E2E 動作確認：BLOCK verdict + PRコメント投稿成功 ✅
- zetide/vorsken-test テストリポジトリ作成

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

| Day      | テーマ                                          | 主なタスク                                             |
| -------- | ----------------------------------------------- | ------------------------------------------------------ |
| Day15 ✅ | Claudeプロンプト英語化 + 文字化けクリーンアップ | SYSTEM_PROMPT刷新・新スキーマ・30テスト・cov100%       |
| Day16 ✅ | OWASP API Top10 サンプルコード + ルール整備     | vulnerable_sample.py + rules/custom/ 10本・11 findings |
| Day17 ✅ | README.md 英語初稿 + ブランド整備               | README上書き・author vorsken統一・バグ修正・CI✅       |
| Day18 ✅ | action.yml 整備・E2E確認                        | Marketplace 公開要件確認・E2Eテスト                    |
| Day19 ✅ | OSS公開準備（ドキュメント整備）                 | CHANGELOG.md・LICENSE修正・Week4スコープ確定           |
| Day20    | バッファ                                        | 予備日・Week4最終確認                                  |

### Week3 終了時ゴール

```
✅ 全コードが英語コメント・英語出力
✅ OWASP API Top10 全10項目をサンプル+ルールで検出できる
✅ README.md 英語初稿完成
✅ action.yml が Marketplace 公開要件を満たしている
→ Week4 で public 公開ボタンを押せる状態 ✅ 達成済み（Day19完了時点）
```

---

## 12. Week4 プラン（Day21-28）

テーマ：**OSS public 公開**

| Day      | テーマ                       | 主なタスク                                                     |
| -------- | ---------------------------- | -------------------------------------------------------------- |
| Day21 ✅ | smoke test                   | 実PRでAction動作確認                                           |
| Day22 ✅ | repo transfer                | mip-ai → vorsken org 移管完了                                  |
| Day23 ✅ | public 化 + Marketplace 公開 | リポジトリ公開・Marketplace 正式公開・E2E動作確認（BLOCK確認） |
| Day24    | README最終調整               | Usage例・バッジ・Marketplace審査待ち対応                       |
| Day25    | 告知記事草稿                 | dev.to / Zenn 公開告知記事                                     |
| Day26-28 | バッファ                     | Issue対応・スター獲得施策                                      |

### Marketplace 登録申請チェックリスト

- [x] `action.yml` の `name` がMarketplace上で重複していないか確認
- [x] READMEに `## Usage` セクション
- [x] `v0.2.0` タグを切る ✅（最新: v0.2.5）
- [x] リポジトリ topics 設定
- [x] GitHub Marketplace 正式公開 ✅（Day23）

## 13. OWASP API Security Top10（2023）対応状況

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

## 14. 新スレ開始時のテンプレート

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

| 値    | 意味   | アイコン |
| ----- | ------ | -------- |
| todo  | 未着手 | ⬜       |
| doing | 進行中 | 🔄       |
| done  | 完了   | ✅       |
