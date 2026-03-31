# ============================================================
# Run-All.ps1 への組み込み方（差分パッチ）
# ============================================================
# 現在の Run-All.ps1 末尾に以下のブロックを追加するだけでOK
# ============================================================

# ------ ここから Run-All.ps1 末尾に追加 ------

# ============================================================
# Step 5: GitHub Issues 自動生成（オプション）
# ============================================================
# 環境変数 GITHUB_TOKEN が設定されている場合のみ実行
# 設定されていない場合はスキップ（API節約）

if ($env:GITHUB_TOKEN) {

    # ★ 自分のリポジトリ情報に書き換えること ★
    $GITHUB_OWNER = "your-github-username"   # 例: "yamada-taro"
    $GITHUB_REPO  = "secai-hub"              # SecAI Hub のDBリポジトリ名

    Write-Host ""
    Write-Host "=============================="
    Write-Host " Step 5: GitHub Issues 生成"
    Write-Host "=============================="

    powershell -ExecutionPolicy Bypass -File .\Step4_Create-GitHubIssues.ps1 `
        -InputPath   .\work\cve_analyzed.json `
        -GitHubOwner $GITHUB_OWNER `
        -GitHubRepo  $GITHUB_REPO `
        -MinScore    50 `
        -MaxIssues   20

} else {
    Write-Host ""
    Write-Host "[Step 5 スキップ] GITHUB_TOKEN 未設定" -ForegroundColor DarkGray
    Write-Host "  Issue生成したい場合: `$env:GITHUB_TOKEN = 'ghp_...'" -ForegroundColor DarkGray
}

# ------ ここまで ------


# ============================================================
# 初回セットアップ手順（一度だけ実行）
# ============================================================
<#
1. GitHub Personal Access Token を取得
   https://github.com/settings/tokens
   スコープ: repo (Issues の read/write に必要)

2. ラベル初期設定（リポジトリに必要なラベルを一括作成）
   $env:GITHUB_TOKEN = "ghp_..."
   .\Setup-GitHubLabels.ps1 -GitHubOwner "yourname" -GitHubRepo "secai-hub"

3. 動作確認（DryRunで内容を確認）
   .\Step4_Create-GitHubIssues.ps1 `
       -GitHubOwner "yourname" `
       -GitHubRepo  "secai-hub" `
       -DryRun

4. 本実行
   .\Step4_Create-GitHubIssues.ps1 `
       -GitHubOwner "yourname" `
       -GitHubRepo  "secai-hub"

5. Run-All.ps1 に組み込んで週次自動化（WeeklyCveReport.xml）
   → GITHUB_TOKEN を環境変数に設定するか、Run-All.ps1 の先頭で設定
#>


# ============================================================
# 生成されるIssueのサンプルイメージ
# ============================================================
<#
タイトル例:
  [HOT] CVE-2024-12345 [LLM] - LangChain プロンプトインジェクション

ラベル例:
  cve  hot  llm  cisa-kev  auto-generated

本文構成:
  ## 📋 基本情報
  | AttentionScore | 87 / 100 (HOT)            |
  | CVSS           | 9.1 / 10.0                |
  | EPSS           | 3.2% (上位 15.0%)         |
  | CISA KEV       | ✅ 実際の悪用確認済み      |
  | 対象製品        | langchain 0.x.x           |

  ## 🗺️ OWASP マッピング
  | OWASP LLM Top10 2025    | LLM01, LLM04 |
  | OWASP Agentic AI Top10  | A02          |
  | OWASP ML Security Top10 | —            |

  ## 🔍 日本語リスク解説
  LangChainの入力検証の不備により...（3-4文）

  ## ⚔️ 攻撃シナリオ
  攻撃者はユーザー入力に悪意あるプロンプトを...

  ## 🛡️ 推奨緩和策
  - LangChain を最新版にアップデートする
  - ユーザー入力のサニタイズを実装する
  - ...

  ## 🔗 参考リンク
  - NVD: https://nvd.nist.gov/vuln/detail/CVE-2024-12345
  - AVID: https://avidml.org/database/AVID-2024-xxxxx
#>
