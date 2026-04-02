param(
    [string]$InputPath  = "",
    [string]$OutputPath = ""
)

$ErrorActionPreference = "Stop"

if (-not $InputPath)  { $InputPath  = Join-Path $PSScriptRoot "work\cve_raw.json" }
if (-not $OutputPath) { $OutputPath = Join-Path $PSScriptRoot "work\cve_analyzed.json" }

$ApiKey = $env:ANTHROPIC_API_KEY
if (-not $ApiKey) { Write-Error "Set ANTHROPIC_API_KEY first." }

# ---------------------------------------------------------------
# System prompt: maps to all 3 OWASP frameworks
# ---------------------------------------------------------------
$SystemPrompt = @"
You are an AI/ML security expert specializing in OWASP frameworks.
Analyze the CVE and reply ONLY with a valid JSON object. No markdown, no preamble, no explanation outside the JSON.

JSON schema:
{
  "is_ai_ml_related": true or false,
  "owasp_llm_top10": ["LLM01: Prompt Injection"],
  "owasp_agentic_top10": ["A01: Memory Poisoning"],
  "owasp_ml_top10": ["ML01: Input Manipulation Attack"],
  "primary_framework": "LLM or AGENT or ML or MULTIPLE or NONE",
  "summary_ja": "3-4 sentence risk summary in Japanese",
  "attack_scenario": "1-2 sentence concrete attack scenario in Japanese",
  "mitigation": "Up to 3 mitigation steps in Japanese, one per line",
  "ai_priority": "CRITICAL or HIGH or MEDIUM or LOW",
  "confidence": "HIGH or MEDIUM or LOW"
}

Rules:
- Set is_ai_ml_related=false if the CVE is unrelated to AI/ML/Agent systems
- For each framework, include only matching categories (empty array [] if none apply)
- primary_framework: dominant framework this CVE maps to; MULTIPLE if 2+ frameworks apply

--- OWASP LLM Top10 2025 ---
LLM01: Prompt Injection
LLM02: Sensitive Information Disclosure
LLM03: Supply Chain Vulnerabilities
LLM04: Data and Model Poisoning
LLM05: Improper Output Handling
LLM06: Excessive Agency
LLM07: System Prompt Leakage
LLM08: Vector and Embedding Weaknesses
LLM09: Misinformation
LLM10: Unbounded Consumption

--- OWASP Agentic AI Top10 2025 ---
A01: Memory Poisoning
A02: Tool/Plugin Misuse
A03: Privilege Escalation
A04: Uncontrolled Execution
A05: Resource Exhaustion
A06: Insecure Communication Channels
A07: Inadequate Human Oversight
A08: Data Exfiltration via Agent
A09: Identity Spoofing
A10: Supply Chain Compromise

--- OWASP Top10 for Machine Learning Security 2023 ---
ML01: Input Manipulation Attack (Adversarial)
ML02: Data Poisoning Attack
ML03: Model Inversion Attack
ML04: Membership Inference Attack
ML05: Model Theft
ML06: AI Supply Chain Attacks
ML07: Transfer Learning Attack
ML08: Model Skewing
ML09: Output Integrity Attack
ML10: Model Poisoning
"@

function Invoke-ClaudeApi($Cve) {
    $msg  = "CVE: $($Cve.Id) | CVSS: $($Cve.Score) ($($Cve.Severity)) | Published: $($Cve.Published) | $($Cve.Description)"
    $body = @{
        model      = "claude-sonnet-4-20250514"
        max_tokens = 1000
        system     = $SystemPrompt
        messages   = @(@{ role = "user"; content = $msg })
    } | ConvertTo-Json -Depth 5
    $headers = @{
        "x-api-key"         = $ApiKey
        "anthropic-version" = "2023-06-01"
        "content-type"      = "application/json"
    }
    try {
        # Use WebClient with explicit UTF-8 - avoids PS5 Shift-JIS default decoding
        $wc = New-Object System.Net.WebClient
        $wc.Encoding = [System.Text.Encoding]::UTF8
        foreach ($k in $headers.Keys) { $wc.Headers.Add($k, $headers[$k]) }
        $respText = $wc.UploadString("https://api.anthropic.com/v1/messages", "POST", $body)
        $json = $respText | ConvertFrom-Json
        $raw  = $json.content[0].text -replace '(?s)```json', '' -replace '```', ''
        return $raw.Trim() | ConvertFrom-Json
    } catch {
        Write-Warning "Claude error ($($Cve.Id)): $_"
        return $null
    }
}

Write-Host "===== Step 2: Claude API Analysis (3 OWASP frameworks) ====="
if (-not (Test-Path $InputPath)) { Write-Error "Not found: $InputPath - run Step1 first." }

$cves     = Get-Content $InputPath -Raw | ConvertFrom-Json
$enriched = [System.Collections.Generic.List[object]]::new()
$i        = 0

Write-Host "  -> Loaded $($cves.Count) CVEs"
Write-Host "  -> Mapping to: OWASP LLM Top10 / Agentic Top10 / ML Security Top10"
Write-Host ""

foreach ($cve in $cves) {
    $i++
    Write-Progress -Activity "Claude analysis" -Status "$i/$($cves.Count): $($cve.Id)" -PercentComplete ([int]($i/$cves.Count*100))
    Write-Host "  [$i/$($cves.Count)] $($cve.Id) CVSS:$($cve.Score) ..." -NoNewline

    $r = Invoke-ClaudeApi $cve
    if ($null -eq $r)             { Write-Host " [ERROR]"     -ForegroundColor Red;      continue }
    if (-not $r.is_ai_ml_related) { Write-Host " [not AI/ML]" -ForegroundColor DarkGray; continue }

    $col = switch ($r.ai_priority) { "CRITICAL"{"Red"} "HIGH"{"Yellow"} "MEDIUM"{"Cyan"} default{"White"} }
    $fw  = if ($r.primary_framework) { " ($($r.primary_framework))" } else { "" }
    Write-Host " [$($r.ai_priority)]$fw" -ForegroundColor $col

    $enriched.Add([PSCustomObject]@{
        CveId              = $cve.Id
        Published          = $cve.Published
        CvssScore          = $cve.Score
        Severity           = $cve.Severity
        NvdUrl             = $cve.NvdUrl
        EpssScore          = $cve.EpssScore
        EpssPercentile     = $cve.EpssPercentile
        InCisaKev          = $cve.InCisaKev
        AttentionScore     = $cve.AttentionScore
        AttentionLabel     = $cve.AttentionLabel
        AvidMatched        = $cve.AvidMatched
        AvidIds            = $cve.AvidIds
        AvidRecords        = $cve.AvidRecords
        PrimaryFramework   = $r.primary_framework
        OwaspLlm           = $r.owasp_llm_top10
        OwaspAgent         = $r.owasp_agentic_top10
        OwaspMl            = $r.owasp_ml_top10
        SummaryJa          = $r.summary_ja
        AttackScenario     = $r.attack_scenario
        Mitigation         = $r.mitigation
        AiPriority         = $r.ai_priority
        Confidence         = $r.confidence
    })
    Start-Sleep -Milliseconds 300
}

Write-Progress -Activity "Claude analysis" -Completed

# Sort: KEV first, then AttentionScore desc, then AiPriority
$order  = @{ CRITICAL=0; HIGH=1; MEDIUM=2; LOW=3 }
$sorted = $enriched | Sort-Object @{E={if($_.InCisaKev){0}else{1}}}, @{E={if($null -ne $_.AttentionScore){$_.AttentionScore}else{0}}; Desc=$true}, @{E={$order[$_.AiPriority]}}

$outDir = Split-Path $OutputPath -Parent
if ($outDir -and -not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}
$utf8Bom = New-Object System.Text.UTF8Encoding $true
[System.IO.File]::WriteAllText($OutputPath, ($sorted | ConvertTo-Json -Depth 5), $utf8Bom)

Write-Host ""
Write-Host "  -> $($sorted.Count) AI/ML CVEs saved to $OutputPath" -ForegroundColor Green

# Framework breakdown summary
$byFw = $sorted | Group-Object PrimaryFramework
Write-Host ""
Write-Host "  Framework breakdown:"
foreach ($fw in @("LLM","AGENT","ML","MULTIPLE")) {
    $c = ($byFw | Where-Object Name -eq $fw).Count
    if ($c -gt 0) { Write-Host "    $fw : $c" -ForegroundColor Cyan }
}
Write-Host ""
