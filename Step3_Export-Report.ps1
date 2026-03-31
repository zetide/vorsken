param(
    [string]$InputPath = "",
    [string]$OutputDir = ""
)

$ErrorActionPreference = "Stop"

if (-not $InputPath) { $InputPath = Join-Path $PSScriptRoot "work\cve_analyzed.json" }
if (-not $OutputDir) { $OutputDir = Join-Path $PSScriptRoot "output" }

# UTF-8 with BOM: Windows apps (Notepad, Excel, VS Code) need BOM to detect UTF-8
$utf8Bom = New-Object System.Text.UTF8Encoding $true

function Safe-Join($arr) {
    if ($null -eq $arr) { return "-" }
    if ($arr -is [string]) { return $arr }
    return ($arr -join ", ")
}

function Build-Markdown($Items, $Today) {
    $L = [System.Collections.Generic.List[string]]::new()
    $L.Add("# AI/LLM/ML/Agent CVE Security Report")
    $L.Add("Date: $Today | Total: $($Items.Count)")
    $L.Add("Sort order: CISA KEV first, then Attention Score (EPSS + KEV + CVSS), then AI Priority")
    $L.Add(""); $L.Add("---"); $L.Add("")

    # ---- Summary table ----
    $L.Add("## Summary")
    $L.Add("")
    $L.Add("| CVE ID | CVSS | Severity | Framework | AI Priority | Attention | EPSS | KEV |")
    $L.Add("|--------|------|----------|-----------|-------------|-----------|------|-----|")
    foreach ($x in $Items) {
        $fw  = if ($x.PrimaryFramework) { $x.PrimaryFramework } else { "-" }
        $kev = if ($x.InCisaKev) { "YES" } else { "-" }
        $ep  = if ($null -ne $x.EpssScore) { $x.EpssScore } else { "-" }
        $atl = if ($x.AttentionLabel) { $x.AttentionLabel } else { "-" }
        $ats = if ($null -ne $x.AttentionScore) { "$($x.AttentionScore)/100" } else { "-" }
        $L.Add("| [$($x.CveId)]($($x.NvdUrl)) | $($x.CvssScore) | $($x.Severity) | $fw | $($x.AiPriority) | $atl $ats | $ep | $kev |")
    }

    # ---- Per-framework index ----
    $L.Add(""); $L.Add("---"); $L.Add("")
    $L.Add("## OWASP Category Index")
    $L.Add("")

    $L.Add("### LLM Top10 Hits")
    $L.Add("")
    $L.Add("| CVE ID | OWASP LLM Categories |")
    $L.Add("|--------|----------------------|")
    foreach ($x in ($Items | Where-Object { $x2 = $_; $x2.OwaspLlm -and $x2.OwaspLlm.Count -gt 0 })) {
        $cats = Safe-Join $x.OwaspLlm
        if ($cats -ne "-") { $L.Add("| [$($x.CveId)]($($x.NvdUrl)) | $cats |") }
    }

    $L.Add("")
    $L.Add("### Agentic AI Top10 Hits")
    $L.Add("")
    $L.Add("| CVE ID | OWASP Agentic Categories |")
    $L.Add("|--------|--------------------------|")
    foreach ($x in ($Items | Where-Object { $x2 = $_; $x2.OwaspAgent -and $x2.OwaspAgent.Count -gt 0 })) {
        $cats = Safe-Join $x.OwaspAgent
        if ($cats -ne "-") { $L.Add("| [$($x.CveId)]($($x.NvdUrl)) | $cats |") }
    }

    $L.Add("")
    $L.Add("### ML Security Top10 Hits")
    $L.Add("")
    $L.Add("| CVE ID | OWASP ML Categories |")
    $L.Add("|--------|---------------------|")
    foreach ($x in ($Items | Where-Object { $x2 = $_; $x2.OwaspMl -and $x2.OwaspMl.Count -gt 0 })) {
        $cats = Safe-Join $x.OwaspMl
        if ($cats -ne "-") { $L.Add("| [$($x.CveId)]($($x.NvdUrl)) | $cats |") }
    }

    $L.Add("")
    $L.Add("### AVID Database Hits")
    $L.Add("")
    $L.Add("| CVE ID | AVID ID | Risk Domain | SEP Category |")
    $L.Add("|--------|---------|-------------|--------------|")
    foreach ($x in ($Items | Where-Object { $_.AvidMatched })) {
        foreach ($ar in $x.AvidRecords) {
            $L.Add("| [$($x.CveId)]($($x.NvdUrl)) | [$($ar.AvidId)]($($ar.AvidUrl)) | $($ar.RiskDomain) | $($ar.SepView) |")
        }
    }

    # ---- Details ----
    $L.Add(""); $L.Add("---"); $L.Add("")
    $L.Add("## Details")
    $L.Add("")

    foreach ($x in $Items) {
        $fw = if ($x.PrimaryFramework) { $x.PrimaryFramework } else { "-" }
        $L.Add("### $($x.CveId)")
        $L.Add("")
        $L.Add("| Field | Value |")
        $L.Add("|-------|-------|")
        $L.Add("| Published | $($x.Published) |")
        $L.Add("| CVSS | $($x.CvssScore) ($($x.Severity)) |")
        $L.Add("| AI Priority | $($x.AiPriority) |")
        $L.Add("| Primary Framework | $fw |")
        $L.Add("| Confidence | $($x.Confidence) |")
        $L.Add("| NVD | $($x.NvdUrl) |")
        if ($x.AvidMatched) { $L.Add("| AVID | $($x.AvidIds -join ', ') |") } else { $L.Add("| AVID | - |") }
        $L.Add("")
        if ($x.AvidMatched -and $x.AvidRecords) {
            $L.Add("**AVID Records**"); $L.Add("")
            $L.Add("| AVID ID | Risk Domain | SEP Category | Lifecycle |")
            $L.Add("|---------|-------------|--------------|-----------|")
            foreach ($ar in $x.AvidRecords) {
                $L.Add("| [$($ar.AvidId)]($($ar.AvidUrl)) | $($ar.RiskDomain) | $($ar.SepView) | $($ar.LifecycleView) |")
            }
            $L.Add("")
        }
        $L.Add("")
        $L.Add("| Framework | OWASP Categories |")
        $L.Add("|-----------|------------------|")
        $L.Add("| LLM Top10 | $(Safe-Join $x.OwaspLlm) |")
        $L.Add("| Agentic Top10 | $(Safe-Join $x.OwaspAgent) |")
        $L.Add("| ML Top10 | $(Safe-Join $x.OwaspMl) |")
        $L.Add("")
        $L.Add("**Risk Summary**")
        $L.Add("")
        $L.Add($x.SummaryJa)
        $L.Add("")
        $L.Add("**Attack Scenario**")
        $L.Add("")
        $L.Add($x.AttackScenario)
        $L.Add("")
        $L.Add("**Mitigation**")
        $L.Add("")
        ($x.Mitigation -split "`n" | Where-Object { $_ -match '\S' }) |
            ForEach-Object { $L.Add("- $($_.TrimStart('- ').Trim())") }
        $L.Add("")
        $L.Add("---")
        $L.Add("")
    }
    return $L -join "`n"
}

function Build-Json($Items, $Today) {
    return @{
        generated_at = "${Today}T00:00:00Z"
        total        = $Items.Count
        items        = @($Items | ForEach-Object {
            @{
                cve_id           = $_.CveId
                published        = $_.Published
                cvss_score       = $_.CvssScore
                severity         = $_.Severity
                nvd_url          = $_.NvdUrl
                primary_framework = $_.PrimaryFramework
                owasp_llm        = $_.OwaspLlm
                owasp_agentic    = $_.OwaspAgent
                owasp_ml         = $_.OwaspMl
                summary_ja       = $_.SummaryJa
                attack_scenario  = $_.AttackScenario
                mitigation       = $_.Mitigation
                ai_priority      = $_.AiPriority
                confidence       = $_.Confidence
            }
        })
    }
}

Write-Host "===== Step 3: Export Report (3 OWASP frameworks) ====="
if (-not (Test-Path $InputPath)) { Write-Error "Not found: $InputPath - run Step2 first." }

$items = [System.IO.File]::ReadAllText($InputPath, [System.Text.Encoding]::UTF8) | ConvertFrom-Json
$today = Get-Date -Format "yyyy-MM-dd"
$sfx   = Get-Date -Format "yyyyMMdd"
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$mdPath = Join-Path $OutputDir "cve_report_$sfx.md"
[System.IO.File]::WriteAllText($mdPath, (Build-Markdown $items $today), $utf8Bom)
Write-Host "  OK Markdown: $mdPath" -ForegroundColor Green

$jsonPath = Join-Path $OutputDir "cve_report_$sfx.json"
[System.IO.File]::WriteAllText($jsonPath, ((Build-Json $items $today) | ConvertTo-Json -Depth 6), $utf8Bom)
Write-Host "  OK JSON    : $jsonPath" -ForegroundColor Green

Write-Host ""
Write-Host "  Attention breakdown:" -ForegroundColor White
$ag = $items | Group-Object AttentionLabel
foreach ($lbl in @("HOT","HIGH","MEDIUM","LOW")) {
    $c = ($ag | Where-Object Name -eq $lbl).Count
    $col = switch ($lbl) { "HOT"{"Red"} "HIGH"{"Yellow"} "MEDIUM"{"Cyan"} default{"Gray"} }
    if ($c -gt 0) { Write-Host "  $lbl : $c" -ForegroundColor $col }
}
$kevCount = @($items | Where-Object { $_.InCisaKev }).Count
if ($kevCount -gt 0) { Write-Host "  CISA KEV confirmed: $kevCount" -ForegroundColor Red }

Write-Host ""
$g = $items | Group-Object AiPriority
foreach ($p in @("CRITICAL","HIGH","MEDIUM","LOW")) {
    $c = ($g | Where-Object Name -eq $p).Count
    if ($c -gt 0) { Write-Host "  [$p] $c items" }
}

Write-Host ""
$byFw = $items | Group-Object PrimaryFramework
Write-Host "  Framework breakdown:"
foreach ($fw in @("LLM","AGENT","ML","MULTIPLE","NONE")) {
    $c = ($byFw | Where-Object Name -eq $fw).Count
    if ($c -gt 0) { Write-Host "    $fw : $c" -ForegroundColor Cyan }
}
Write-Host ""
Write-Host "  Done!" -ForegroundColor Green
