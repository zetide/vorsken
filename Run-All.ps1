param(
    [int]$Days         = 14,
    [string]$WorkDir   = "",
    [string]$OutputDir = ""
)

$ScriptRoot = $PSScriptRoot

if (-not $WorkDir)   { $WorkDir   = Join-Path $ScriptRoot "work" }
if (-not $OutputDir) { $OutputDir = Join-Path $ScriptRoot "output" }

New-Item -ItemType Directory -Path $WorkDir   -Force | Out-Null
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$raw      = Join-Path $WorkDir "cve_raw.json"
$enriched = Join-Path $WorkDir "cve_enriched.json"
$avid     = Join-Path $WorkDir "cve_avid.json"
$analyzed = Join-Path $WorkDir "cve_analyzed.json"
$t        = Get-Date

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  AI/LLM/ML CVE Analyzer (PowerShell)"      -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[Step 1/5] Collect CVEs from NVD" -ForegroundColor Yellow
powershell -ExecutionPolicy Bypass -File "$ScriptRoot\Step1_Collect-CVEs.ps1" -Days $Days -OutputPath $raw
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "[Step 2/5] Enrich with EPSS + CISA KEV" -ForegroundColor Yellow
powershell -ExecutionPolicy Bypass -File "$ScriptRoot\Step1b_Enrich-Attention.ps1" -InputPath $raw -OutputPath $enriched
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "[Step 3/5] Enrich with AVID database" -ForegroundColor Yellow
powershell -ExecutionPolicy Bypass -File "$ScriptRoot\Step1c_Enrich-Avid.ps1" -InputPath $enriched -OutputPath $avid
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "[Step 4/5] Analyze with Claude API" -ForegroundColor Yellow
powershell -ExecutionPolicy Bypass -File "$ScriptRoot\Step2_Analyze-WithClaude.ps1" -InputPath $avid -OutputPath $analyzed
if ($LASTEXITCODE -ne 0) { exit 1 }

Write-Host "[Step 5/5] Export Report" -ForegroundColor Yellow
powershell -ExecutionPolicy Bypass -File "$ScriptRoot\Step3_Export-Report.ps1" -InputPath $analyzed -OutputDir $OutputDir
if ($LASTEXITCODE -ne 0) { exit 1 }

$e = ((Get-Date) - $t).ToString("mm\:ss")
Write-Host ""
Write-Host "  All done! ($e)" -ForegroundColor Green
Write-Host "  Reports: $OutputDir" -ForegroundColor Green
Write-Host ""

# ------ Append to end of Run-All.ps1 ------

# ============================================================
# Step 5: GitHub Issues Auto-Generator (optional)
# ============================================================
# Runs only if GITHUB_TOKEN is set. Skipped otherwise.
if ($env:GITHUB_TOKEN) {
    # Update with your repository info
    $GITHUB_OWNER = "mip-ai"
    $GITHUB_REPO  = "secaihub"

    Write-Host ""
    Write-Host "==============================" -ForegroundColor Cyan
    Write-Host " Step 5: GitHub Issues"        -ForegroundColor Cyan
    Write-Host "==============================" -ForegroundColor Cyan
    powershell -ExecutionPolicy Bypass -File .\Step4_Create-GitHubIssues.ps1 `
        -InputPath   "$PSScriptRoot\work\cve_analyzed.json" `
        -GitHubOwner $GITHUB_OWNER `
        -GitHubRepo  $GITHUB_REPO `
        -MinScore    25 `
        -MaxIssues   20
} else {
    Write-Host ""
    Write-Host "[Step 5 skipped] GITHUB_TOKEN not set" -ForegroundColor DarkGray
    Write-Host "  To create issues, set: `$env:GITHUB_TOKEN = 'ghp_...'" -ForegroundColor DarkGray
}

# ------ End of addition ------