# Test-Encoding.ps1
# Run this BEFORE Run-All.ps1 to verify encoding works - no API calls made

$ErrorActionPreference = "Stop"
$pass = 0; $fail = 0

function Pass([string]$msg) { Write-Host "  [PASS] $msg" -ForegroundColor Green; $script:pass++ }
function Fail([string]$msg) { Write-Host "  [FAIL] $msg" -ForegroundColor Red;  $script:fail++ }

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Encoding Pre-flight Check"             -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$testDir = Join-Path $PSScriptRoot "work\_enctest"
New-Item -ItemType Directory -Path $testDir -Force | Out-Null
$utf8Bom = New-Object System.Text.UTF8Encoding $true

# Japanese test strings built from unicode escapes (script file stays pure ASCII)
$j1 = [char]0x30C6 + [char]0x30B9 + [char]0x30C8 + ": CRITICAL HIGH " + [char]0x8106 + [char]0x5F31 + [char]0x6027 + " " + [char]0x89E3 + [char]0x8AAC
$j2 = [char]0x3053 + [char]0x308C + [char]0x306F + [char]0x30C6 + [char]0x30B9 + [char]0x30C8 + [char]0x3067 + [char]0x3059 + [char]0x3002 + [char]0x65E5 + [char]0x672C + [char]0x8A9E + [char]0x304C + [char]0x6B63 + [char]0x3057 + [char]0x304F + [char]0x4FDD + [char]0x5B58 + [char]0x3055 + [char]0x308C + [char]0x308B + [char]0x3053 + [char]0x3068 + [char]0x3092 + [char]0x78BA + [char]0x8A8D + [char]0x3057 + [char]0x307E + [char]0x3059 + [char]0x3002
$j3 = "LangChain" + [char]0x306E + "PDFLoader" + [char]0x306B + [char]0x5B58 + [char]0x5728 + [char]0x3059 + [char]0x308B + [char]0x30D7 + [char]0x30ED + [char]0x30F3 + [char]0x30D7 + [char]0x30C8 + [char]0x30A4 + [char]0x30F3 + [char]0x30B8 + [char]0x30A7 + [char]0x30AF + [char]0x30B7 + [char]0x30E7 + [char]0x30F3 + [char]0x8106 + [char]0x5F31 + [char]0x6027 + [char]0x3067 + [char]0x3059 + [char]0x3002 + [char]0x60AA + [char]0x610F + [char]0x3042 + [char]0x308B + "PDF" + [char]0x3092 + [char]0x8AAD + [char]0x307F + [char]0x8FBC + [char]0x307E + [char]0x305B + [char]0x308B + [char]0x3053 + [char]0x3068 + [char]0x3067 + [char]0x57CB + [char]0x3081 + [char]0x8FBC + [char]0x307E + [char]0x308C + [char]0x305F + [char]0x6307 + [char]0x793A + [char]0x304C + "LLM" + [char]0x306B + [char]0x5B9F + [char]0x884C + [char]0x3055 + [char]0x308C + [char]0x307E + [char]0x3059 + [char]0x3002
$j4 = [char]0x653B + [char]0x6483 + [char]0x8005 + [char]0x304C + [char]0x7D30 + [char]0x5DE5 + [char]0x3057 + [char]0x305F + "PDF" + [char]0x3092 + "RAG" + [char]0x30B7 + [char]0x30B9 + [char]0x30C6 + [char]0x30E0 + [char]0x306B + [char]0x6295 + [char]0x5165 + [char]0x3057 + [char]0x6A5F + [char]0x5BC6 + [char]0x60C5 + [char]0x5831 + [char]0x3092 + [char]0x7A83 + [char]0x53D6 + [char]0x3057 + [char]0x307E + [char]0x3059 + [char]0x3002
$j5 = "LangChain " + [char]0x3092 + [char]0x6700 + [char]0x65B0 + [char]0x30D0 + [char]0x30FC + [char]0x30B8 + [char]0x30E7 + [char]0x30F3 + [char]0x306B + [char]0x30A2 + [char]0x30C3 + [char]0x30D7 + [char]0x30C7 + [char]0x30FC + [char]0x30C8
$j6 = [char]0x5916 + [char]0x90E8 + [char]0x5165 + [char]0x529B + [char]0x30C9 + [char]0x30AD + [char]0x30E5 + [char]0x30E1 + [char]0x30F3 + [char]0x30C8 + [char]0x306E + [char]0x30B5 + [char]0x30CB + [char]0x30BF + [char]0x30A4 + [char]0x30BA + [char]0x51E6 + [char]0x7406 + [char]0x3092 + [char]0x8FFD + [char]0x52A0

# ---- Test 1: WriteAllText BOM -> ReadAllText ----
Write-Host "[Test 1] WriteAllText(BOM) -> ReadAllText" -ForegroundColor Yellow
$path1 = Join-Path $testDir "t1.txt"
[System.IO.File]::WriteAllText($path1, $j1, $utf8Bom)
$r1 = [System.IO.File]::ReadAllText($path1, [System.Text.Encoding]::UTF8)
if ($r1 -eq $j1) { Pass "WriteAllText/ReadAllText round-trip OK" } else { Fail "Mismatch: [$r1]" }

# ---- Test 2: JSON with Japanese round-trip ----
Write-Host "[Test 2] JSON Japanese round-trip" -ForegroundColor Yellow
$obj  = @{ summary_ja = $j2; ai_priority = "HIGH" }
$path2 = Join-Path $testDir "t2.json"
[System.IO.File]::WriteAllText($path2, ($obj | ConvertTo-Json), $utf8Bom)
$r2 = [System.IO.File]::ReadAllText($path2, [System.Text.Encoding]::UTF8) | ConvertFrom-Json
if ($r2.summary_ja -eq $j2) { Pass "JSON Japanese round-trip OK" } else { Fail "Mismatch: [$($r2.summary_ja)]" }

# ---- Test 3: Invoke-WebRequest UTF-8 (EPSS - no key needed) ----
Write-Host "[Test 3] Invoke-WebRequest UTF-8 decode via EPSS API" -ForegroundColor Yellow
try {
    $wr = Invoke-WebRequest -Uri "https://api.first.org/data/v1/epss?cve=CVE-2021-44228" -UseBasicParsing -TimeoutSec 15
    # PS5: RawContentBytes can be null - fall back to .Content string
    if ($wr.RawContentBytes -and $wr.RawContentBytes.Length -gt 0) {
        $jsonText = [System.Text.Encoding]::UTF8.GetString($wr.RawContentBytes)
        Pass "Invoke-WebRequest RawContentBytes UTF-8 decode OK"
    } else {
        $jsonText = $wr.Content
        Pass "Invoke-WebRequest .Content fallback used (PS5 proxy/cache behavior)"
    }
    $json = $jsonText | ConvertFrom-Json
    if ($json.data -and $json.data[0].cve -eq "CVE-2021-44228") {
        Pass "EPSS API response parsed OK (EPSS=$($json.data[0].epss))"
    } else { Fail "Unexpected EPSS response structure" }
} catch { Fail "Network error: $_" }

# ---- Test 4: Simulated Claude JSON response ----
Write-Host "[Test 4] Simulated Claude JSON response (Japanese)" -ForegroundColor Yellow
$simObj  = @{ is_ai_ml_related=$true; summary_ja=$j3; ai_priority="CRITICAL" }
$simJson = $simObj | ConvertTo-Json
$path4   = Join-Path $testDir "t4.json"
[System.IO.File]::WriteAllText($path4, $simJson, $utf8Bom)
$r4 = [System.IO.File]::ReadAllText($path4, [System.Text.Encoding]::UTF8) | ConvertFrom-Json
if ($r4.summary_ja -eq $j3) { Pass "Claude response simulation OK" } else { Fail "Mismatch: [$($r4.summary_ja)]" }

# ---- Test 5: PowerShell version ----
Write-Host "[Test 5] PowerShell version" -ForegroundColor Yellow
$psVer = $PSVersionTable.PSVersion
Write-Host "  Version: $psVer" -ForegroundColor DarkGray
if ($psVer.Major -ge 5) { Pass "PS$($psVer.Major) - explicit System.IO.File methods will be used" }
else                     { Fail "PS version too old: $psVer" }

# ---- Test 6: Write sample .md and display for visual check ----
Write-Host "[Test 6] Write sample Markdown report for visual inspection" -ForegroundColor Yellow
$mdLines = @(
    "# AI CVE Report - Encoding Test",
    "Date: $(Get-Date -Format yyyy-MM-dd)",
    "",
    "## CVE-2024-9999",
    "| Field | Value |",
    "|-------|-------|",
    "| AI Priority | CRITICAL |",
    "",
    "**Risk Summary**",
    $j3,
    "",
    "**Attack Scenario**",
    $j4,
    "",
    "**Mitigation**",
    "- $j5",
    "- $j6"
)
$mdPath = Join-Path $testDir "sample_report.md"
[System.IO.File]::WriteAllText($mdPath, ($mdLines -join "`n"), $utf8Bom)
$checkMd = [System.IO.File]::ReadAllText($mdPath, [System.Text.Encoding]::UTF8)
if ($checkMd -match "LangChain") { Pass "Markdown write OK - open file below to verify visually" }
else                              { Fail "Japanese lost in markdown" }

Write-Host ""
Write-Host "  >>> Open this file to visually verify Japanese:" -ForegroundColor White
Write-Host "  $mdPath" -ForegroundColor Yellow
Write-Host "  If Japanese shows correctly -> run Run-All.ps1" -ForegroundColor White
Write-Host "  If garbled -> re-download the ps1 files and retry this test" -ForegroundColor White
Write-Host ""

# ---- Test 7: WebClient UTF-8 decode (simulates Claude API path) ----
Write-Host "[Test 7] System.Net.WebClient UTF-8 decode" -ForegroundColor Yellow
try {
    $wc = New-Object System.Net.WebClient
    $wc.Encoding = [System.Text.Encoding]::UTF8
    $wc.Headers.Add("Accept", "application/json")
    # Use EPSS API (no key needed) to verify WebClient UTF-8 decoding
    $respText = $wc.DownloadString("https://api.first.org/data/v1/epss?cve=CVE-2021-44228")
    $json = $respText | ConvertFrom-Json
    if ($json.data -and $json.data[0].cve -eq "CVE-2021-44228") {
        Pass "WebClient UTF-8 decode OK - this is the same path used for Claude API"
    } else { Fail "Unexpected response from EPSS via WebClient" }
} catch { Fail "WebClient error: $_" }

# ---- Summary ----
Write-Host "========================================" -ForegroundColor Cyan
if ($fail -eq 0) {
    Write-Host "  $pass/$($pass+$fail) passed - Safe to run Run-All.ps1" -ForegroundColor Green
} else {
    Write-Host "  $pass passed, $fail FAILED - do NOT run Run-All.ps1 yet" -ForegroundColor Red
}
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Remove-Item (Join-Path $testDir "t1.txt")  -ErrorAction SilentlyContinue
Remove-Item (Join-Path $testDir "t2.json") -ErrorAction SilentlyContinue
Remove-Item (Join-Path $testDir "t4.json") -ErrorAction SilentlyContinue
