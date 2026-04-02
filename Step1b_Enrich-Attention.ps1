param(
    [string]$InputPath  = "",
    [string]$OutputPath = ""
)

$ErrorActionPreference = "Stop"

if (-not $InputPath)  { $InputPath  = Join-Path $PSScriptRoot "work\cve_raw.json" }
if (-not $OutputPath) { $OutputPath = Join-Path $PSScriptRoot "work\cve_enriched.json" }

# ---------------------------------------------------------------
# CISA KEV: download the full catalog once and cache in memory
# ---------------------------------------------------------------
function Get-CisaKevSet {
    Write-Host "  Downloading CISA KEV catalog..." -ForegroundColor Cyan
    try {
        $kev = Invoke-RestMethod -Uri "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" -TimeoutSec 30
        $set = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($v in $kev.vulnerabilities) { $set.Add($v.cveID) | Out-Null }
        Write-Host "  -> KEV catalog loaded: $($set.Count) entries" -ForegroundColor Green
        return $set
    } catch {
        Write-Warning "CISA KEV download failed: $_"
        return [System.Collections.Generic.HashSet[string]]::new()
    }
}

# ---------------------------------------------------------------
# EPSS: batch query up to 100 CVEs per request
# ---------------------------------------------------------------
function Get-EpssScores([string[]]$CveIds) {
    $result  = @{}
    $batchSz = 50   # FIRST API: comma-separated CVE IDs, keep URL short
    $total   = $CveIds.Count
    $offset  = 0

    while ($offset -lt $total) {
        $chunk    = $CveIds[$offset..([math]::Min($offset + $batchSz - 1, $total - 1))]
        $cveParam = ($chunk -join ",")
        $uri      = "https://api.first.org/data/v1/epss?cve=$cveParam&limit=$batchSz"
        try {
            $wr       = Invoke-WebRequest -Uri $uri -UseBasicParsing -TimeoutSec 20
            $respText = if ($wr.RawContentBytes -and $wr.RawContentBytes.Length -gt 0) {
                            [System.Text.Encoding]::UTF8.GetString($wr.RawContentBytes)
                        } else { $wr.Content }
            $resp = $respText | ConvertFrom-Json
            foreach ($item in $resp.data) {
                $result[$item.cve] = @{
                    epss       = [math]::Round([double]$item.epss, 4)
                    percentile = [math]::Round([double]$item.percentile, 4)
                }
            }
        } catch {
            Write-Warning "EPSS batch failed (offset $offset): $_"
        }
        $offset += $batchSz
        Start-Sleep -Milliseconds 500
    }
    return $result
}

# ---------------------------------------------------------------
# Attention score: composite 0-100
#   EPSS percentile x 60  (exploitation probability, max weight)
#   KEV bonus        +30  (confirmed in-the-wild exploitation)
#   CVSS contribution +10 (base severity, normalized)
# ---------------------------------------------------------------
function Get-AttentionScore($Epss, $Percentile, [bool]$InKev, $CvssScore) {
    $score = 0
    if ($null -ne $Percentile) { $score += [math]::Round($Percentile * 60, 1) }
    if ($InKev)                 { $score += 30 }
    if ($CvssScore -ne "N/A" -and $null -ne $CvssScore) {
        $score += [math]::Round(([double]$CvssScore / 10.0) * 10, 1)
    }
    return [math]::Min([math]::Round($score, 1), 100)
}

function Get-AttentionLabel([double]$Score) {
    if ($Score -ge 80) { return "HOT" }
    if ($Score -ge 50) { return "HIGH" }
    if ($Score -ge 25) { return "MEDIUM" }
    return "LOW"
}

# ---------------------------------------------------------------
# Main
# ---------------------------------------------------------------
Write-Host "===== Step 1b: Enrich CVEs with EPSS + CISA KEV ====="

if (-not (Test-Path $InputPath)) { Write-Error "Not found: $InputPath - run Step1 first." }
$cves = Get-Content $InputPath -Raw | ConvertFrom-Json
Write-Host "  -> Loaded $($cves.Count) CVEs"

# 1. CISA KEV
$kevSet = Get-CisaKevSet

# 2. EPSS (batch)
Write-Host "  Fetching EPSS scores..." -ForegroundColor Cyan
$ids       = @($cves | ForEach-Object { $_.Id })
$epssMap   = Get-EpssScores $ids
Write-Host "  -> EPSS scores received: $($epssMap.Count)" -ForegroundColor Green

# 3. Merge
$enriched = foreach ($cve in $cves) {
    $epss       = $epssMap[$cve.Id]
    $epssScore  = if ($epss) { $epss.epss }       else { $null }
    $epssPerc   = if ($epss) { $epss.percentile }  else { $null }
    $inKev      = $kevSet.Contains($cve.Id)
    $attention  = Get-AttentionScore $epssScore $epssPerc $inKev $cve.Score
    $label      = Get-AttentionLabel $attention

    $cve | Select-Object * | ForEach-Object {
        $_ | Add-Member -NotePropertyName EpssScore      -NotePropertyValue $epssScore  -Force
        $_ | Add-Member -NotePropertyName EpssPercentile -NotePropertyValue $epssPerc   -Force
        $_ | Add-Member -NotePropertyName InCisaKev      -NotePropertyValue $inKev      -Force
        $_ | Add-Member -NotePropertyName AttentionScore -NotePropertyValue $attention  -Force
        $_ | Add-Member -NotePropertyName AttentionLabel -NotePropertyValue $label      -Force
        $_
    }
}

# Sort: KEV first, then AttentionScore desc
$sorted = $enriched | Sort-Object { if ($_.InCisaKev) { 0 } else { 1 } }, { -$_.AttentionScore }

$outDir = Split-Path $OutputPath -Parent
if ($outDir -and -not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$utf8Bom = New-Object System.Text.UTF8Encoding $true
[System.IO.File]::WriteAllText($OutputPath, ($sorted | ConvertTo-Json -Depth 5), $utf8Bom)

# Summary
Write-Host ""
Write-Host "  --- Attention Summary ---" -ForegroundColor White
$kevCount = @($sorted | Where-Object { $_.InCisaKev }).Count
Write-Host "  CISA KEV hits : $kevCount" -ForegroundColor Red
$g = $sorted | Group-Object AttentionLabel
foreach ($lbl in @("HOT","HIGH","MEDIUM","LOW")) {
    $c = ($g | Where-Object Name -eq $lbl).Count
    $col = switch ($lbl) { "HOT"{"Red"} "HIGH"{"Yellow"} "MEDIUM"{"Cyan"} default{"Gray"} }
    if ($c -gt 0) { Write-Host "  $lbl : $c" -ForegroundColor $col }
}
Write-Host ""
Write-Host "  -> Saved: $OutputPath" -ForegroundColor Green
Write-Host ""
