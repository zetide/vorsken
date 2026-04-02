param(
    [string]$InputPath  = "",
    [string]$OutputPath = ""
)

$ErrorActionPreference = "Stop"

if (-not $InputPath)  { $InputPath  = Join-Path $PSScriptRoot "work\cve_enriched.json" }
if (-not $OutputPath) { $OutputPath = Join-Path $PSScriptRoot "work\cve_avid.json" }

# ---------------------------------------------------------------
# Download entire avid-db repo as ZIP (single request ~1MB)
# then extract and parse JSON files in memory
# ---------------------------------------------------------------
function Get-AvidCveMap {
    $zipUrl  = "https://github.com/avidml/avid-db/archive/refs/heads/main.zip"
    $zipPath = Join-Path $env:TEMP "avid-db.zip"
    $extPath = Join-Path $env:TEMP "avid-db-extract"

    Write-Host "  Downloading AVID database (ZIP)..." -ForegroundColor Cyan

    try {
        # Download ZIP
        $wr = Invoke-WebRequest -Uri $zipUrl -UseBasicParsing -TimeoutSec 60
        [System.IO.File]::WriteAllBytes($zipPath, $wr.Content)
        Write-Host "  -> Downloaded: $([math]::Round($wr.Content.Length/1KB)) KB" -ForegroundColor DarkGray

        # Extract
        if (Test-Path $extPath) { Remove-Item $extPath -Recurse -Force }
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($zipPath, $extPath)

        # Find all report JSON files
        $reportsDir = Join-Path $extPath "avid-db-main\reports"
        $files = Get-ChildItem -Path $reportsDir -Filter "*.json" -Recurse
        Write-Host "  -> Found $($files.Count) AVID report files" -ForegroundColor DarkGray

    } catch {
        Write-Warning "AVID ZIP download failed: $_"
        return @{}
    }

    # Build CVE -> AVID record map
    $map = @{}
    foreach ($file in $files) {
        try {
            $json = [System.IO.File]::ReadAllText($file.FullName, [System.Text.Encoding]::UTF8) | ConvertFrom-Json
        } catch { continue }

        if (-not $json.id) { continue }

        # Extract CVE IDs from references and description
        $cveIds = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($ref in $json.references) {
            if ($ref.url   -match '(CVE-\d{4}-\d+)') { $cveIds.Add($Matches[1]) | Out-Null }
            if ($ref.label -match '(CVE-\d{4}-\d+)') { $cveIds.Add($Matches[1]) | Out-Null }
        }
        $descVal = if ($json.description -and $json.description.value) { $json.description.value } else { "" }
        if ($descVal -match '(CVE-\d{4}-\d+)') { $cveIds.Add($Matches[1]) | Out-Null }

        if ($cveIds.Count -eq 0) { continue }

        $avid = if ($json.impact -and $json.impact.avid) { $json.impact.avid } else { $null }
        $record = [PSCustomObject]@{
            AvidId        = $json.id
            AvidUrl       = "https://avidml.org/database/$($json.id.ToLower())/"
            RiskDomain    = if ($avid -and $avid.risk_domain)    { $avid.risk_domain -join ", " }    else { "-" }
            SepView       = if ($avid -and $avid.sep_view)       { $avid.sep_view -join "; " }       else { "-" }
            LifecycleView = if ($avid -and $avid.lifecycle_view) { $avid.lifecycle_view -join "; " } else { "-" }
        }

        foreach ($cve in $cveIds) {
            if (-not $map.ContainsKey($cve)) { $map[$cve] = [System.Collections.Generic.List[object]]::new() }
            $map[$cve].Add($record)
        }
    }

    # Cleanup temp files
    Remove-Item $zipPath  -ErrorAction SilentlyContinue
    Remove-Item $extPath  -Recurse -ErrorAction SilentlyContinue

    Write-Host "  -> CVEs cross-referenced: $($map.Count)" -ForegroundColor Green
    return $map
}

# ---------------------------------------------------------------
# Main
# ---------------------------------------------------------------
Write-Host "===== Step 1c: Enrich CVEs with AVID Database ====="

if (-not (Test-Path $InputPath)) { Write-Error "Not found: $InputPath - run Step1b first." }
$cves = [System.IO.File]::ReadAllText($InputPath, [System.Text.Encoding]::UTF8) | ConvertFrom-Json
Write-Host "  -> Loaded $($cves.Count) CVEs"

$avidMap = Get-AvidCveMap

$enriched = foreach ($cve in $cves) {
    $recs = if ($avidMap.ContainsKey($cve.Id)) { @($avidMap[$cve.Id]) } else { @() }
    $cve | Select-Object * | ForEach-Object {
        $_ | Add-Member -NotePropertyName AvidRecords -NotePropertyValue $recs                  -Force
        $_ | Add-Member -NotePropertyName AvidMatched -NotePropertyValue ($recs.Count -gt 0)   -Force
        $_ | Add-Member -NotePropertyName AvidIds     -NotePropertyValue @($recs | ForEach-Object { $_.AvidId }) -Force
        $_
    }
}

$outDir = Split-Path $OutputPath -Parent
if ($outDir -and -not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

$utf8Bom = New-Object System.Text.UTF8Encoding $true
[System.IO.File]::WriteAllText($OutputPath, ($enriched | ConvertTo-Json -Depth 6), $utf8Bom)

$matched = @($enriched | Where-Object { $_.AvidMatched }).Count
Write-Host ""
Write-Host "  -> AVID matches: $matched / $($enriched.Count)" -ForegroundColor Green
Write-Host "  -> Saved: $OutputPath"
Write-Host ""
