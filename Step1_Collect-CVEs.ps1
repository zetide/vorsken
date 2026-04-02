param(
    [int]$Days = 14,
    [string]$OutputPath = ""
)

$ErrorActionPreference = "Stop"

# Default output next to this script
if (-not $OutputPath) { $OutputPath = Join-Path $PSScriptRoot "work\cve_raw.json" }

$Keywords = @(
    "langchain","llamaindex","llama-index","transformers","huggingface",
    "mlflow","ray serve","ollama","litellm","prompt injection",
    "large language model","onnx","tensorflow","torch"
)

function Get-Severity([object]$Score) {
    if ($null -eq $Score -or $Score -eq "N/A") { return "UNKNOWN" }
    $s = [double]$Score
    if ($s -ge 9.0) { return "CRITICAL" }
    if ($s -ge 7.0) { return "HIGH" }
    if ($s -ge 4.0) { return "MEDIUM" }
    return "LOW"
}

function Invoke-NvdApi([string]$Keyword, [int]$Days) {
    $end   = [datetime]::UtcNow
    $start = $end.AddDays(-$Days)
    $fmt   = "yyyy-MM-ddTHH:mm:ss.000"
    $uri   = "https://services.nvd.nist.gov/rest/json/cves/2.0" +
             "?keywordSearch=$([uri]::EscapeDataString($Keyword))" +
             "&pubStartDate=$($start.ToString($fmt))" +
             "&pubEndDate=$($end.ToString($fmt))" +
             "&resultsPerPage=10"
    try {
        $resp = Invoke-RestMethod -Uri $uri -Method Get -TimeoutSec 30
        return $resp.vulnerabilities
    } catch {
        Write-Warning "NVD error ($Keyword): $_"
        return @()
    }
}

function ConvertTo-CveObject($Item) {
    $cve      = $Item.cve
    $metrics  = $cve.metrics
    $cvssData = $null
    $p31 = $metrics.PSObject.Properties["cvssMetricV31"]
    $p30 = $metrics.PSObject.Properties["cvssMetricV30"]
    if ($p31 -and $p31.Value.Count -gt 0) { $cvssData = $p31.Value[0].cvssData }
    elseif ($p30 -and $p30.Value.Count -gt 0) { $cvssData = $p30.Value[0].cvssData }
    $score = if ($cvssData) { $cvssData.baseScore } else { "N/A" }
    $desc  = ($cve.descriptions | Where-Object lang -eq "en" | Select-Object -First 1).value
    if (-not $desc) { $desc = "No description" }
    return [PSCustomObject]@{
        Id          = $cve.id
        Score       = $score
        Severity    = Get-Severity $score
        Description = $desc
        Refs        = @($cve.references | Select-Object -First 3 -ExpandProperty url)
        NvdUrl      = "https://nvd.nist.gov/vuln/detail/$($cve.id)"
        Published   = $cve.published.Substring(0,10)
    }
}

Write-Host "===== Step 1: Collect CVEs from NVD (past $Days days) ====="

$seen    = [System.Collections.Generic.HashSet[string]]::new()
$results = [System.Collections.Generic.List[object]]::new()

foreach ($kw in $Keywords) {
    Write-Host "  Fetching: $kw" -ForegroundColor Cyan
    $items = Invoke-NvdApi $kw $Days
    foreach ($item in $items) {
        if ($seen.Add($item.cve.id)) { $results.Add((ConvertTo-CveObject $item)) }
    }
    # NVD free API: 5 requests per 30 seconds -> wait 7 seconds to be safe
    Write-Host "    (waiting 7s for NVD rate limit...)" -ForegroundColor DarkGray
    Start-Sleep -Seconds 7
}

$sorted = $results | Sort-Object {
    if ($_.Score -eq "N/A") { 0 } else { [double]$_.Score }
} -Descending

# Ensure output directory exists
$outDir = Split-Path $OutputPath -Parent
if ($outDir -and -not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

$sorted | ConvertTo-Json -Depth 5 | Set-Content -Path $OutputPath -Encoding UTF8

Write-Host ""
Write-Host "  -> $($sorted.Count) CVEs saved to $OutputPath" -ForegroundColor Green
Write-Host ""
