<#
.SYNOPSIS
  Lance les scans SAST (Bandit) et SCA (pip-audit, OWASP Dependency-Check)
  sur une version Git du projet, via Docker.

.EXAMPLE
  .\scripts\scan.ps1 -Ref v1.0-vulnerable     # version initiale
  .\scripts\scan.ps1 -Ref v2.0-secure         # version corrigee
  .\scripts\scan.ps1 -Ref HEAD -SkipDependencyCheck

  Les rapports sont ecrits dans reports\demo\<ref>\
#>
param(
    [string]$Ref = "HEAD",
    [switch]$SkipDependencyCheck
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$safe = $Ref -replace '[^A-Za-z0-9._-]', '_'
$work = Join-Path $env:TEMP "tp1-scan-$safe"
$out = Join-Path $root "reports\demo\$safe"
$feed = "https://dependency-check.github.io/DependencyCheck_Builder/nvd_cache/"

# 1. Extraction de la version demandee (sans toucher a la copie de travail)
if (Test-Path $work) { Remove-Item -Recurse -Force $work }
New-Item -ItemType Directory -Force $work, $out | Out-Null
git -C $root archive --format=tar -o "$work.tar" $Ref
if ($LASTEXITCODE -ne 0) { throw "Reference Git inconnue : $Ref" }
tar -xf "$work.tar" -C $work
Remove-Item "$work.tar"
Write-Host "== Version scannee : $Ref ($(git -C $root rev-parse --short "$Ref^{commit}"))" -ForegroundColor Cyan

# 2. SAST - Bandit
Write-Host "== [SAST] Bandit" -ForegroundColor Cyan
foreach ($fmt in "txt", "json", "html") {
    docker run --rm -v "${work}:/src:ro" -v "${out}:/out" -w /src --entrypoint bandit `
        ghcr.io/pycqa/bandit/bandit -r app -q -f $fmt -o "/out/bandit.$fmt" | Out-Null
}
$bandit = (Get-Content "$out\bandit.json" -Raw | ConvertFrom-Json).metrics._totals

# 3. SCA - pip-audit (base PyPA / OSV)
Write-Host "== [SCA] pip-audit" -ForegroundColor Cyan
docker run --rm -v "${work}:/src:ro" -v "${out}:/out" -w /src python:3.13-slim sh -c `
    "pip install -q --root-user-action=ignore --disable-pip-version-check pip-audit >/dev/null 2>&1; pip-audit -r requirements.txt --no-deps --disable-pip -f json -o /out/pip-audit.json 2>/dev/null; pip-audit -r requirements.txt --no-deps --disable-pip --desc off 2>/dev/null > /out/pip-audit.txt" | Out-Null
$audit = Get-Content "$out\pip-audit.json" -Raw | ConvertFrom-Json
$auditIds = @($audit.dependencies | ForEach-Object { $_.vulns | ForEach-Object { $_.id } } | Sort-Object -Unique)
$auditPkgs = @($audit.dependencies | Where-Object { $_.vulns.Count -gt 0 })

# 4. SCA - OWASP Dependency-Check (base NVD)
if (-not $SkipDependencyCheck) {
    Write-Host "== [SCA] OWASP Dependency-Check (mise a jour NVD puis analyse)" -ForegroundColor Cyan
    docker run --rm -v "${work}:/src:ro" -v "${out}:/out" -v dc-data:/usr/share/dependency-check/data `
        owasp/dependency-check:latest --project "TP1 Notes App ($Ref)" --scan /src `
        --enableExperimental --disableOssIndex --nvdDatafeed $feed `
        --format HTML --format JSON --out /out | Out-Null
    $dc = Get-Content "$out\dependency-check-report.json" -Raw | ConvertFrom-Json
    $dcVulns = @($dc.dependencies | Where-Object { $_.vulnerabilities } | ForEach-Object { $_.vulnerabilities })
}

# 5. Synthese
Write-Host ""
Write-Host "================ SYNTHESE : $Ref ================" -ForegroundColor Yellow
Write-Host ("Bandit (SAST)            : High={0}  Medium={1}  Low={2}" -f `
    $bandit.'SEVERITY.HIGH', $bandit.'SEVERITY.MEDIUM', $bandit.'SEVERITY.LOW')
Write-Host ("pip-audit (SCA)          : {0} vulnerabilite(s) dans {1} paquet(s)" -f $auditIds.Count, $auditPkgs.Count)
if (-not $SkipDependencyCheck) {
    Write-Host ("Dependency-Check (SCA)   : {0} CVE (Critical={1} High={2})" -f $dcVulns.Count, `
        @($dcVulns | Where-Object { $_.severity -eq "CRITICAL" }).Count, `
        @($dcVulns | Where-Object { $_.severity -eq "HIGH" }).Count)
}
Write-Host "Rapports : $out"
Remove-Item -Recurse -Force $work
