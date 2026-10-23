<#
.SYNOPSIS
    Refreshes the Windows security release catalog and pushes it to GitHub (Task Scheduler alternative
    to the GitHub Actions workflow). Run by the scheduled task created with Register-CatalogTask.ps1.
.NOTES
    Requires git and Python 3.10+ on PATH. Runs as a standard (non-admin) user.
    GitHub access: a fine-grained personal access token limited to this one repository with
    "Contents: Read and write" only, stored by Git Credential Manager on first push.
    Notification secrets (optional): Set-NotificationSecrets.ps1 stores them DPAPI-encrypted for this
    user on this machine; they are passed only to the notification process.
#>
[CmdletBinding()]
param(
    [string]$RepoPath = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [switch]$FullRefresh
)
$ErrorActionPreference = 'Stop'
$stateDir = Join-Path $env:LOCALAPPDATA 'WindowsPatchCatalog'
$logDir = Join-Path $stateDir 'logs'
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
Start-Transcript -Path (Join-Path $logDir ("run_{0:yyyyMMdd_HHmmss}.log" -f (Get-Date))) | Out-Null
Get-ChildItem $logDir -Filter 'run_*.log' | Sort-Object LastWriteTime -Descending | Select-Object -Skip 60 | Remove-Item

function Invoke-Notify([string]$Status, [string]$SummaryFile) {
    $secretFile = Join-Path $stateDir 'notification-secrets.xml'
    if (-not (Test-Path $secretFile)) { Write-Host 'No notification secrets configured; skipping.'; return }
    $secrets = Import-Clixml $secretFile   # DPAPI: readable only by this user on this machine
    $names = @()
    try {
        foreach ($name in $secrets.Keys) {
            [Environment]::SetEnvironmentVariable($name, [Net.NetworkCredential]::new('', $secrets[$name]).Password, 'Process')
            $names += $name
        }
        $notifyArgs = @('-I', 'scripts/notify.py', '--status', $Status)
        if ($SummaryFile) { $notifyArgs += @('--summary-file', $SummaryFile) }
        & python @notifyArgs
    }
    finally {
        foreach ($name in $names) { [Environment]::SetEnvironmentVariable($name, $null, 'Process') }
    }
}

Push-Location $RepoPath
try {
    git pull --ff-only
    if ($LASTEXITCODE -ne 0) { throw 'git pull failed' }

    $summary = Join-Path $stateDir 'summary.md'
    $outputs = Join-Path $stateDir 'outputs.txt'
    Remove-Item $summary, $outputs -ErrorAction SilentlyContinue
    $env:GITHUB_OUTPUT = $outputs   # build_catalog.py writes changed/material/latest_month here
    $buildArgs = @('-I', 'scripts/build_catalog.py', '--data-dir', 'data', '--summary-out', $summary)
    if ($FullRefresh) { $buildArgs += '--full-refresh' }
    & python @buildArgs
    if ($LASTEXITCODE -ne 0) { throw "build_catalog.py failed with exit code $LASTEXITCODE" }

    $result = Get-Content $outputs -Raw | ConvertFrom-StringData
    if ($result.changed -eq 'true') {
        git add data
        $message = if ($result.material -eq 'true') { "Catalog: $($result.latest_month) ($($result.new_release_count) new releases)" }
                   else { 'Catalog: MSRC revisions (no new releases)' }
        git commit -m $message
        git push
        if ($LASTEXITCODE -ne 0) { throw 'git push failed' }
    }
    if ($result.material -eq 'true') { Invoke-Notify -Status 'success' -SummaryFile $summary }
}
catch {
    Write-Error $_ -ErrorAction Continue
    Invoke-Notify -Status 'failure'
    exit 1
}
finally {
    Remove-Item Env:\GITHUB_OUTPUT -ErrorAction SilentlyContinue
    Pop-Location
    Stop-Transcript | Out-Null
}
