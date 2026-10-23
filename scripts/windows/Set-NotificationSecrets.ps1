<#
.SYNOPSIS
    Stores notification settings for Update-Catalog.ps1, encrypted with Windows DPAPI
    (only the current user on this machine can read them). Leave a prompt empty to skip that setting.
#>
$ErrorActionPreference = 'Stop'
$stateDir = Join-Path $env:LOCALAPPDATA 'WindowsPatchCatalog'
New-Item -ItemType Directory -Force -Path $stateDir | Out-Null

$secrets = @{}
foreach ($name in 'TEAMS_WEBHOOK_URL', 'SMTP_HOST', 'SMTP_PORT', 'SMTP_USERNAME', 'SMTP_PASSWORD', 'MAIL_FROM', 'MAIL_TO') {
    $value = Read-Host -Prompt $name -AsSecureString
    if ($value.Length -gt 0) { $secrets[$name] = $value }
}
$file = Join-Path $stateDir 'notification-secrets.xml'
$secrets | Export-Clixml -Path $file
Write-Host "Saved $($secrets.Count) setting(s) to $file (DPAPI-encrypted)."
