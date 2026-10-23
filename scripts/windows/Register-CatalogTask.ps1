<#
.SYNOPSIS
    Creates the "Windows Patch Catalog" scheduled task on this device (no admin rights needed).
.DESCRIPTION
    Runs Update-Catalog.ps1 daily at the given time as the current, standard user, whether or not the
    user is logged on. The catalog run is incremental, so a daily run costs seconds when nothing changed.
    The task runs with "Limited" privileges (never elevated).
.EXAMPLE
    .\Register-CatalogTask.ps1 -At 07:30
#>
[CmdletBinding()]
param(
    [string]$At = '07:30',
    [string]$TaskName = 'Windows Patch Catalog'
)
$ErrorActionPreference = 'Stop'
$script = Join-Path $PSScriptRoot 'Update-Catalog.ps1'
$credential = Get-Credential -UserName "$env:USERDOMAIN\$env:USERNAME" -Message 'Your Windows password, so the task can run when you are logged off'

$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$script`""
$trigger = New-ScheduledTaskTrigger -Daily -At $At
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RunOnlyIfNetworkAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Hours 1) -MultipleInstances IgnoreNew

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings `
    -User $credential.UserName -Password $credential.GetNetworkCredential().Password -RunLevel Limited `
    -Description 'Refreshes the Windows security release catalog from Microsoft MSRC and pushes it to GitHub.' | Out-Null
Write-Host "Scheduled task '$TaskName' created: daily at $At. Logs: $env:LOCALAPPDATA\WindowsPatchCatalog\logs"
