#Requires -Version 5.1

<#
.SYNOPSIS
    Removes the WPShield service and, optionally, its files. Touches nothing in IIS.

.DESCRIPTION
    The reverse of Install-WPShield.ps1, and written to be found in a hurry.

    READ THIS FIRST, BECAUSE IT IS THE MISTAKE THIS SCRIPT CANNOT UNDO:

      If the IIS rewrite rule is still enabled, removing this service TAKES THE SITE DOWN. IIS keeps
      forwarding every request to a loopback port with nothing behind it, and every visitor gets an
      error. Uninstalling is not a rollback.

      The rollback is the rewrite rule. Disable it first, confirm the site serves normally again,
      and only then remove the service. This script refuses to run without -Force while it can still
      see a WPShield rewrite rule anywhere in IIS, because getting that order wrong during an
      incident is exactly when it would happen.

    Logs are kept by default. They are the record of what the gateway saw, and an uninstall during
    an incident is the worst moment to delete evidence. Pass -RemoveLogs when you actually mean it.

.PARAMETER InstallPath
    The installation directory. Default C:\Program Files\WPShield.

.PARAMETER LogPath
    The log directory. Default C:\ProgramData\WPShield\logs.

.PARAMETER RemoveFiles
    Also delete the installation directory.

.PARAMETER RemoveLogs
    Also delete the log directory. Off by default, deliberately.

.PARAMETER Force
    Proceed even though a WPShield rewrite rule is still present in IIS. Only use this when you have
    confirmed the rule is disabled or the site is already down.

.EXAMPLE
    .\Uninstall-WPShield.ps1 -WhatIf

.EXAMPLE
    .\Uninstall-WPShield.ps1 -RemoveFiles

.NOTES
    Part of WPShield, a research preview. Not approved for production traffic.
    https://github.com/peopleworks/WPShield
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string] $InstallPath = 'C:\Program Files\WPShield',
    [string] $LogPath = 'C:\ProgramData\WPShield\logs',
    [switch] $RemoveFiles,
    [switch] $RemoveLogs,
    [switch] $Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:ServiceName = 'WPShield'

function Write-Step {
    param([string] $Text)
    Write-Host ''
    Write-Host $Text -ForegroundColor Cyan
}

function Write-Detail {
    param([string] $Text, [string] $Colour = 'DarkGray')
    Write-Host ('  ' + $Text) -ForegroundColor $Colour
}

# A real run requires elevation; a -WhatIf preview does not. Reading what an uninstaller intends to
# do should not be harder to reach than running it - and during an incident the preview is the thing
# somebody needs first.
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if (-not $WhatIfPreference) {
        throw 'This script must run from an elevated PowerShell session. Nothing was changed.'
    }
    Write-Host ''
    Write-Host 'Not elevated. This is a -WhatIf preview, so it continues; a real run will refuse.' -ForegroundColor Yellow
}

Write-Host ''
Write-Host 'WPShield uninstall' -ForegroundColor Cyan
Write-Host ('Host: ' + $env:COMPUTERNAME + '    ' + (Get-Date -Format 'u'))
if ($WhatIfPreference) {
    Write-Host 'Running with -WhatIf. Nothing will be changed.' -ForegroundColor Yellow
}

# =====================================================================================
Write-Step '1. Is IIS still sending traffic here?'
# =====================================================================================

# Read-only. This script reads the IIS configuration to answer a question; it never writes to it.
$rulesFound = New-Object System.Collections.Generic.List[string]
$iisReadable = $false

try {
    Import-Module WebAdministration -ErrorAction Stop -Verbose:$false
    $iisReadable = $true

    foreach ($website in (Get-Website -ErrorAction Stop)) {
        $rules = @()
        try {
            $rules = @(Get-WebConfiguration -PSPath ('IIS:\Sites\' + $website.Name) `
                -Filter 'system.webServer/rewrite/rules/rule' -ErrorAction Stop)
        }
        catch { continue }

        foreach ($rule in $rules) {
            $ruleName = ''
            $enabled = $true
            try { $ruleName = [string] $rule.name } catch { }
            try { if ($null -ne $rule.enabled) { $enabled = [bool] $rule.enabled } } catch { }

            if ($ruleName -like '*WPShield*' -and $enabled) {
                [void] $rulesFound.Add($website.Name + '/' + $ruleName)
            }
        }
    }
}
catch {
    $iisReadable = $false
}

# "Nobody could look" is not "there is nothing there", and on an uninstall the difference decides
# whether a site stays up. An unreadable IIS configuration cannot rule out a rule still pointing at
# the gateway, so it is treated as the dangerous case rather than the reassuring one.
if (-not $iisReadable) {
    Write-Host ''
    Write-Host '  The IIS configuration could not be read, so this check could not run.' -ForegroundColor Yellow
    Write-Host '  That is not the same as finding no rule. If one is still enabled, removing the' -ForegroundColor Yellow
    Write-Host '  service takes the site down and uninstalling will not bring it back.' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '  Run elevated so the check can run, or confirm by hand that no rewrite rule points' -ForegroundColor Yellow
    Write-Host '  at the gateway and re-run with -Force.' -ForegroundColor Yellow

    if (-not $Force) {
        throw 'Refusing to uninstall without being able to confirm that IIS no longer forwards to the gateway. Nothing was changed.'
    }

    Write-Detail 'Continuing anyway because -Force was given.' 'Yellow'
}
elseif ($rulesFound.Count -gt 0) {
    Write-Host ''
    Write-Host '  An enabled WPShield rewrite rule is still present:' -ForegroundColor Red
    foreach ($rule in $rulesFound) { Write-Host ('    ' + $rule) -ForegroundColor Red }
    Write-Host ''
    Write-Host '  Removing the service now leaves IIS forwarding every request to a port with' -ForegroundColor Yellow
    Write-Host '  nothing behind it. The site goes down, and uninstalling will not bring it back.' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '  Disable the rule first, confirm the site serves normally, then run this again.' -ForegroundColor Yellow

    if (-not $Force) {
        throw 'Refusing to uninstall while IIS still forwards to the gateway. Nothing was changed. Use -Force only if you have confirmed the rule is disabled or the site is already down.'
    }

    Write-Detail 'Continuing anyway because -Force was given.' 'Yellow'
}
else {
    Write-Detail 'no enabled WPShield rewrite rule found'
}

# =====================================================================================
Write-Step '2. Stop and remove the service'
# =====================================================================================

$service = $null
try { $service = Get-Service -Name $script:ServiceName -ErrorAction Stop } catch { }

if ($null -eq $service) {
    Write-Detail 'no WPShield service is installed'
}
else {
    if ($service.Status -ne 'Stopped') {
        if ($PSCmdlet.ShouldProcess($script:ServiceName, 'Stop the service')) {
            Stop-Service -Name $script:ServiceName -Force
            (Get-Service -Name $script:ServiceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
            Write-Detail 'stopped'
        }
    }

    if ($PSCmdlet.ShouldProcess($script:ServiceName, 'Delete the service')) {
        # Remove-Service exists only in PowerShell 6 and later; sc.exe is what 5.1 has, and 5.1 is
        # what a Windows Server host has before anything is installed on it.
        $output = & sc.exe delete $script:ServiceName 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw ('Deleting the service failed with exit code ' + $LASTEXITCODE + ': ' + ($output -join ' '))
        }
        Write-Detail 'deleted'
        Write-Detail 'the virtual account NT SERVICE\WPShield goes with it; there is no account left behind'
    }
}

# =====================================================================================
Write-Step '3. Files'
# =====================================================================================

if ($RemoveFiles) {
    if (-not (Test-Path -LiteralPath $InstallPath)) {
        Write-Detail ('nothing at ' + $InstallPath)
    }
    elseif ($PSCmdlet.ShouldProcess($InstallPath, 'Delete the installation directory')) {
        # Only ever the directory that was named, and only after confirming it is a WPShield
        # install rather than something else that happens to be at this path.
        $marker = Join-Path $InstallPath 'WPShield.Gateway.exe'
        if (-not (Test-Path -LiteralPath $marker)) {
            throw ($InstallPath + ' does not contain WPShield.Gateway.exe. Refusing to delete a ' +
                   'directory that may not be a WPShield installation. Nothing was changed here.')
        }

        Remove-Item -LiteralPath $InstallPath -Recurse -Force
        Write-Detail ('removed: ' + $InstallPath)
    }
}
else {
    Write-Detail ('kept: ' + $InstallPath + '   (pass -RemoveFiles to delete it)')
}

if ($RemoveLogs) {
    if (-not (Test-Path -LiteralPath $LogPath)) {
        Write-Detail ('nothing at ' + $LogPath)
    }
    elseif ($PSCmdlet.ShouldProcess($LogPath, 'Delete the log directory')) {
        Remove-Item -LiteralPath $LogPath -Recurse -Force
        Write-Detail ('removed: ' + $LogPath)
    }
}
else {
    Write-Detail ('kept: ' + $LogPath + '   (the record of what the gateway saw)')
}

# =====================================================================================

Write-Host ''
Write-Host '================================================================================' -ForegroundColor Cyan
if ($WhatIfPreference) {
    Write-Host ' -WhatIf: nothing above was actually done.' -ForegroundColor Yellow
}
else {
    Write-Host ' Removed. IIS was not touched.' -ForegroundColor Green
}
Write-Host '================================================================================' -ForegroundColor Cyan
Write-Host ''
Write-Host 'IIS still holds whatever was configured by hand: the private loopback bindings and the' -ForegroundColor DarkGray
Write-Host 'rewrite rules. Remove those yourself if the gateway is not coming back.' -ForegroundColor DarkGray
