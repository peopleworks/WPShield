#Requires -Version 5.1

<#
.SYNOPSIS
    Installs the WPShield gateway as a Windows service, with a least-privilege identity and
    restricted directories. Touches nothing in IIS.

.DESCRIPTION
    This script changes the machine, which is why it supports -WhatIf and why the list of what it
    will and will not do is stated here rather than left to be discovered.

    WHAT IT DOES:
      - Creates the installation and log directories.
      - Copies a published build into the installation directory.
      - Registers a Windows service named WPShield, and only ever that one.
      - Gives that service a virtual account, NT SERVICE\WPShield: no password to store, no account
        to manage, and a per-service identity that can be named in an ACL.
      - Locks both directories down to SYSTEM, the local Administrators group and that service
        account. Read and execute on the program files; write only on the logs.
      - Configures the service to restart itself after a crash.

    WHAT IT DELIBERATELY DOES NOT DO:
      - It does not touch IIS. No binding, no rewrite rule, no application pool, no proxy setting.
        Those are the changes that take a live site down, they need to be reviewed one at a time by
        somebody looking at the site, and on a shared server they affect applications that have
        nothing to do with WPShield. They are documented as manual steps, and they stay manual.
      - It does not touch any service other than WPShield.
      - It does not write appsettings.Local.json. That file carries real hostnames and topology; it
        belongs to the operator, and Invoke-WPShieldPreflight.ps1 prints its contents to be pasted.
        Pass -ConfigurationPath to copy one that already exists.
      - It does not start the service unless asked. A gateway with no site configuration resolves
        no host, and starting it before the configuration is in place proves nothing.

    ABOUT ROLLING BACK, WHICH IS THE PART WORTH READING TWICE:

      Once the IIS rewrite rule is live, stopping this service DOES NOT bypass WPShield - it takes
      the site down, because IIS is still forwarding every request to a port with nothing behind it.

      The bypass is the rewrite rule, not the service. Disable the rule and traffic goes straight to
      the site again, with the service still installed and still stopped or running as it was. Know
      how to do that before you enable it.

.PARAMETER Path
    The published build to install: a directory produced by Publish-WPShield.ps1.

.PARAMETER InstallPath
    Where to install. Default C:\Program Files\WPShield.

.PARAMETER LogPath
    Where the gateway writes its log. Default C:\ProgramData\WPShield\logs.

.PARAMETER ConfigurationPath
    Optional appsettings.Local.json to copy into the installation directory.

.PARAMETER Start
    Start the service when the install finishes. Off by default.

.EXAMPLE
    .\Install-WPShield.ps1 -Path C:\staging\wpshield -WhatIf

.EXAMPLE
    .\Install-WPShield.ps1 -Path C:\staging\wpshield -ConfigurationPath C:\staging\appsettings.Local.json

.NOTES
    Run elevated. Run Invoke-WPShieldPreflight.ps1 first and clear every blocker.

    Part of WPShield, a research preview. Not approved for production traffic.
    https://github.com/peopleworks/WPShield
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true)]
    [string] $Path,

    [string] $InstallPath = 'C:\Program Files\WPShield',

    [string] $LogPath = 'C:\ProgramData\WPShield\logs',

    [string] $ConfigurationPath,

    [switch] $Start
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# The service name is a constant, in one place, and every operation below names this variable rather
# than a literal. scripts/Test-WPShieldScripts.ps1 asserts that no other service name appears in
# this file: an installer that can be pointed at an arbitrary service on a host running sixty
# applications is a different and much worse tool than this one.
$script:ServiceName = 'WPShield'
$script:ServiceDisplayName = 'WPShield gateway'
$script:ServiceDescription = 'WPShield defensive security gateway for WordPress on IIS. Research preview: not approved for production traffic.'
$script:VirtualAccount = 'NT SERVICE\WPShield'
$script:ExecutableName = 'WPShield.Gateway.exe'

function Write-Step {
    param([string] $Text)
    Write-Host ''
    Write-Host $Text -ForegroundColor Cyan
}

function Write-Detail {
    param([string] $Text, [string] $Colour = 'DarkGray')
    Write-Host ('  ' + $Text) -ForegroundColor $Colour
}

<#
    A real run requires elevation. A -WhatIf run does not, and refusing it there would be the wrong
    trade: the point of a dry run is that an operator can read exactly what an installer intends to
    do before deciding to let it, and requiring administrator rights to be allowed to *read* that
    makes the preview harder to reach than the thing it previews.
#>
function Assert-Elevated {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    if ($principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        return
    }

    if ($WhatIfPreference) {
        Write-Host ''
        Write-Host 'Not elevated. This is a -WhatIf preview, so it continues; a real run will refuse.' -ForegroundColor Yellow
        return
    }

    throw 'This script must run from an elevated PowerShell session. Nothing was changed.'
}

<#
    Runs sc.exe and fails loudly.

    sc.exe is used for the three things New-Service cannot express: a virtual account with no
    password, the service SID type, and the recovery actions. Its argument grammar is unusual - the
    key carries the "=" and the value is a separate argument - so the arguments are built as an
    array rather than as a string, which is the form PowerShell passes through unchanged.
#>
function Invoke-ServiceControl {
    param(
        [string[]] $Arguments,
        [string] $What
    )

    $output = & sc.exe @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw ($What + ' failed. sc.exe exited with ' + $LASTEXITCODE + ': ' + ($output -join ' '))
    }
    return $output
}

<#
    Replaces a directory's permissions with an explicit, inheritance-free set.

    Principals are named by well-known SID rather than by name, because the name differs by
    system language: "BUILTIN\Administrators" is "BUILTIN\Administradores" on a Spanish Windows and
    a script that grants by name silently grants nothing there. The SIDs are the same everywhere.
#>
function Set-RestrictedDirectoryAcl {
    param(
        [string] $Directory,
        [System.Security.AccessControl.FileSystemRights] $ServiceRights,
        [System.Security.Principal.SecurityIdentifier] $ServiceSid
    )

    $acl = New-Object System.Security.AccessControl.DirectorySecurity

    # $true disables inheritance, $false discards the inherited entries rather than copying them.
    # Copying them would keep exactly the broad access this is removing.
    $acl.SetAccessRuleProtection($true, $false)

    $administrators = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $localSystem = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')

    $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $propagate = [System.Security.AccessControl.PropagationFlags]::None
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $full = [System.Security.AccessControl.FileSystemRights]::FullControl

    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        $administrators, $full, $inherit, $propagate, $allow)))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        $localSystem, $full, $inherit, $propagate, $allow)))
    $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
        $ServiceSid, $ServiceRights, $inherit, $propagate, $allow)))

    # The permissions are the control, so this one is allowed to fail the install.
    Set-Acl -LiteralPath $Directory -AclObject $acl

    # Ownership is defence in depth, and it is applied separately because it can fail on its own.
    # An owner keeps an implicit right to rewrite the permissions above, so a directory that was
    # created earlier by somebody else leaves that person able to grant themselves access back.
    # Setting it needs a privilege the DACL write does not, though, and failing here would abort
    # the install at step 5 - after the files are copied and the service is registered, which is
    # the worst place to stop. So it is attempted, and reported when it does not work.
    try {
        $owner = New-Object System.Security.AccessControl.DirectorySecurity
        $owner.SetOwner($administrators)
        Set-Acl -LiteralPath $Directory -AclObject $owner
    }
    catch {
        $current = 'unknown'
        try { $current = (Get-Acl -LiteralPath $Directory).Owner } catch { }
        Write-Detail ('note: could not set the owner of ' + $Directory + ' to Administrators; it stays ' +
            $current + '. The permissions above were applied. ' + $_.Exception.Message) 'Yellow'
    }
}

function Get-BroadAccess {
    param([string] $Directory)

    $acl = Get-Acl -LiteralPath $Directory
    $broad = @('S-1-5-32-545', 'S-1-1-0', 'S-1-5-11', 'S-1-5-32-568')  # Users, Everyone, Authenticated Users, IIS_IUSRS
    return @($acl.Access | Where-Object {
        $broad -contains ([string] $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value)
    })
}

# =====================================================================================
#  Checks before anything changes.
# =====================================================================================

Assert-Elevated

Write-Host ''
Write-Host 'WPShield install' -ForegroundColor Cyan
Write-Host ('Host: ' + $env:COMPUTERNAME + '    ' + (Get-Date -Format 'u'))
if ($WhatIfPreference) {
    Write-Host 'Running with -WhatIf. Nothing will be changed.' -ForegroundColor Yellow
}

if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
    throw ('The published build was not found at ' + $Path + '. Nothing was changed.')
}

$sourceExecutable = Join-Path $Path $script:ExecutableName
if (-not (Test-Path -LiteralPath $sourceExecutable)) {
    throw ($Path + ' does not look like a WPShield build: it has no ' + $script:ExecutableName +
           '. Nothing was changed.')
}

# A published build must not carry operator topology. Publish-WPShield.ps1 refuses to produce one
# that does, but this build may have arrived by some other route.
$strayConfiguration = Join-Path $Path 'appsettings.Local.json'
if (Test-Path -LiteralPath $strayConfiguration) {
    Write-Detail 'WARNING: the build directory contains appsettings.Local.json.' 'Yellow'
    Write-Detail 'That file carries real hostnames and topology and should not travel inside a build.' 'Yellow'
    Write-Detail 'It will be installed, which is probably what you want, but it should not have been packaged.' 'Yellow'
}

if (-not [string]::IsNullOrWhiteSpace($ConfigurationPath)) {
    if (-not (Test-Path -LiteralPath $ConfigurationPath -PathType Leaf)) {
        throw ('The configuration file was not found at ' + $ConfigurationPath + '. Nothing was changed.')
    }

    # Fail before touching anything rather than after installing a file the gateway will reject.
    try {
        Get-Content -LiteralPath $ConfigurationPath -Raw | ConvertFrom-Json | Out-Null
    }
    catch {
        throw ('The configuration at ' + $ConfigurationPath + ' is not valid JSON. Nothing was changed. ' + $_.Exception.Message)
    }
    Write-Detail ('Configuration to install: ' + $ConfigurationPath + ' (valid JSON)')
}

$existingService = $null
try { $existingService = Get-Service -Name $script:ServiceName -ErrorAction Stop } catch { }

Write-Detail ('Source      : ' + $Path)
Write-Detail ('Install to  : ' + $InstallPath)
Write-Detail ('Logs to     : ' + $LogPath)
Write-Detail ('Service     : ' + $script:ServiceName + $(if ($null -eq $existingService) { ' (new)' } else { ' (upgrade, currently ' + $existingService.Status + ')' }))
Write-Detail ('Identity    : ' + $script:VirtualAccount)

# =====================================================================================
Write-Step '1. Stop the service if it is already running'
# =====================================================================================

if ($null -ne $existingService -and $existingService.Status -ne 'Stopped') {
    if ($PSCmdlet.ShouldProcess($script:ServiceName, 'Stop the service')) {
        Stop-Service -Name $script:ServiceName -Force
        (Get-Service -Name $script:ServiceName).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
        Write-Detail 'stopped'
    }
}
else {
    Write-Detail 'nothing to stop'
}

# =====================================================================================
Write-Step '2. Create the directories'
# =====================================================================================

foreach ($directory in @($InstallPath, $LogPath)) {
    if (Test-Path -LiteralPath $directory) {
        Write-Detail ('exists: ' + $directory)
    }
    elseif ($PSCmdlet.ShouldProcess($directory, 'Create directory')) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
        Write-Detail ('created: ' + $directory)
    }
}

# =====================================================================================
Write-Step '3. Copy the build'
# =====================================================================================

if ($PSCmdlet.ShouldProcess($InstallPath, 'Copy the published build')) {
    # The shipped appsettings.json is replaced; appsettings.Local.json in the destination is not
    # touched by this, because the source has none unless it was packaged by mistake.
    Copy-Item -Path (Join-Path $Path '*') -Destination $InstallPath -Recurse -Force
    $copied = @(Get-ChildItem -LiteralPath $InstallPath -Recurse -File).Count
    Write-Detail ($copied.ToString() + ' files in place')
}

if (-not [string]::IsNullOrWhiteSpace($ConfigurationPath)) {
    $destination = Join-Path $InstallPath 'appsettings.Local.json'
    if ($PSCmdlet.ShouldProcess($destination, 'Install the operator configuration')) {
        Copy-Item -LiteralPath $ConfigurationPath -Destination $destination -Force
        Write-Detail ('configuration installed: ' + $destination)
    }
}

# =====================================================================================
Write-Step '4. Register the service'
# =====================================================================================

$installedExecutable = Join-Path $InstallPath $script:ExecutableName

if ($null -eq $existingService) {
    if ($PSCmdlet.ShouldProcess($script:ServiceName, 'Create the Windows service')) {
        New-Service -Name $script:ServiceName `
            -BinaryPathName ('"' + $installedExecutable + '"') `
            -DisplayName $script:ServiceDisplayName `
            -Description $script:ServiceDescription `
            -StartupType Automatic | Out-Null
        Write-Detail ('created: ' + $script:ServiceName)
    }
}
else {
    if ($PSCmdlet.ShouldProcess($script:ServiceName, 'Update the service binary path')) {
        Invoke-ServiceControl @('config', $script:ServiceName, 'binPath=', ('"' + $installedExecutable + '"')) 'Updating the binary path'
        Write-Detail 'binary path updated'
    }
}

# The service SID has to be in the process token before NT SERVICE\WPShield means anything as an
# identity, and it has to exist before it can be granted anything in an ACL. This is why the ACLs
# below come after the service is registered rather than before.
if ($PSCmdlet.ShouldProcess($script:ServiceName, 'Enable the per-service SID')) {
    Invoke-ServiceControl @('sidtype', $script:ServiceName, 'unrestricted') 'Setting the service SID type' | Out-Null
    Write-Detail 'per-service SID enabled'
}

if ($PSCmdlet.ShouldProcess($script:ServiceName, ('Set the service identity to ' + $script:VirtualAccount))) {
    # A virtual service account: Windows manages it, it has no password anywhere, and it cannot be
    # used to log on. password= must be present and empty.
    Invoke-ServiceControl @('config', $script:ServiceName, 'obj=', $script:VirtualAccount, 'password=', '') 'Setting the service identity' | Out-Null
    Write-Detail ('identity: ' + $script:VirtualAccount)
}

if ($PSCmdlet.ShouldProcess($script:ServiceName, 'Configure restart-on-failure')) {
    # Three escalating restarts, and the counter resets after a day. A gateway that dies and stays
    # dead takes the site with it, because IIS is still forwarding to its port.
    Invoke-ServiceControl @('failure', $script:ServiceName, 'reset=', '86400',
        'actions=', 'restart/5000/restart/15000/restart/60000') 'Configuring recovery actions' | Out-Null
    Write-Detail 'restarts after a crash: 5s, 15s, 60s'
}

# =====================================================================================
Write-Step '5. Lock down the directories'
# =====================================================================================

if ($PSCmdlet.ShouldProcess(($InstallPath + ' and ' + $LogPath), 'Replace the permissions')) {
    $serviceSid = $null
    try {
        $serviceSid = (New-Object System.Security.Principal.NTAccount($script:VirtualAccount)).Translate(
            [System.Security.Principal.SecurityIdentifier])
    }
    catch {
        throw ('Could not resolve ' + $script:VirtualAccount + ' to a SID. The service must exist ' +
               'before its account can be granted anything. ' + $_.Exception.Message)
    }

    # Read and execute on the program files. The service runs the binaries; it has no business
    # rewriting them, and a gateway that can overwrite its own executable is a persistence
    # mechanism waiting for a bug.
    Set-RestrictedDirectoryAcl -Directory $InstallPath `
        -ServiceRights ([System.Security.AccessControl.FileSystemRights]'ReadAndExecute') `
        -ServiceSid $serviceSid
    Write-Detail ($InstallPath + ': SYSTEM and Administrators full, service read+execute')

    # Modify on the logs, because writing is the point.
    Set-RestrictedDirectoryAcl -Directory $LogPath `
        -ServiceRights ([System.Security.AccessControl.FileSystemRights]'Modify') `
        -ServiceSid $serviceSid
    Write-Detail ($LogPath + ': SYSTEM and Administrators full, service modify')

    foreach ($directory in @($InstallPath, $LogPath)) {
        $broad = @(Get-BroadAccess $directory)
        if ($broad.Count -gt 0) {
            Write-Detail ('WARNING: ' + $directory + ' still grants access to a broad group.') 'Yellow'
        }
    }
    Write-Detail 'no unprivileged account can read either directory'
}

# =====================================================================================
Write-Step '6. Start'
# =====================================================================================

$configurationInstalled = Test-Path -LiteralPath (Join-Path $InstallPath 'appsettings.Local.json')

if (-not $Start) {
    Write-Detail 'not started: pass -Start, or use Start-Service, once the configuration is in place'
}
elseif (-not $configurationInstalled) {
    Write-Detail 'not started: there is no appsettings.Local.json, so the gateway has no real site to resolve.' 'Yellow'
    Write-Detail 'Install one and start the service yourself.' 'Yellow'
}
elseif ($PSCmdlet.ShouldProcess($script:ServiceName, 'Start the service')) {
    Start-Service -Name $script:ServiceName
    (Get-Service -Name $script:ServiceName).WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
    Write-Detail 'running'
}

# =====================================================================================
#  What happens next, and the part that is easy to get wrong.
# =====================================================================================

Write-Host ''
Write-Host '================================================================================' -ForegroundColor Cyan
if ($WhatIfPreference) {
    Write-Host ' -WhatIf: nothing above was actually done.' -ForegroundColor Yellow
}
else {
    Write-Host ' Installed. IIS was not touched.' -ForegroundColor Green
}
Write-Host '================================================================================' -ForegroundColor Cyan

Write-Host ''
Write-Host 'Still to do, by hand, in this order:' -ForegroundColor Cyan
Write-Host '  1. Put appsettings.Local.json in place. Invoke-WPShieldPreflight.ps1 prints one.'
Write-Host ('     ' + (Join-Path $InstallPath 'appsettings.Local.json'))
Write-Host '  2. Start the service and confirm it listens, before any IIS change:'
Write-Host ('     Start-Service ' + $script:ServiceName)
Write-Host '     Invoke-WebRequest http://127.0.0.1:10000/_wpshield/health/ready -UseBasicParsing'
Write-Host '  3. Add the private loopback binding to each site.'
Write-Host '  4. Add the rewrite rule, ordered BEFORE any catch-all rule the site already has.'
Write-Host '     A WordPress permalink rule is a catch-all: put the WPShield rule above it or it never runs.'
Write-Host '  5. Watch the log with the sites in Monitor mode before changing anything to Block.'

Write-Host ''
Write-Host 'Know the bypass before you enable the rule:' -ForegroundColor Yellow
Write-Host '  Once IIS forwards to the gateway, stopping this service DOES NOT bypass WPShield -' -ForegroundColor Yellow
Write-Host '  it takes the site down, because IIS keeps forwarding to a port with nothing behind it.' -ForegroundColor Yellow
Write-Host '  The bypass is disabling the rewrite rule. That is the control that puts the site back.' -ForegroundColor Yellow

Write-Host ''
Write-Host 'To reverse this install entirely: Uninstall-WPShield.ps1' -ForegroundColor DarkGray
Write-Host 'This is a research preview. It is not approved for production traffic.' -ForegroundColor Yellow
