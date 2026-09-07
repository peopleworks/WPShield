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

.PARAMETER AllowWebRootPaths
    Install even though -InstallPath or -LogPath is inside a directory IIS serves. Warns instead of
    refusing. There is no good reason to do this; the switch exists for a layout nobody anticipated.

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

    [switch] $AllowWebRootPaths,

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

function Get-ComparablePath {
    param([string] $Path)

    $full = $Path
    try { $full = [System.IO.Path]::GetFullPath($Path) } catch { }
    return ([string] $full).TrimEnd('\', '/')
}

function Test-PathIsInside {
    param([string] $Path, [string] $Container)

    if ([string]::IsNullOrWhiteSpace($Path) -or [string]::IsNullOrWhiteSpace($Container)) { return $false }

    $candidate = Get-ComparablePath $Path
    $root = Get-ComparablePath $Container
    if ([string]::IsNullOrWhiteSpace($root)) { return $false }
    if ($candidate -eq $root) { return $true }

    return $candidate.StartsWith(($root + '\'), [System.StringComparison]::OrdinalIgnoreCase)
}

<#
    Every directory IIS is known to serve from, plus the conventional root whether or not IIS is
    readable. The inetpub entry is not redundant: an unelevated -WhatIf run cannot read the IIS
    configuration, and the most common version of this mistake lands in exactly that directory.
#>
function Get-ServedDirectory {
    $roots = New-Object System.Collections.Generic.List[string]

    if (-not [string]::IsNullOrWhiteSpace($env:SystemDrive)) {
        [void] $roots.Add((Join-Path $env:SystemDrive 'inetpub'))
    }

    try {
        Import-Module WebAdministration -ErrorAction Stop
        foreach ($site in @(Get-Website -ErrorAction Stop)) {
            $physical = ''
            try { $physical = [Environment]::ExpandEnvironmentVariables([string] $site.physicalPath) } catch { }
            if (-not [string]::IsNullOrWhiteSpace($physical)) { [void] $roots.Add($physical) }
        }
    }
    catch {
        # IIS unreadable. The inetpub entry above still stands, and the check is a refusal rather
        # than a clearance: not finding a reason to refuse is not the same as proving there is none.
    }

    return @($roots | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
}

<#
    WPShield is not an IIS application and must not live inside one.

    Installed under a served directory, three things become true at once. The evidence log sits in
    the tree IIS hands out, and .json is in the default IIS MIME map, so appsettings.Local.json -
    which names every host this gateway protects and the private port behind each - is fetchable
    over HTTP. The log's restricted ACL is the only thing standing between an attacker and a
    description of what the shield can see. And a webshell on any neighbouring site, running as an
    application pool identity that can read the web root, reads all of it without an HTTP request at
    all.

    This is not hypothetical. WPShield was unpacked into C:\inetpub\wwwroot\WPShield on the server
    this project was built for, and wrote its log there for a day before anyone noticed.
#>
function Assert-NotUnderWebRoot {
    param([string[]] $Path)

    $roots = @(Get-ServedDirectory)
    $offences = New-Object System.Collections.Generic.List[string]

    foreach ($candidate in $Path) {
        foreach ($root in $roots) {
            if (Test-PathIsInside -Path $candidate -Container $root) {
                [void] $offences.Add($candidate + '  is inside  ' + $root)
                break
            }
        }
    }

    if ($offences.Count -eq 0) { return }

    if ($AllowWebRootPaths) {
        Write-Detail 'WARNING: installing inside a directory IIS serves.' 'Yellow'
        foreach ($offence in $offences) { Write-Detail ('  ' + $offence) 'Yellow' }
        Write-Detail 'Continuing because -AllowWebRootPaths was passed. The evidence log and' 'Yellow'
        Write-Detail 'appsettings.Local.json are now inside the tree IIS hands out.' 'Yellow'
        return
    }

    throw ('WPShield would be installed inside a directory IIS serves, and it refuses to be. ' +
           ($offences -join '; ') + '. WPShield is not an IIS application: it is a separate ' +
           'process on a loopback port that IIS forwards to, so nothing of it belongs under a web ' +
           'root. There, appsettings.Local.json is fetchable over HTTP - .json is in the default ' +
           'IIS MIME map - and it names every host this gateway protects. Use the defaults, or ' +
           'pass -InstallPath and -LogPath outside every served directory. Nothing was changed.')
}

<#
    Writes the log directory into the configuration the gateway actually reads.

    Until this existed the installer created C:\ProgramData\WPShield\logs, removed inheritance from
    it, granted the service account Modify, printed "Logs to: C:\ProgramData\WPShield\logs" - and
    told the gateway none of it. The gateway read Logging:File:Directory, which shipped as the
    relative "logs", resolved it against its content root and wrote next to its own binaries: a
    directory this same installer deliberately leaves read-only for the service account. The write
    failed, the failure was reported to a stream a Windows service has no console for, and the
    result was an installation that reported success and produced no evidence at all.

    An installer that hardens a directory nothing writes to has not hardened anything. It has only
    told the operator it did.
#>
function Set-InstalledLogDirectory {
    param([string] $ConfigurationFile, [string] $Directory)

    if (-not (Test-Path -LiteralPath $ConfigurationFile -PathType Leaf)) {
        throw ('The installed build has no appsettings.json at ' + $ConfigurationFile +
               ', so the log directory cannot be written into it.')
    }

    $document = $null
    try {
        $document = Get-Content -LiteralPath $ConfigurationFile -Raw | ConvertFrom-Json
    }
    catch {
        throw ('The installed appsettings.json is not valid JSON: ' + $_.Exception.Message)
    }

    # Checked rather than created. A build whose configuration has lost this section is not a build
    # to install quietly, and adding the section here would hide the fact that it went missing.
    if (-not ($document.PSObject.Properties.Name -contains 'Logging')) {
        throw 'The installed appsettings.json has no Logging section. This is not a WPShield build this installer understands.'
    }
    if (-not ($document.Logging.PSObject.Properties.Name -contains 'File')) {
        throw 'The installed appsettings.json has no Logging:File section. This is not a WPShield build this installer understands.'
    }

    $document.Logging.File.Directory = $Directory

    $json = $document | ConvertTo-Json -Depth 20
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($ConfigurationFile, $json, $utf8NoBom)
}

<#
    The URL that verifies THIS installation, rather than the one in the documentation.

    Gateway:Urls is configurable. Printing a hardcoded port to an operator who configured a different
    one sends them to test a port nothing is listening on, and that failure looks exactly like a
    gateway that did not start - which is the most expensive way to be wrong at this point in an
    install.

    The source build and the overlay are read rather than the installed copy, because this also runs
    under -WhatIf, where nothing has been copied yet. The overlay wins, as it does at runtime.
#>
function Get-GatewayHealthUrl {
    param([string] $BuildPath, [string] $OverlayPath)

    foreach ($candidate in @($OverlayPath, (Join-Path $BuildPath 'appsettings.json'))) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }

        try {
            $document = Get-Content -LiteralPath $candidate -Raw | ConvertFrom-Json
            if (-not ($document.PSObject.Properties.Name -contains 'Gateway')) { continue }
            if (-not ($document.Gateway.PSObject.Properties.Name -contains 'Urls')) { continue }

            $urls = @($document.Gateway.Urls)
            if ($urls.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace([string] $urls[0])) {
                return ([string] $urls[0]).TrimEnd('/') + '/_wpshield/health/ready'
            }
        }
        catch { }
    }

    return 'http://127.0.0.1:10000/_wpshield/health/ready'
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

    # Refused rather than passed. Windows PowerShell 5.1 DROPS an empty argument to a native command
    # instead of passing it as "", so a key like 'password=' followed by '' arrives at sc.exe with
    # nothing after it and the whole command line is rejected with 1639. PowerShell 7 passes the same
    # array correctly, which is exactly what makes the fault so hard to see: it appears only on the
    # interpreter this script is written for, and only on a real install.
    foreach ($argument in $Arguments) {
        if ([string]::IsNullOrEmpty($argument)) {
            throw ($What + ' was built with an empty sc.exe argument. Windows PowerShell 5.1 drops ' +
                   'those, so sc.exe would receive a key with no value and reject the command line ' +
                   'with 1639. Omit the key instead of passing an empty value for it.')
        }
    }

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
    #
    # Read the descriptor back and modify it, rather than writing a freshly constructed one. A new
    # DirectorySecurity carries an empty, unprotected DACL, and Set-Acl writes that too - so the
    # first version of this silently undid the permissions three lines above, putting the log
    # directory back to inheriting from C:\ProgramData and its read-for-BUILTIN\Users. It could not
    # fail on an unelevated machine, because SetOwner threw before Set-Acl was reached; it only
    # ever went wrong where it mattered, on an elevated install. CI found it.
    try {
        $descriptor = Get-Acl -LiteralPath $Directory
        $descriptor.SetOwner($administrators)
        Set-Acl -LiteralPath $Directory -AclObject $descriptor
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

# Before anything is created, copied or registered, and before the elevation-dependent steps, so a
# refusal here leaves the machine exactly as it was found.
Assert-NotUnderWebRoot -Path @($InstallPath, $LogPath)

$existingService = $null
try { $existingService = Get-Service -Name $script:ServiceName -ErrorAction Stop } catch { }

Write-Detail ('Source      : ' + $Path)
Write-Detail ('Install to  : ' + $InstallPath)
Write-Detail ('Logs to     : ' + $LogPath + '  (written into appsettings.json, not just created)')
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

    # Immediately after the copy, because the copy above just replaced the file being edited.
    Set-InstalledLogDirectory -ConfigurationFile (Join-Path $InstallPath 'appsettings.json') -Directory $LogPath
    Write-Detail ('Logging:File:Directory set to ' + $LogPath)
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
    <#
        A virtual service account: Windows manages it, it has no password anywhere, and it cannot be
        used to log on.

        No password= token at all, and that omission is the whole fix. This used to pass
        'password=', '' - a key followed by an empty string - and under Windows PowerShell 5.1 an
        empty argument to a native command is DROPPED rather than passed as "". sc.exe therefore
        received a trailing 'password=' with no value after it, rejected the whole command line with
        1639, and printed its usage.

        The install then threw here, at step 4 of 6. The service had already been created by
        New-Service, which defaults to LocalSystem, so what was left running was the gateway with the
        most privileged account on the machine - and steps 5 and 6 never ran, so both directories
        kept their inherited permissions and the evidence log stayed readable by BUILTIN\Users.

        It survived because this line only executes on a real install: -WhatIf skips it, PowerShell 7
        passes the empty argument correctly, and CI parses this file under 5.1 without ever running
        it. Every way it was exercised was a way it could not fail.
    #>
    Invoke-ServiceControl @('config', $script:ServiceName, 'obj=', $script:VirtualAccount) 'Setting the service identity' | Out-Null
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

$localConfigurationPath = Join-Path $InstallPath 'appsettings.Local.json'

# What is on disk. The start decision below hangs on this and on nothing else: -ConfigurationPath
# having been passed is an intention, and a ShouldProcess prompt answered No means the intention did
# not happen.
$configurationInstalled = Test-Path -LiteralPath $localConfigurationPath

# What the operator asked for. The closing notes use this instead, so that a -WhatIf preview - where
# nothing has been copied yet - does not tell an operator who just passed -ConfigurationPath to go
# and put the file in place.
$configurationExpected = $configurationInstalled -or (-not [string]::IsNullOrWhiteSpace($ConfigurationPath))

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
if ($configurationExpected) {
    Write-Host '  1. Read back the site table the gateway resolves at startup, and check that every'
    Write-Host '     host and destination is one you meant. The configuration is already in place:'
}
else {
    Write-Host '  1. Put appsettings.Local.json in place. Invoke-WPShieldPreflight.ps1 prints one.'
}
Write-Host ('     ' + $localConfigurationPath)
Write-Host '  2. Start the service and confirm it listens, before any IIS change:'
Write-Host ('     Start-Service ' + $script:ServiceName)
Write-Host ('     Invoke-WebRequest ' + (Get-GatewayHealthUrl -BuildPath $Path -OverlayPath $ConfigurationPath) +
            ' -UseBasicParsing')
Write-Host '  3. Add the private loopback binding to each site.'
Write-Host '  4. Add the rewrite rule, ordered BEFORE any catch-all rule the site already has.'
Write-Host '     A WordPress permalink rule is a catch-all: put the WPShield rule above it or it never runs.'
Write-Host '  5. Watch the log with the sites in Monitor mode before changing anything to Block.'

Write-Host ''
Write-Host 'Where the evidence goes:' -ForegroundColor Cyan
Write-Host ('  ' + $LogPath)
Write-Host '  That path is now written into appsettings.json, not merely created here. The gateway'
Write-Host '  refuses to start if it cannot write there, because a gateway that inspects traffic and'
Write-Host '  records none of it looks exactly like a quiet night.'

Write-Host ''
Write-Host 'Know the bypass before you enable the rule:' -ForegroundColor Yellow
Write-Host '  Once IIS forwards to the gateway, stopping this service DOES NOT bypass WPShield -' -ForegroundColor Yellow
Write-Host '  it takes the site down, because IIS keeps forwarding to a port with nothing behind it.' -ForegroundColor Yellow
Write-Host '  The bypass is disabling the rewrite rule. That is the control that puts the site back.' -ForegroundColor Yellow

Write-Host ''
Write-Host 'To reverse this install entirely: Uninstall-WPShield.ps1' -ForegroundColor DarkGray
Write-Host 'This is a research preview. It is not approved for production traffic.' -ForegroundColor Yellow
