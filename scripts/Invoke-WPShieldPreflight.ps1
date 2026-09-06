#Requires -Version 5.1

<#
.SYNOPSIS
    Read-only readiness check for putting WPShield in front of live IIS sites. Reports every
    blocker, changes nothing.

.DESCRIPTION
    WPShield's production traffic path is the one recorded in ADR 0001: IIS keeps ports 80 and 443,
    URL Rewrite and ARR send each request to WPShield on a loopback port, and WPShield forwards it
    back to a private loopback binding of the same IIS site.

    That path has several ways to fail silently, and each of them fails on the live site rather than
    on a test one. This script checks them before anything is installed:

      - ARR's server-level proxy switch is off by default. With it off, a rewrite to
        http://127.0.0.1:10000 does not proxy - it 404s, on every request, with nothing in the log
        that says why.

      - ARR does not preserve the client Host header by default. WPShield resolves the site from
        that header and fails closed with HTTP 421 when it does not match, so the whole site
        answers 421 the moment the rule goes live.

      - The rewrite rule sends everything to WPShield, and WPShield sends it back to IIS. If the
        private binding is reachable through the same rule, the request loops.

      - Something else on a busy server may already own the port the gateway wants.

    It also prints the configuration to use, filled in from what it found, so the operator does not
    have to retype hostnames and ports into a file where a typo means a 421.

    NOTHING IS CHANGED. No IIS setting, no binding, no rewrite rule, no service, no firewall rule,
    no ACL. This script reads and reports. Installing is a separate, deliberate act, and on a server
    running other people's applications it should not be a side effect of asking a question.

    Written in pure ASCII, as a single file with no dependencies, so it can be copied to a server by
    any route - including a chat window - and still run. See scripts/Test-WPShieldScripts.ps1.

.PARAMETER GatewayPort
    The loopback port WPShield will listen on. Default 10000.

.PARAMETER PrivatePort
    Candidate loopback ports for the private IIS bindings WPShield forwards to. Default 8081, 8082.

.PARAMETER SiteName
    IIS site names to plan for. When omitted, every site is inventoried and the ones that look like
    WordPress are proposed.

.PARAMETER InstallPath
    Where WPShield will be installed. Checked for existence and permissions only.

.PARAMETER LogPath
    Where WPShield will write its log. Checked for whether unprivileged users can read it.

.PARAMETER OutputPath
    Optional JSON Lines report, in the same envelope the gateway log and the triage tool use.

.EXAMPLE
    .\Invoke-WPShieldPreflight.ps1

.EXAMPLE
    .\Invoke-WPShieldPreflight.ps1 -SiteName 'example-one','example-two' -OutputPath .\preflight.jsonl

.NOTES
    Run as an administrator. Without elevation the IIS configuration, the listening ports and the
    directory permissions are all partly or wholly unreadable, and the answer will be wrong in the
    optimistic direction - which is the worst direction for a check like this.

    Part of WPShield, a research preview. Not approved for production traffic.
    https://github.com/peopleworks/WPShield
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 65535)]
    [int] $GatewayPort = 10000,

    [int[]] $PrivatePort = @(8081, 8082),

    [string[]] $SiteName,

    [string] $InstallPath = 'C:\Program Files\WPShield',

    [string] $LogPath = 'C:\ProgramData\WPShield\logs',

    [string] $OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# The correlation header WPShield stamps on every forwarded request, and strips from every inbound
# one. The rewrite rule's loop guard tests it, and that is only safe because of the stripping.
$script:RequestIdHeader = 'X-WPShield-Request-ID'
$script:ServiceName = 'WPShield'

$script:Results = [System.Collections.Generic.List[object]]::new()
$script:Writer = $null

# =====================================================================================
#  Output.
#
#  The JSON helper below is a copy of the one in Invoke-WPShieldTriage.ps1, and the duplication is
#  deliberate. These scripts are run on servers where nothing may be installed and where the only
#  transport might be a chat window, so each has to be a single file that works alone. A shared
#  module would mean two files that must travel together and one that fails obscurely when it does
#  not. Test-WPShieldScripts.ps1 exercises both copies against the same cases, so they cannot
#  diverge in behaviour without a build failing.
# =====================================================================================

function ConvertTo-PreflightJsonString {
    param([AllowNull()] [string] $Value)

    if ($null -eq $Value) { return 'null' }

    $builder = New-Object System.Text.StringBuilder
    [void] $builder.Append('"')

    foreach ($character in $Value.ToCharArray()) {
        $code = [int] $character

        if ($character -eq '"') {
            [void] $builder.Append('\"')
        }
        elseif ($character -eq '\') {
            [void] $builder.Append('\\')
        }
        elseif ($code -ge 0x20 -and $code -le 0x7E) {
            [void] $builder.Append($character)
        }
        else {
            [void] $builder.Append(('\u{0:x4}' -f $code))
        }
    }

    [void] $builder.Append('"')
    return $builder.ToString()
}

function ConvertTo-PreflightJsonValue {
    param([AllowNull()] $Value)

    if ($null -eq $Value) { return 'null' }

    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal]) {
        return [string]::Format([System.Globalization.CultureInfo]::InvariantCulture, '{0}', $Value)
    }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $parts = @(foreach ($item in $Value) { ConvertTo-PreflightJsonValue $item })
        return '[' + ($parts -join ',') + ']'
    }

    return ConvertTo-PreflightJsonString ([string] $Value)
}

<#
    Records one check.

    Status is one of:
      Pass    - ready.
      Warn    - works, but something will need attention or is not what the design assumes.
      Blocker - the traffic path will not work, or will break the live site, until this is fixed.
      Info    - inventory. Not a judgement.

    Every Blocker carries a Remedy, because a readiness check that reports a problem without saying
    what to do about it has moved the problem rather than solved it.
#>
function Add-Check {
    param(
        [string] $Id,
        [ValidateSet('Pass', 'Warn', 'Blocker', 'Info')]
        [string] $Status,
        [string] $Title,
        [string] $Detail,
        [string] $Remedy,
        [hashtable] $Data
    )

    $result = [pscustomobject] @{
        Id     = $Id
        Status = $Status
        Title  = $Title
        Detail = $Detail
        Remedy = $Remedy
    }
    $script:Results.Add($result)

    $colour = 'Gray'
    if ($Status -eq 'Pass') { $colour = 'Green' }
    elseif ($Status -eq 'Warn') { $colour = 'Yellow' }
    elseif ($Status -eq 'Blocker') { $colour = 'Red' }

    Write-Host ('  ' + $Status.PadRight(8) + $Id + '  ' + $Title) -ForegroundColor $colour
    if (-not [string]::IsNullOrWhiteSpace($Detail)) {
        Write-Host ('           ' + $Detail) -ForegroundColor DarkGray
    }
    if ($Status -eq 'Blocker' -and -not [string]::IsNullOrWhiteSpace($Remedy)) {
        Write-Host ('           -> ' + $Remedy) -ForegroundColor Yellow
    }

    if ($null -eq $script:Writer) { return }

    $level = 'Information'
    if ($Status -eq 'Warn') { $level = 'Warning' }
    elseif ($Status -eq 'Blocker') { $level = 'Error' }

    $state = @{
        checkId = $Id
        status  = $Status
        title   = $Title
    }
    if (-not [string]::IsNullOrWhiteSpace($Detail)) { $state['detail'] = $Detail }
    if (-not [string]::IsNullOrWhiteSpace($Remedy)) { $state['remedy'] = $Remedy }
    if ($null -ne $Data) { foreach ($key in $Data.Keys) { $state[$key] = $Data[$key] } }

    $pairs = New-Object System.Collections.Generic.List[string]
    foreach ($key in ($state.Keys | Sort-Object)) {
        $pairs.Add((ConvertTo-PreflightJsonString $key) + ':' + (ConvertTo-PreflightJsonValue $state[$key]))
    }

    $timestamp = [datetimeoffset]::UtcNow.ToUniversalTime().ToString(
        'yyyy-MM-ddTHH:mm:ss.fffffffzzz', [System.Globalization.CultureInfo]::InvariantCulture)

    $script:Writer.WriteLine(
        '{' +
        '"timestamp":' + (ConvertTo-PreflightJsonString $timestamp) + ',' +
        '"level":' + (ConvertTo-PreflightJsonString $level) + ',' +
        '"category":' + (ConvertTo-PreflightJsonString 'WPShield.Preflight') + ',' +
        '"message":' + (ConvertTo-PreflightJsonString $Title) + ',' +
        '"state":{' + ($pairs -join ',') + '}' +
        '}')
    $script:Writer.Flush()
}

function Write-Section {
    param([string] $Title)
    Write-Host ''
    Write-Host $Title -ForegroundColor Cyan
}

# =====================================================================================
#  Small helpers.
# =====================================================================================

function Test-Elevated {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-ListenerOnPort {
    param([int] $Port)

    try {
        return @(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction Stop)
    }
    catch {
        return @()
    }
}

function Get-ProcessNameById {
    param([int] $ProcessId)

    try { return (Get-Process -Id $ProcessId -ErrorAction Stop).ProcessName }
    catch { return ('pid ' + $ProcessId) }
}

if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    $outputDirectory = Split-Path -Parent $OutputPath
    if ([string]::IsNullOrWhiteSpace($outputDirectory)) { $outputDirectory = (Get-Location).ProviderPath }
    if (-not (Test-Path -LiteralPath $outputDirectory)) {
        New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
    }
    $script:Writer = New-Object System.IO.StreamWriter(
        $OutputPath, $false, (New-Object System.Text.UTF8Encoding($false)))
}

try {

Write-Host ''
Write-Host 'WPShield preflight - read-only. No IIS setting, service, binding, ACL or firewall rule is changed.' -ForegroundColor Cyan
Write-Host ('Host: ' + $env:COMPUTERNAME + '    ' + (Get-Date -Format 'u'))

# =====================================================================================
Write-Section 'Host'
# =====================================================================================

$elevated = Test-Elevated
if ($elevated) {
    Add-Check 'PRE-001' 'Pass' 'Running elevated' 'The IIS configuration, listening ports and directory permissions are all readable.'
}
else {
    Add-Check 'PRE-001' 'Blocker' 'Not running as administrator' `
        'Without elevation the IIS configuration, the listening ports and the directory ACLs are partly unreadable, and every check below will fail optimistically.' `
        'Re-run this script from an elevated PowerShell session.' `
        @{ elevated = $false }
}

Add-Check 'PRE-002' 'Info' 'Windows and PowerShell' `
    ((Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption +
     '  |  PowerShell ' + $PSVersionTable.PSVersion.ToString()) `
    '' @{ powerShell = $PSVersionTable.PSVersion.ToString() }

# .NET runtime. A framework-dependent build needs ASP.NET Core 10 on the host; a self-contained one
# does not. Either is fine - this reports which deployment shape the server is ready for.
$runtimes = @()
try {
    $runtimes = @(& dotnet --list-runtimes 2>$null)
}
catch { }

$aspNet10 = @($runtimes | Where-Object { $_ -match '^Microsoft\.AspNetCore\.App 10\.' })
if ($aspNet10.Count -gt 0) {
    Add-Check 'PRE-003' 'Pass' 'ASP.NET Core 10 runtime present' `
        ($aspNet10[0]) '' @{ selfContainedRequired = $false }
}
elseif ($runtimes.Count -gt 0) {
    Add-Check 'PRE-003' 'Warn' 'ASP.NET Core 10 runtime not found' `
        'A .NET installation exists but not ASP.NET Core 10. Deploy the self-contained build, which carries its own runtime and needs nothing installed.' `
        '' @{ selfContainedRequired = $true }
}
else {
    Add-Check 'PRE-003' 'Warn' 'No .NET installation found' `
        'Deploy the self-contained win-x64 build. It carries its own runtime, which on a server running other applications is the safer choice anyway: WPShield cannot be broken by someone else patching a shared runtime.' `
        '' @{ selfContainedRequired = $true }
}

# =====================================================================================
Write-Section 'IIS'
# =====================================================================================

$iisAvailable = $false
try {
    Import-Module WebAdministration -ErrorAction Stop -Verbose:$false
    $iisAvailable = $true
}
catch {
    Add-Check 'PRE-004' 'Blocker' 'The IIS management module is not available' `
        'WebAdministration could not be imported, so nothing about IIS can be read.' `
        'Install the IIS management scripts and tools feature, and run elevated.' `
        @{ iisReadable = $false }
}

if ($iisAvailable) {
    $w3svc = $null
    try { $w3svc = Get-Service -Name 'W3SVC' -ErrorAction Stop } catch { }

    if ($null -eq $w3svc) {
        Add-Check 'PRE-004' 'Blocker' 'IIS is not installed' '' `
            'This traffic path assumes IIS owns ports 80 and 443. Without IIS there is nothing to put WPShield behind.' `
            @{ iisInstalled = $false }
    }
    else {
        $status = 'Pass'
        if ($w3svc.Status -ne 'Running') { $status = 'Warn' }
        Add-Check 'PRE-004' $status 'IIS is installed' ('W3SVC is ' + $w3svc.Status) '' `
            @{ w3svcStatus = $w3svc.Status.ToString() }
    }

    # --- URL Rewrite ------------------------------------------------------------------
    $rewriteInstalled = Test-Path -LiteralPath (Join-Path $env:windir 'System32\inetsrv\rewrite.dll')
    if ($rewriteInstalled) {
        Add-Check 'PRE-005' 'Pass' 'URL Rewrite is installed' '' '' @{ urlRewrite = $true }
    }
    else {
        Add-Check 'PRE-005' 'Blocker' 'URL Rewrite is not installed' `
            'rewrite.dll was not found under System32\inetsrv.' `
            'Install the IIS URL Rewrite module. It is what sends traffic to WPShield; without it there is no way in.' `
            @{ urlRewrite = $false }
    }

    # --- ARR --------------------------------------------------------------------------
    $arrPaths = @(
        (Join-Path $env:ProgramFiles 'IIS\Application Request Routing'),
        (Join-Path ${env:ProgramFiles(x86)} 'IIS\Application Request Routing')
    )
    $arrInstalled = $false
    foreach ($candidate in $arrPaths) {
        if (-not [string]::IsNullOrWhiteSpace($candidate) -and (Test-Path -LiteralPath $candidate)) {
            $arrInstalled = $true
        }
    }

    if ($arrInstalled) {
        Add-Check 'PRE-006' 'Pass' 'Application Request Routing is installed' '' '' @{ arr = $true }
    }
    else {
        Add-Check 'PRE-006' 'Blocker' 'Application Request Routing is not installed' `
            'ARR is what actually performs the proxy hop to WPShield. URL Rewrite alone can rewrite a URL but cannot forward the request to another process.' `
            'Install Application Request Routing 3.0 from the Microsoft Web Platform installer or the standalone package.' `
            @{ arr = $false }
    }

    # --- The two ARR settings that fail silently ---------------------------------------
    #
    # These are the checks this whole script is worth writing for. Both default to the value that
    # breaks the design, and neither failure says what it is: the first 404s every request, the
    # second turns the entire site into HTTP 421.

    $proxyEnabled = $null
    $preserveHost = $null
    try {
        $proxyEnabled = (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' `
            -Filter 'system.webServer/proxy' -Name 'enabled' -ErrorAction Stop).Value
        $preserveHost = (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' `
            -Filter 'system.webServer/proxy' -Name 'preserveHostHeader' -ErrorAction Stop).Value
    }
    catch { }

    if ($null -eq $proxyEnabled) {
        Add-Check 'PRE-007' 'Warn' 'The ARR proxy setting could not be read' `
            'This is expected when ARR is not installed yet; re-run after installing it.' '' @{}
    }
    elseif ($proxyEnabled) {
        Add-Check 'PRE-007' 'Pass' 'ARR server-level proxy is enabled' '' '' @{ proxyEnabled = $true }
    }
    else {
        Add-Check 'PRE-007' 'Blocker' 'ARR server-level proxy is disabled' `
            'This is the default. With it off, a rewrite rule pointing at http://127.0.0.1:10000 does not proxy - it returns 404 for every request, with nothing in the log explaining why.' `
            'IIS Manager -> server node -> Application Request Routing Cache -> Server Proxy Settings -> Enable proxy. Do this before the rewrite rule, never after.' `
            @{ proxyEnabled = $false }
    }

    if ($null -eq $preserveHost) {
        Add-Check 'PRE-008' 'Warn' 'The ARR host header setting could not be read' '' '' @{}
    }
    elseif ($preserveHost) {
        Add-Check 'PRE-008' 'Pass' 'ARR preserves the client Host header' `
            'WPShield resolves the site from this header, so this setting is load-bearing.' '' `
            @{ preserveHostHeader = $true }
    }
    else {
        Add-Check 'PRE-008' 'Blocker' 'ARR does not preserve the client Host header' `
            'WPShield resolves the site from the Host header and fails closed with HTTP 421 when it does not match a configured site. With this off, ARR replaces the header with the destination, so every request becomes 421 and the whole site goes down the moment the rule is enabled.' `
            'IIS Manager -> server node -> Application Request Routing Cache -> Server Proxy Settings -> Preserve client Host header.' `
            @{ preserveHostHeader = $false }
    }
}

# =====================================================================================
Write-Section 'Ports'
# =====================================================================================

$gatewayListeners = @(Get-ListenerOnPort $GatewayPort)
if ($gatewayListeners.Count -eq 0) {
    Add-Check 'PRE-009' 'Pass' ('Gateway port ' + $GatewayPort + ' is free') '' '' `
        @{ gatewayPort = $GatewayPort }
}
else {
    $owners = @($gatewayListeners | ForEach-Object { Get-ProcessNameById $_.OwningProcess } | Sort-Object -Unique)
    Add-Check 'PRE-009' 'Blocker' ('Gateway port ' + $GatewayPort + ' is already in use') `
        ('Held by: ' + ($owners -join ', ')) `
        'Choose a different loopback port for WPShield, or free this one. On a server running many applications, picking an unused high port is usually the faster answer.' `
        @{ gatewayPort = $GatewayPort; owners = $owners }
}

foreach ($port in $PrivatePort) {
    $listeners = @(Get-ListenerOnPort $port)
    if ($listeners.Count -eq 0) {
        Add-Check ('PRE-010.' + $port) 'Pass' ('Private port ' + $port + ' is free') `
            'Available for the private loopback binding WPShield forwards to.' '' @{ port = $port }
    }
    else {
        $owners = @($listeners | ForEach-Object { Get-ProcessNameById $_.OwningProcess } | Sort-Object -Unique)
        $status = 'Warn'
        $detail = 'Held by: ' + ($owners -join ', ')
        if ($owners -contains 'System' -or $owners -contains 'Idle') {
            # http.sys listens as System. If IIS already has a binding here, that is not a conflict,
            # it may already be the private binding this design wants.
            $detail += '. This is how an existing IIS binding appears, so check whether it is already the private binding for one of the sites below.'
        }
        Add-Check ('PRE-010.' + $port) $status ('Private port ' + $port + ' is in use') $detail '' `
            @{ port = $port; owners = $owners }
    }
}

foreach ($publicPort in @(80, 443)) {
    $listeners = @(Get-ListenerOnPort $publicPort)
    if ($listeners.Count -eq 0) {
        Add-Check ('PRE-011.' + $publicPort) 'Warn' ('Nothing is listening on port ' + $publicPort) `
            'This design assumes IIS owns the public ports.' '' @{ port = $publicPort }
    }
    else {
        $owners = @($listeners | ForEach-Object { Get-ProcessNameById $_.OwningProcess } | Sort-Object -Unique)
        Add-Check ('PRE-011.' + $publicPort) 'Info' ('Port ' + $publicPort + ' is held by ' + ($owners -join ', ')) `
            'WPShield never binds a public port. It listens on loopback only, which is why it needs no elevated binding rights.' '' `
            @{ port = $publicPort; owners = $owners }
    }
}

# =====================================================================================
Write-Section 'Sites'
# =====================================================================================

$plannedSites = New-Object System.Collections.Generic.List[object]

if (-not $iisAvailable) {
    # Without this the section header prints with nothing under it, which reads as "there are no
    # sites" rather than "nobody could look". On a readiness check those must never look alike.
    Add-Check 'PRE-012' 'Blocker' 'The sites could not be inventoried' `
        'IIS was unreadable, so this run says nothing about what is being served, which bindings exist, or which rewrite rules are already in place.' `
        'Fix the blockers above and run again. Do not read the absence of site findings as an absence of sites.' `
        @{ sitesReadable = $false }
}

if ($iisAvailable) {
    $websites = @()
    try { $websites = @(Get-Website -ErrorAction Stop) } catch { }

    if ($websites.Count -eq 0) {
        Add-Check 'PRE-012' 'Warn' 'No IIS sites could be read' '' '' @{}
    }

    foreach ($website in $websites) {
        if ($null -ne $SiteName -and $SiteName.Count -gt 0 -and $SiteName -notcontains $website.Name) {
            continue
        }

        $physical = ''
        try { $physical = [Environment]::ExpandEnvironmentVariables([string] $website.physicalPath) } catch { }

        $isWordPress = $false
        if (-not [string]::IsNullOrWhiteSpace($physical) -and (Test-Path -LiteralPath $physical)) {
            $isWordPress =
                (Test-Path -LiteralPath (Join-Path $physical 'wp-config.php')) -or
                (Test-Path -LiteralPath (Join-Path $physical 'wp-includes\version.php'))
        }

        $bindings = @()
        try {
            $bindings = @($website.bindings.Collection | ForEach-Object { $_.protocol + ' ' + $_.bindingInformation })
        }
        catch { }

        $publicHosts = New-Object System.Collections.Generic.List[string]
        $loopbackBindings = New-Object System.Collections.Generic.List[string]
        $usesHttps = $false

        foreach ($binding in $bindings) {
            if ($binding -match '^https ') { $usesHttps = $true }

            # bindingInformation is address:port:hostname.
            $parts = ($binding -split ' ', 2)[1]
            $fields = $parts -split ':'
            if ($fields.Count -ge 3) {
                $address = $fields[0]
                $port = $fields[1]
                $header = ($fields[2..($fields.Count - 1)] -join ':')

                if ($address -eq '127.0.0.1' -or $address -eq '::1') {
                    [void] $loopbackBindings.Add($address + ':' + $port)
                }
                elseif (-not [string]::IsNullOrWhiteSpace($header)) {
                    [void] $publicHosts.Add($header)
                }
            }
        }

        $label = 'not WordPress'
        if ($isWordPress) { $label = 'WordPress' }

        Add-Check ('PRE-012.' + $website.Name) 'Info' ('Site: ' + $website.Name + '  (' + $label + ', ' + $website.State + ')') `
            ('bindings: ' + ($bindings -join ' | ') + '   path: ' + $physical) '' `
            @{
                site        = $website.Name
                state       = [string] $website.State
                wordPress   = $isWordPress
                https       = $usesHttps
                bindings    = $bindings
                physicalPath = $physical
            }

        if ($isWordPress -or ($null -ne $SiteName -and $SiteName.Count -gt 0)) {
            $plannedSites.Add([pscustomobject] @{
                Name             = $website.Name
                Hosts            = @($publicHosts | Sort-Object -Unique)
                Https            = $usesHttps
                LoopbackBindings = @($loopbackBindings | Sort-Object -Unique)
            })
        }
    }

    # --- Existing rewrite rules -------------------------------------------------------
    #
    # A rule that already rewrites everything will interact with the WPShield rule, and the order
    # decides which wins. Worth seeing before, not after.
    foreach ($website in $websites) {
        $rules = @()
        try {
            $rules = @(Get-WebConfiguration -PSPath ('IIS:\Sites\' + $website.Name) `
                -Filter 'system.webServer/rewrite/rules/rule' -ErrorAction Stop)
        }
        catch { }

        if ($rules.Count -eq 0) { continue }

        $names = @($rules | ForEach-Object { $_.name })
        $hasWPShield = @($names | Where-Object { $_ -like '*WPShield*' }).Count -gt 0

        if ($hasWPShield) {
            Add-Check ('PRE-013.' + $website.Name) 'Warn' ('A WPShield rewrite rule already exists on ' + $website.Name) `
                ('rules: ' + ($names -join ', ')) '' @{ site = $website.Name; rules = $names }
        }
        else {
            Add-Check ('PRE-013.' + $website.Name) 'Info' ($website.Name + ' has ' + $rules.Count + ' existing rewrite rule(s)') `
                ('rules: ' + ($names -join ', ') + '. The WPShield rule must be ordered so these still behave as intended.') '' `
                @{ site = $website.Name; rules = $names }
        }
    }
}

# =====================================================================================
Write-Section 'Installation target'
# =====================================================================================

$existingService = $null
try { $existingService = Get-Service -Name $script:ServiceName -ErrorAction Stop } catch { }

if ($null -eq $existingService) {
    Add-Check 'PRE-014' 'Pass' 'No WPShield service is installed yet' '' '' @{ serviceInstalled = $false }
}
else {
    Add-Check 'PRE-014' 'Warn' ('A WPShield service already exists and is ' + $existingService.Status) `
        'An install would be an upgrade. Stop it before replacing files on disk.' '' `
        @{ serviceInstalled = $true; serviceStatus = $existingService.Status.ToString() }
}

<#
    Reports whether unprivileged users can read a directory.

    This matters for the log directory specifically. C:\ProgramData is the conventional place to put
    one, and its default ACL grants BUILTIN\Users read - so a log holding request paths, rule hits
    and client addresses would be readable by every account on a server that runs other people's
    applications. The install step has to remove that inheritance; this reports whether it still
    needs to.
#>
function Test-DirectoryReadableByUsers {
    param([string] $Path)

    if (-not (Test-Path -LiteralPath $Path)) { return $null }

    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
    }
    catch {
        return $null
    }

    $broad = @('BUILTIN\Users', 'Everyone', 'NT AUTHORITY\Authenticated Users', 'BUILTIN\IIS_IUSRS')
    $matches = @($acl.Access | Where-Object {
        $broad -contains ([string] $_.IdentityReference) -and
        $_.AccessControlType -eq 'Allow'
    })

    return @($matches | ForEach-Object { [string] $_.IdentityReference } | Sort-Object -Unique)
}

foreach ($pair in @(
    @{ Id = 'PRE-015'; Path = $InstallPath; What = 'Installation directory' },
    @{ Id = 'PRE-016'; Path = $LogPath;     What = 'Log directory' }
)) {
    if (-not (Test-Path -LiteralPath $pair.Path)) {
        Add-Check $pair.Id 'Info' ($pair.What + ' does not exist yet') `
            ($pair.Path + ' - the install step will create it with a restricted ACL.') '' `
            @{ path = $pair.Path; exists = $false }
        continue
    }

    $readable = @(Test-DirectoryReadableByUsers $pair.Path)
    if ($readable.Count -eq 0) {
        Add-Check $pair.Id 'Pass' ($pair.What + ' exists and is not readable by unprivileged accounts') `
            $pair.Path '' @{ path = $pair.Path; exists = $true }
    }
    else {
        $status = 'Warn'
        $remedy = ''
        if ($pair.Id -eq 'PRE-016') {
            $status = 'Blocker'
            $remedy = 'Remove inheritance on the log directory and grant only the service account and administrators. A WPShield log carries request paths, rule hits and client addresses.'
        }
        Add-Check $pair.Id $status ($pair.What + ' is readable by unprivileged accounts') `
            ($pair.Path + ' grants: ' + ($readable -join ', ')) $remedy `
            @{ path = $pair.Path; exists = $true; broadAccess = $readable }
    }
}

# =====================================================================================
#  Verdict, then the configuration to use.
# =====================================================================================

$blockers = @($script:Results | Where-Object { $_.Status -eq 'Blocker' })
$warnings = @($script:Results | Where-Object { $_.Status -eq 'Warn' })

Write-Host ''
Write-Host '================================================================================' -ForegroundColor Cyan
if ($blockers.Count -eq 0) {
    Write-Host (' Ready. ' + $warnings.Count + ' warning(s), no blockers.') -ForegroundColor Green
}
else {
    Write-Host (' NOT ready. ' + $blockers.Count + ' blocker(s), ' + $warnings.Count + ' warning(s).') -ForegroundColor Red
}
Write-Host '================================================================================' -ForegroundColor Cyan

foreach ($blocker in $blockers) {
    Write-Host ('  ' + $blocker.Id + '  ' + $blocker.Title) -ForegroundColor Red
    if (-not [string]::IsNullOrWhiteSpace($blocker.Remedy)) {
        Write-Host ('        ' + $blocker.Remedy) -ForegroundColor Yellow
    }
}

if ($plannedSites.Count -gt 0) {
    Write-Host ''
    Write-Host 'Suggested appsettings.Local.json, from what was found here.' -ForegroundColor Cyan
    Write-Host 'Mode is Monitor: WPShield reports and forwards, and refuses nothing, until you change it.' -ForegroundColor DarkGray
    Write-Host 'This file is gitignored and must stay on this server. It is printed, never written.' -ForegroundColor DarkGray
    Write-Host ''

    $portIndex = 0
    $siteBlocks = New-Object System.Collections.Generic.List[string]

    foreach ($site in $plannedSites) {
        $destinationPort = $GatewayPort + 1000 + $portIndex
        if ($portIndex -lt $PrivatePort.Count) { $destinationPort = $PrivatePort[$portIndex] }
        $portIndex++

        $hostList = @($site.Hosts)
        if ($hostList.Count -eq 0) { $hostList = @('REPLACE-WITH-THE-PUBLIC-HOSTNAME') }

        $quotedHosts = @($hostList | ForEach-Object { '        "' + $_ + '"' })

        $siteBlocks.Add(
            '    {' + "`n" +
            '      "Id": "' + $site.Name + '",' + "`n" +
            '      "Hosts": [' + "`n" + ($quotedHosts -join (',' + "`n")) + "`n" + '      ],' + "`n" +
            '      "Destination": "http://127.0.0.1:' + $destinationPort + '",' + "`n" +
            '      "Mode": "Monitor",' + "`n" +
            '      "ObserveThreshold": 30,' + "`n" +
            '      "BlockThreshold": 80' + "`n" +
            '    }')
    }

    $anyHttps = @($plannedSites | Where-Object { $_.Https }).Count -gt 0
    $trustedProxies = '"TrustedProxies": [ "127.0.0.1" ]'

    Write-Host ('{' + "`n" +
        '  "Gateway": {' + "`n" +
        '    "Urls": [ "http://127.0.0.1:' + $GatewayPort + '" ],' + "`n" +
        '    ' + $trustedProxies + "`n" +
        '  },' + "`n" +
        '  "Sites": [' + "`n" +
        ($siteBlocks -join (',' + "`n")) + "`n" +
        '  ],' + "`n" +
        '  "Logging": { "File": { "Enabled": true, "Directory": "' + ($LogPath -replace '\\', '\\\\') + '" } }' + "`n" +
        '}')

    Write-Host ''
    if ($anyHttps) {
        Write-Host 'At least one site uses HTTPS, so TrustedProxies matters.' -ForegroundColor Yellow
        Write-Host 'It is set to 127.0.0.1 above because that is the peer address ARR will present. Without it,' -ForegroundColor DarkGray
        Write-Host 'X-Forwarded-Proto is discarded, WordPress sees plain HTTP and starts emitting http:// URLs' -ForegroundColor DarkGray
        Write-Host 'behind an HTTPS site - which is a redirect loop, not a subtle degradation.' -ForegroundColor DarkGray
    }

    Write-Host ''
    Write-Host 'Each site also needs a private loopback binding on its destination port, and the rewrite rule:' -ForegroundColor Cyan
    Write-Host ''
    Write-Host '  <rule name="WPShield" stopProcessing="true">'
    Write-Host '    <match url=".*" />'
    Write-Host '    <conditions>'
    Write-Host ('      <add input="{HTTP_' + ($script:RequestIdHeader -replace '-', '_').ToUpperInvariant() + '}" pattern="^$" />')
    Write-Host '    </conditions>'
    Write-Host ('    <action type="Rewrite" url="http://127.0.0.1:' + $GatewayPort + '/{R:0}" />')
    Write-Host '  </rule>'
    Write-Host ''
    Write-Host 'The condition is the loop guard. WPShield stamps that header on everything it forwards and' -ForegroundColor DarkGray
    Write-Host 'strips any inbound copy, so the request coming back from the gateway does not match the rule' -ForegroundColor DarkGray
    Write-Host 'and a visitor cannot forge the header to skip inspection. Both halves are load-bearing.' -ForegroundColor DarkGray
}

Write-Host ''
Write-Host 'Nothing on this server was changed.' -ForegroundColor Green
if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    Write-Host ('Report: ' + $OutputPath) -ForegroundColor Green
}

}
finally {
    if ($null -ne $script:Writer) {
        $script:Writer.Flush()
        $script:Writer.Dispose()
        $script:Writer = $null
    }
}
