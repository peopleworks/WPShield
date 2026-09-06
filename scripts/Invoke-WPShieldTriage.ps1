#Requires -Version 5.1

<#
.SYNOPSIS
    Read-only triage of WordPress sites on Windows and IIS. Reports what is on disk, and which of
    it WPShield would refuse a request to.

.DESCRIPTION
    This script reads. It never deletes, quarantines, renames, moves, or repairs anything, and it
    never executes a file it finds. That restriction is the whole point: a compromised host is
    evidence before it is a problem, and the first tool that runs on one should not destroy the
    record of how the intruder arrived.

    It answers three questions, in this order:

      1. What is on disk that should not be?  Executable files in directories that hold data,
         file names Windows will not store literally, PHP that reaches an execution sink with
         request input, and the timestamp anomalies a mass-rewriter leaves behind.

      2. When was each artifact used, by whom, and how often?  Answered from the IIS logs, which
         is usually the only surviving record of the requests that reached a webshell.

      3. Would WPShield have refused those requests?  Every file finding carries the verdict the
         gateway's request-path rules would return for a request to that file. This is the part
         that is worth having: it turns a list of suspicious files into a measurement of the
         gateway's coverage, including - deliberately - the cases it does not cover.

    The findings are written as JSON Lines in the same envelope the gateway's own log uses, so a
    forensic report and a gateway log can be read by one parser, sorted together, and correlated
    on the same field names.

    WHAT THE REPORT DOES NOT CONTAIN, ON PURPOSE:

      File contents. Not one byte. A triage report is written to be attached to a support thread
      or a public issue, and a report that reproduces the payload distributes the webshell to
      everyone who reads it. Marker names, sizes, hashes and timestamps identify a file without
      republishing it. To read a file, open it yourself, in an editor, on a machine that will not
      run it.

      Anything outside ASCII. Every string in the output is escaped to the printable ASCII range,
      so no file name recovered from a compromised host can carry a control character or an ANSI
      escape sequence into the terminal of whoever reads the report.

    This file is written in pure ASCII for the same reason it insists on ASCII output. Windows
    PowerShell 5.1 reads a .ps1 without a byte order mark as ANSI, and a multi-byte UTF-8
    character becomes two characters there - some of which are typographic quotes that PowerShell
    treats as string delimiters. A script that arrives by copy, paste, email or chat must survive
    every one of those paths, and an ASCII file survives all of them.

.PARAMETER SitePath
    One or more WordPress installation roots - the directory holding wp-config.php. When omitted,
    the script asks IIS for its sites and looks for WordPress in each of them.

.PARAMETER IisLogPath
    Root of the IIS log directory. Defaults to the configured location, then to
    C:\inetpub\logs\LogFiles. Pass an empty string to skip log correlation entirely.

.PARAMETER OutputPath
    Where to write the JSON Lines findings. Defaults to a timestamped file in the current
    directory.

.PARAMETER RecentDays
    How far back "recent" reaches for the timestamp checks and the log scan. Default 30.

.PARAMETER MaximumFileBytes
    How much of each PHP file to read when scanning for execution markers. The head and the tail
    of the file are read, half of this budget each, because injectors prepend and webshells are
    appended. Default 65536.

.PARAMETER MaximumFilesScanned
    Upper bound on files examined per site. Default 200000.

.PARAMETER MaximumLogBytes
    Upper bound on IIS log bytes read. Default 1073741824 (1 GiB).

.PARAMETER MaximumFindings
    Upper bound on findings emitted. Default 5000. When the bound is reached the report says so
    rather than stopping silently.

.PARAMETER DiscoverOnly
    Print the sites that would be examined, then exit. Run this first on a host you do not know.

.EXAMPLE
    .\Invoke-WPShieldTriage.ps1 -DiscoverOnly

.EXAMPLE
    .\Invoke-WPShieldTriage.ps1 -SitePath 'C:\inetpub\wwwroot\example' -OutputPath '.\triage.jsonl'

.NOTES
    Run as an administrator: an unprivileged account cannot read the IIS logs, and cannot see
    every file in the web root. Where a file cannot be read, the report says so and continues.

    Part of WPShield, a research preview. Not approved for production traffic.
    https://github.com/peopleworks/WPShield
#>

[CmdletBinding()]
param(
    [string[]] $SitePath,

    [AllowEmptyString()]
    [string] $IisLogPath,

    [string] $OutputPath = ('.\wpshield-triage-{0}.jsonl' -f (Get-Date -Format 'yyyyMMdd-HHmmss')),

    [ValidateRange(1, 3650)]
    [int] $RecentDays = 30,

    [ValidateRange(4096, 16777216)]
    [int] $MaximumFileBytes = 65536,

    [ValidateRange(1, 5000000)]
    [int] $MaximumFilesScanned = 200000,

    [ValidateRange(1048576, 137438953472)]
    [long] $MaximumLogBytes = 1073741824,

    [ValidateRange(1, 1000000)]
    [int] $MaximumFindings = 5000,

    [switch] $DiscoverOnly,

    # Read the host as well as the sites: scheduled tasks, accounts, services, autorun keys,
    # staging directories and the antivirus history. Off by default because it answers a
    # different question from the rest of the script, and because it needs elevation to answer
    # it properly. The summary always says whether it ran.
    [switch] $IncludeHost
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# =====================================================================================
#  Vocabulary shared with the gateway rules.
#
#  These four lists are copies of the ones in src/WPShield.Rules.WordPress. They are copies
#  because this script has to run on a server that has no .NET 10 runtime and no build of
#  WPShield on it - a host being triaged is not a host to install software on. The copies are
#  compared against the C# originals by scripts/Test-WPShieldScripts.ps1, which fails the build
#  when they drift, because a triage tool that reports coverage from a stale list reports
#  coverage that does not exist.
# =====================================================================================

# Extensions a PHP-FastCGI handler will execute.
$script:PhpExecutableExtensions = @(
    'php', 'php3', 'php4', 'php5', 'php7', 'php8',
    'phps', 'pht', 'phtm', 'phtml', 'phar'
)

# Extensions IIS maps to a managed or native handler. On Windows these are exactly as dangerous
# as a PHP script, and a WordPress tree has no reason to contain one.
$script:IisExecutableExtensions = @(
    'aspx', 'asp', 'ashx', 'asmx', 'ascx', 'axd',
    'cshtml', 'vbhtml', 'razor',
    'svc', 'soap', 'rem', 'asax', 'master'
)

# Directories under wp-content that hold data written by upload code paths. Never code.
$script:WordPressDataDirectories = @('uploads', 'upgrade', 'updraft')

# Directories whose entire purpose is to be served verbatim.
$script:StaticAssetDirectories = @(
    'dist', 'build', '_next', 'out',
    'node_modules', 'bower_components',
    'static',
    'fonts', 'webfonts', 'img', 'images'
)

# Names deliberately absent from the list above, recorded here so that the omission stays a
# decision rather than an oversight. Older plugins really do serve generated CSS and JS from PHP,
# so a script in one of these is not by itself evidence of anything.
$script:DirectoriesExcludedFromAssetList = @('assets', 'css', 'js', 'media', 'vendor')

$script:ExecutableExtensions = @($script:PhpExecutableExtensions + $script:IisExecutableExtensions)

# The gateway's default scoring, mirrored so the verdict this script reports is the verdict the
# gateway would reach. See src/WPShield.Core/SiteOptions.cs.
$script:ObserveThreshold = 30
$script:BlockThreshold = 80
$script:RulePathUploads = @{ Id = 'WP-PATH-001'; Score = 100 }
$script:RulePathAssets = @{ Id = 'WP-PATH-002'; Score = 100 }
$script:RulePathUnsafe = @{ Id = 'IIS-PATH-001'; Score = 60 }

# =====================================================================================
#  PHP marker vocabulary.
#
#  A list of suspicious function names, on its own, produces a report nobody reads: WordPress
#  core and half the plugin ecosystem call base64_decode legitimately. So markers are grouped by
#  what they mean, and a file is only reported when the groups combine into something that a
#  legitimate file has no reason to be - a way to run code, reachable from a request, or an
#  obfuscation habit dense enough that the author was hiding rather than compressing.
# =====================================================================================

# A way to execute code chosen at runtime. The lookbehind keeps $db->exec() - ordinary PDO - out
# of the results, which is the single largest source of false positives in this whole check.
$script:ExecutionSinkMarkers = @(
    @{ Name = 'eval';           Pattern = '(?<![\w>$])eval\s*\(' },
    @{ Name = 'assert';         Pattern = '(?<![\w>$])assert\s*\(' },
    @{ Name = 'create_function'; Pattern = '(?<![\w>$])create_function\s*\(' },
    @{ Name = 'shell_exec';     Pattern = '(?<![\w>$])shell_exec\s*\(' },
    @{ Name = 'exec';           Pattern = '(?<![\w>$])exec\s*\(' },
    @{ Name = 'system';         Pattern = '(?<![\w>$])system\s*\(' },
    @{ Name = 'passthru';       Pattern = '(?<![\w>$])passthru\s*\(' },
    @{ Name = 'popen';          Pattern = '(?<![\w>$])popen\s*\(' },
    @{ Name = 'proc_open';      Pattern = '(?<![\w>$])proc_open\s*\(' },
    @{ Name = 'pcntl_exec';     Pattern = '(?<![\w>$])pcntl_exec\s*\(' },
    @{ Name = 'backtick';       Pattern = '`[^`\r\n]{1,120}`' },
    # preg_replace with the /e modifier compiled its replacement as PHP until 7.0. Still found in
    # shells written to run anywhere.
    @{ Name = 'preg_replace_e'; Pattern = 'preg_replace\s*\(\s*[''"][^''"]*[''"]\s*[eimsuxADSUX]*e' }
)

# Request-controlled input. A sink is only remote code execution if something remote reaches it.
$script:RequestInputMarkers = @(
    @{ Name = 'post';        Pattern = '\$_POST\b' },
    @{ Name = 'get';         Pattern = '\$_GET\b' },
    @{ Name = 'request';     Pattern = '\$_REQUEST\b' },
    @{ Name = 'cookie';      Pattern = '\$_COOKIE\b' },
    @{ Name = 'files';       Pattern = '\$_FILES\b' },
    @{ Name = 'php_input';   Pattern = 'php://input' },
    @{ Name = 'headers';     Pattern = '(?<![\w>$])getallheaders\s*\(' },
    @{ Name = 'http_header'; Pattern = '\$_SERVER\s*\[\s*[''"]HTTP_' }
)

# Habits of someone hiding what the file does.
$script:ObfuscationMarkers = @(
    @{ Name = 'base64_decode';   Pattern = '(?<![\w>$])base64_decode\s*\(' },
    @{ Name = 'gzinflate';       Pattern = '(?<![\w>$])gzinflate\s*\(' },
    @{ Name = 'gzuncompress';    Pattern = '(?<![\w>$])gzuncompress\s*\(' },
    @{ Name = 'str_rot13';       Pattern = '(?<![\w>$])str_rot13\s*\(' },
    @{ Name = 'strrev';          Pattern = '(?<![\w>$])strrev\s*\(' },
    @{ Name = 'hexdec';          Pattern = '(?<![\w>$])hexdec\s*\(' },
    @{ Name = 'chr_chain';       Pattern = '(?:chr\s*\(\s*\d+\s*\)\s*\.\s*){3,}' },
    @{ Name = 'hex_escapes';     Pattern = '(?:\\x[0-9A-Fa-f]{2}){6,}' },
    @{ Name = 'variable_variable'; Pattern = '\$\{\s*[''"$]' },
    @{ Name = 'long_base64';     Pattern = '[''"][A-Za-z0-9+/]{200,}={0,2}[''"]' },
    @{ Name = 'error_silenced_include'; Pattern = '@\s*(?:include|require)(?:_once)?\s*[\(''"$]' }
)

# =====================================================================================
#  Output. JSON built by hand, escaped to ASCII.
# =====================================================================================

$script:Findings = [System.Collections.Generic.List[object]]::new()
$script:FindingsTruncated = $false
$script:Writer = $null
$script:UnreadablePaths = 0

<#
    Escapes a string into a JSON string literal containing only printable ASCII.

    Everything outside 0x20-0x7E becomes \uXXXX. This is stricter than JSON requires, and the
    strictness is the feature: the values here are file names and paths recovered from a host
    somebody else has been writing to, and a raw one can carry a control character, a newline or
    an ANSI escape sequence into a terminal, a log viewer, or a browser rendering an issue.
#>
function ConvertTo-TriageJsonString {
    param([AllowNull()] [string] $Value)

    if ($null -eq $Value) { return 'null' }

    $builder = New-Object System.Text.StringBuilder
    [void] $builder.Append('"')

    # Deliberately if/elseif rather than switch. Inside a switch, PowerShell's `continue` ends the
    # switch and resumes the enclosing loop body rather than skipping it, so a matched character
    # would be escaped and then emitted again - which is how the first version of this function
    # turned every Windows path separator into three backslashes and produced JSON that no parser
    # would accept.
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

function ConvertTo-TriageJsonValue {
    param([AllowNull()] $Value)

    if ($null -eq $Value) { return 'null' }

    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal]) {
        return [string]::Format([System.Globalization.CultureInfo]::InvariantCulture, '{0}', $Value)
    }
    if ($Value -is [datetime]) {
        return ConvertTo-TriageJsonString (Format-TriageTimestamp ([datetimeoffset] $Value))
    }
    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        $parts = @(foreach ($item in $Value) { ConvertTo-TriageJsonValue $item })
        return '[' + ($parts -join ',') + ']'
    }

    return ConvertTo-TriageJsonString ([string] $Value)
}

<#
    Renders a timestamp exactly as the gateway's LogEntryFormatter does, so that a triage report
    and a gateway log sort together as text without either being reformatted first.
#>
function Format-TriageTimestamp {
    param([datetimeoffset] $Value)

    return $Value.ToUniversalTime().ToString(
        'yyyy-MM-ddTHH:mm:ss.fffffffzzz',
        [System.Globalization.CultureInfo]::InvariantCulture)
}

<#
    Writes one finding, in the gateway's own log envelope: timestamp, level, category, message,
    state. One JSON object per line, no indentation.

    Lines are flushed as they are produced rather than at the end, so that a run interrupted
    half-way still leaves behind everything it had established by then. Triage runs on hosts that
    are having a bad day.
#>
function Write-TriageFinding {
    param(
        [ValidateSet('Information', 'Warning', 'Error')]
        [string] $Level,

        [string] $Message,

        [hashtable] $State
    )

    if ($script:Findings.Count -ge $MaximumFindings) {
        $script:FindingsTruncated = $true
        return
    }

    $timestamp = Format-TriageTimestamp ([datetimeoffset]::UtcNow)

    $pairs = New-Object System.Collections.Generic.List[string]
    foreach ($key in ($State.Keys | Sort-Object)) {
        $pairs.Add((ConvertTo-TriageJsonString $key) + ':' + (ConvertTo-TriageJsonValue $State[$key]))
    }

    $line =
        '{' +
        '"timestamp":' + (ConvertTo-TriageJsonString $timestamp) + ',' +
        '"level":' + (ConvertTo-TriageJsonString $Level) + ',' +
        '"category":' + (ConvertTo-TriageJsonString 'WPShield.Triage') + ',' +
        '"message":' + (ConvertTo-TriageJsonString $Message) + ',' +
        '"state":{' + ($pairs -join ',') + '}' +
        '}'

    if ($null -ne $script:Writer) {
        $script:Writer.WriteLine($line)
        $script:Writer.Flush()
    }

    $script:Findings.Add([pscustomobject] @{
        Level    = $Level
        RuleId   = $(if ($State.ContainsKey('ruleId')) { $State['ruleId'] } else { $null })
        Message  = $Message
        Path     = $(if ($State.ContainsKey('path')) { $State['path'] } else { $null })
        Verdict  = $(if ($State.ContainsKey('gatewayVerdict')) { $State['gatewayVerdict'] } else { $null })
    })
}

function Write-TriageHost {
    param([string] $Text, [string] $Colour = 'Gray')
    Write-Host $Text -ForegroundColor $Colour
}

# =====================================================================================
#  Path analysis. This mirrors WPShield.Abstractions.NormalizedRequestPath closely enough that
#  the verdicts agree, and no more: the gateway normalizes a hostile URL, while this script
#  normalizes a path it read from the file system, which cannot contain percent-encoding or
#  traversal because Windows already resolved both.
# =====================================================================================

<#
    Splits a file name into its extension segments, every one of them.

    /uploads/shell.php.jpg is executable because a handler mapping can match "php" anywhere in
    the name, not only last. This is the same rule the upload inspector applies, and it is why
    the check is written over all segments rather than over [IO.Path]::GetExtension.
#>
function Get-ExtensionSegment {
    param([string] $Name)

    $parts = $Name.Split('.')
    if ($parts.Length -le 1) { return @() }
    return @($parts[1..($parts.Length - 1)] | ForEach-Object { $_.ToLowerInvariant() })
}

function Test-ExecutableName {
    param([string] $Name)

    foreach ($segment in (Get-ExtensionSegment $Name)) {
        if ($script:ExecutableExtensions -contains $segment) { return $true }
    }
    return $false
}

function Get-ExecutableExtension {
    param([string] $Name)

    foreach ($segment in (Get-ExtensionSegment $Name)) {
        if ($script:ExecutableExtensions -contains $segment) { return $segment }
    }
    return $null
}

<#
    Returns the name anomalies that IIS-PATH-001 scores: the forms Windows accepts on the wire but
    does not store literally, so that what is checked and what is opened are two different names.
#>
function Get-UnsafeNameAnomaly {
    param([string] $Name)

    $anomalies = New-Object System.Collections.Generic.List[string]

    if ($Name -match '[\x00-\x1F\x7F]') { [void] $anomalies.Add('controlCharacter') }
    if ($Name -match '[\. ]$')          { [void] $anomalies.Add('trailingDotOrSpace') }
    if ($Name -match ':')               { [void] $anomalies.Add('alternateDataStream') }

    return @($anomalies.ToArray())
}

<#
    The verdict the gateway would return for an HTTP request to this file.

    Scores are summed, exactly as RequestPathEngine sums them, and compared against the same two
    thresholds. The answer is one of:

      blocked         - the gateway refuses the request outright.
      observed        - it scores, is recorded, but is forwarded. Below the block threshold.
      not-covered     - the file is executable and no request-path rule fires. The gateway
                        forwards a request that reaches code, silently. A real gap.
      not-applicable  - requests to this file are not how it does harm, so a rule family that
                        decides about executable requests has nothing to say about it.

    "not-covered" is the value this whole script exists to be able to print. A tool that only
    listed what its own product catches would be an advertisement.

    "not-applicable" exists so that "not-covered" keeps meaning something. An uploaded web.config
    is remote code execution on IIS, but not because anybody requests it - IIS reads it on its own
    and applies the handler mappings it declares. Counting it as a gap in the request-path rules
    would inflate the one number a reader is meant to act on, with a case no request-path rule
    could ever close. The upload rules are what cover a web.config, at the moment it arrives.
#>
function Get-GatewayVerdict {
    param(
        [string[]] $Segments,
        [string] $FileName
    )

    $lowered = @($Segments | ForEach-Object { $_.ToLowerInvariant() })
    $rules = New-Object System.Collections.Generic.List[string]
    $score = 0

    $executableIndex = -1
    for ($index = 0; $index -lt $lowered.Count; $index++) {
        if (Test-ExecutableName $lowered[$index]) { $executableIndex = $index; break }
    }

    if ($executableIndex -ge 0) {
        # WP-PATH-001: wp-content/uploads, and wp-content/{upgrade,updraft}.
        $dataDirectoryEnd = -1
        for ($index = 0; $index -lt $lowered.Count - 1; $index++) {
            if ($lowered[$index] -eq 'wp-content' -and
                $script:WordPressDataDirectories -contains $lowered[$index + 1]) {
                $dataDirectoryEnd = $index + 1
                break
            }
        }

        if ($dataDirectoryEnd -ge 0 -and $executableIndex -gt $dataDirectoryEnd) {
            [void] $rules.Add($script:RulePathUploads.Id)
            $score += $script:RulePathUploads.Score
        }

        # WP-PATH-002: a static asset directory, entered before the executable segment.
        for ($index = 0; $index -lt $executableIndex; $index++) {
            if ($script:StaticAssetDirectories -contains $lowered[$index]) {
                [void] $rules.Add($script:RulePathAssets.Id)
                $score += $script:RulePathAssets.Score
                break
            }
        }
    }

    # IIS-PATH-001: the path carries a form the two normalizations disagree about.
    $unsafe = @()
    foreach ($segment in $Segments) {
        $unsafe += @(Get-UnsafeNameAnomaly $segment)
    }
    if ($unsafe.Count -gt 0) {
        [void] $rules.Add($script:RulePathUnsafe.Id)
        $score += $script:RulePathUnsafe.Score
    }

    $verdict = 'not-covered'
    if ($score -ge $script:BlockThreshold) { $verdict = 'blocked' }
    elseif ($score -ge $script:ObserveThreshold) { $verdict = 'observed' }
    elseif ($executableIndex -lt 0) { $verdict = 'not-applicable' }

    return [pscustomobject] @{
        Verdict    = $verdict
        Score      = $score
        RuleIds    = @($rules.ToArray())
        Executable = ($executableIndex -ge 0)
    }
}

# =====================================================================================
#  Site discovery.
# =====================================================================================

function Test-WordPressRoot {
    param([string] $Path)

    return (Test-Path -LiteralPath (Join-Path $Path 'wp-includes\version.php')) -or
           (Test-Path -LiteralPath (Join-Path $Path 'wp-config.php'))
}

function Get-WordPressVersion {
    param([string] $Path)

    $versionFile = Join-Path $Path 'wp-includes\version.php'
    if (-not (Test-Path -LiteralPath $versionFile)) { return $null }

    try {
        $match = Select-String -LiteralPath $versionFile -Pattern '\$wp_version\s*=\s*[''"]([^''"]+)' |
            Select-Object -First 1
        if ($null -ne $match) { return $match.Matches[0].Groups[1].Value }
    }
    catch { }

    return $null
}

<#
    Asks IIS what it is serving, and looks for WordPress in each answer - at the root of the site
    and one directory below it, which is where a site that hosts more than one application keeps
    them.

    Falls back to a scan of the default web root when the IIS module is unavailable, which is the
    normal case for a non-elevated shell.
#>
function Find-TriageSite {
    $roots = New-Object System.Collections.Generic.List[string]

    try {
        Import-Module WebAdministration -ErrorAction Stop -Verbose:$false
        foreach ($website in (Get-Website -ErrorAction Stop)) {
            $physical = [Environment]::ExpandEnvironmentVariables([string] $website.physicalPath)
            if (-not [string]::IsNullOrWhiteSpace($physical)) { [void] $roots.Add($physical) }
        }
        foreach ($application in (Get-WebApplication -ErrorAction SilentlyContinue)) {
            $physical = [Environment]::ExpandEnvironmentVariables([string] $application.PhysicalPath)
            if (-not [string]::IsNullOrWhiteSpace($physical)) { [void] $roots.Add($physical) }
        }
    }
    catch {
        Write-TriageHost 'IIS configuration is not readable from this shell. Falling back to a scan of the default web root.' 'Yellow'
        Write-TriageHost 'Run as an administrator, or pass -SitePath, for a complete list.' 'Yellow'
        foreach ($candidate in @('C:\inetpub\wwwroot')) {
            if (Test-Path -LiteralPath $candidate) { [void] $roots.Add($candidate) }
        }
    }

    $found = New-Object System.Collections.Generic.List[string]

    foreach ($root in ($roots | Sort-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $root)) { continue }

        if (Test-WordPressRoot $root) {
            [void] $found.Add((Resolve-Path -LiteralPath $root).ProviderPath)
            continue
        }

        try {
            foreach ($child in (Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue)) {
                if (Test-WordPressRoot $child.FullName) { [void] $found.Add($child.FullName) }
            }
        }
        catch { }
    }

    return @($found | Sort-Object -Unique)
}

# =====================================================================================
#  File enumeration.
#
#  Written by hand rather than with Get-ChildItem -Recurse for one reason: reparse points.
#  Get-ChildItem in Windows PowerShell 5.1 walks through a directory junction, and a web root
#  containing a junction to its own parent - or to C:\Windows - turns a triage run into an
#  infinite one. Skipping reparse points also keeps the report about the site, rather than about
#  whatever the site links to.
# =====================================================================================

function Get-TriageFile {
    param(
        [string] $Root,
        [int] $Limit
    )

    $files = New-Object System.Collections.Generic.List[object]
    $queue = New-Object System.Collections.Generic.Queue[string]
    $queue.Enqueue($Root)

    while ($queue.Count -gt 0 -and $files.Count -lt $Limit) {
        $current = $queue.Dequeue()

        $entries = $null
        try {
            $entries = Get-ChildItem -LiteralPath $current -Force -ErrorAction Stop
        }
        catch {
            $script:UnreadablePaths++
            continue
        }

        foreach ($entry in $entries) {
            $isReparsePoint =
                ($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq
                [System.IO.FileAttributes]::ReparsePoint

            if ($isReparsePoint) { continue }

            if ($entry.PSIsContainer) {
                $queue.Enqueue($entry.FullName)
            }
            elseif ($files.Count -lt $Limit) {
                $files.Add($entry)
            }
        }
    }

    return $files
}

<#
    Reads the head and the tail of a file, as Latin-1 so that every byte maps to exactly one
    character and nothing is lost or transformed by a decoder guessing at an encoding.

    Both ends, because the two ways PHP gets backdoored put the code in different places: an
    injector rewriting every file in a tree prepends its loader so it runs before anything else,
    while a shell dropped into an existing file is appended past the code that is already there.
    Reading only the head finds the first and misses the second.
#>
function Read-TriageFileText {
    param(
        [System.IO.FileInfo] $File,
        [int] $Budget
    )

    $latin1 = [System.Text.Encoding]::GetEncoding(28591)
    $stream = $null

    try {
        # FileShare ReadWrite, because a live site has PHP holding these files open, and a triage
        # run must not fail on a file merely because it is in use.
        #
        # Falls back to the verbatim \\?\ form for names Windows will not resolve, which are the
        # names most worth reading.
        try {
            $stream = [System.IO.File]::Open(
                $File.FullName,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read,
                [System.IO.FileShare]::ReadWrite)
        }
        catch {
            $stream = [System.IO.File]::Open(
                (Get-VerbatimPath $File.FullName),
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read,
                [System.IO.FileShare]::ReadWrite)
        }

        if ($stream.Length -le $Budget) {
            $buffer = New-Object byte[] ([int] $stream.Length)
            $read = $stream.Read($buffer, 0, $buffer.Length)
            return $latin1.GetString($buffer, 0, $read)
        }

        $half = [int] ($Budget / 2)

        $head = New-Object byte[] $half
        $headRead = $stream.Read($head, 0, $half)

        [void] $stream.Seek(-$half, [System.IO.SeekOrigin]::End)
        $tail = New-Object byte[] $half
        $tailRead = $stream.Read($tail, 0, $half)

        return $latin1.GetString($head, 0, $headRead) + "`n" + $latin1.GetString($tail, 0, $tailRead)
    }
    catch {
        $script:UnreadablePaths++
        return $null
    }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
}

<#
    Returns a path that reaches the file even when its name is one Windows will not resolve.

    A name ending in a dot or a space, or carrying a control character, cannot be opened through the
    ordinary path layer: Win32 normalizes the name away before the request reaches NTFS, and the
    open fails or lands on a different file. The \\?\ prefix turns that normalization off.

    This matters more here than anywhere else in the script, because those names are exactly the
    ones a triage run most wants to read. The first version of this function did not do it, and the
    one file in the fixture that Windows refuses to name was also the one file whose hash came back
    null - the artifact most worth identifying was the artifact least identified.
#>
function Get-VerbatimPath {
    param([string] $Path)

    if ($Path.StartsWith('\\?\')) { return $Path }
    if ($Path.StartsWith('\\')) { return '\\?\UNC\' + $Path.Substring(2) }
    return '\\?\' + $Path
}

function Get-TriageFileHash {
    param([System.IO.FileInfo] $File)

    foreach ($path in @($File.FullName, (Get-VerbatimPath $File.FullName))) {
        try {
            $stream = [System.IO.File]::Open(
                $path,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read,
                [System.IO.FileShare]::ReadWrite)
            try {
                $algorithm = [System.Security.Cryptography.SHA256]::Create()
                try {
                    $hash = $algorithm.ComputeHash($stream)
                    return ([System.BitConverter]::ToString($hash) -replace '-', '')
                }
                finally { $algorithm.Dispose() }
            }
            finally { $stream.Dispose() }
        }
        catch { }
    }

    return $null
}

function Get-MarkerHit {
    param(
        [string] $Text,
        [object[]] $Markers
    )

    $hits = New-Object System.Collections.Generic.List[string]
    foreach ($marker in $Markers) {
        if ([System.Text.RegularExpressions.Regex]::IsMatch($Text, $marker.Pattern)) {
            [void] $hits.Add($marker.Name)
        }
    }
    return @($hits.ToArray())
}

# =====================================================================================
#  The checks.
# =====================================================================================

<#
    Builds the state object shared by every file finding, including the gateway verdict. Keeping
    this in one place is what makes the two halves of the report - what is on disk, and what the
    gateway would do about it - impossible to report inconsistently.
#>
function New-FileFindingState {
    param(
        [string] $RuleId,
        [System.IO.FileInfo] $File,
        [string] $SiteRoot,
        [hashtable] $Extra
    )

    $relative = $File.FullName.Substring($SiteRoot.Length).TrimStart('\', '/')
    $segments = @($relative -split '[\\/]+' | Where-Object { $_.Length -gt 0 })
    $requestPath = '/' + ($segments -join '/')

    $gateway = Get-GatewayVerdict -Segments $segments -FileName $File.Name

    $state = @{
        ruleId          = $RuleId
        site            = $SiteRoot
        path            = $File.FullName
        requestPath     = $requestPath
        sizeBytes       = [long] $File.Length
        createdUtc      = Format-TriageTimestamp ([datetimeoffset] $File.CreationTimeUtc)
        modifiedUtc     = Format-TriageTimestamp ([datetimeoffset] $File.LastWriteTimeUtc)
        gatewayVerdict  = $gateway.Verdict
        gatewayScore    = $gateway.Score
        gatewayRuleIds  = $gateway.RuleIds
    }

    if ($null -ne $Extra) {
        foreach ($key in $Extra.Keys) { $state[$key] = $Extra[$key] }
    }

    return $state
}

function Invoke-TriageSiteScan {
    param(
        [string] $SiteRoot,
        [object[]] $Files
    )

    $cutoff = [datetime]::UtcNow.AddDays(-$RecentDays)
    $candidatePaths = New-Object System.Collections.Generic.List[string]
    $scanned = 0

    foreach ($file in $Files) {
        $scanned++
        if (($scanned % 500) -eq 0) {
            Write-Progress -Activity 'Examining files' -Status $SiteRoot `
                -PercentComplete ([Math]::Min(100, (100.0 * $scanned / [Math]::Max(1, $Files.Count))))
        }

        $relative = $file.FullName.Substring($SiteRoot.Length).TrimStart('\', '/')
        $segments = @($relative -split '[\\/]+' | Where-Object { $_.Length -gt 0 })
        $lowered = @($segments | ForEach-Object { $_.ToLowerInvariant() })
        $isExecutable = Test-ExecutableName $file.Name

        # -----------------------------------------------------------------------------
        # TRIAGE-001 - an executable file inside a directory that holds data.
        # -----------------------------------------------------------------------------
        if ($isExecutable) {
            for ($index = 0; $index -lt $lowered.Count - 1; $index++) {
                if ($lowered[$index] -eq 'wp-content' -and
                    $script:WordPressDataDirectories -contains $lowered[$index + 1]) {

                    [void] $candidatePaths.Add($file.FullName)
                    Write-TriageFinding -Level 'Warning' `
                        -Message 'An executable file is stored in a WordPress data directory. Nothing legitimate places code where uploads are written.' `
                        -State (New-FileFindingState -RuleId 'TRIAGE-001' -File $file -SiteRoot $SiteRoot -Extra @{
                            dataDirectory = $lowered[$index + 1]
                            extension     = Get-ExecutableExtension $file.Name
                            sha256        = Get-TriageFileHash $file
                        })
                    break
                }
            }
        }

        # -----------------------------------------------------------------------------
        # TRIAGE-002 - an executable file among static assets.
        # -----------------------------------------------------------------------------
        if ($isExecutable) {
            for ($index = 0; $index -lt $lowered.Count - 1; $index++) {
                if ($script:StaticAssetDirectories -contains $lowered[$index]) {
                    [void] $candidatePaths.Add($file.FullName)
                    Write-TriageFinding -Level 'Warning' `
                        -Message 'An executable file is stored in a directory that exists to be served verbatim.' `
                        -State (New-FileFindingState -RuleId 'TRIAGE-002' -File $file -SiteRoot $SiteRoot -Extra @{
                            assetDirectory = $lowered[$index]
                            extension      = Get-ExecutableExtension $file.Name
                            sha256         = Get-TriageFileHash $file
                        })
                    break
                }
            }
        }

        # -----------------------------------------------------------------------------
        # TRIAGE-003 - a web.config below the site root. On IIS this is remote code execution:
        # a web.config can add a handler mapping, so an attacker who can write one can decide
        # what the server executes and with which extension.
        # -----------------------------------------------------------------------------
        if ($file.Name -ieq 'web.config' -and $segments.Count -gt 1) {
            [void] $candidatePaths.Add($file.FullName)
            Write-TriageFinding -Level 'Warning' `
                -Message 'A web.config exists below the site root. On IIS a web.config can add a handler mapping, so writing one is equivalent to executing code.' `
                -State (New-FileFindingState -RuleId 'TRIAGE-003' -File $file -SiteRoot $SiteRoot -Extra @{
                    depth       = $segments.Count
                    sha256      = Get-TriageFileHash $file
                    gatewayNote = 'IIS reads a web.config on its own, so no request-path rule can cover this. The control that does is the upload rule set, at the moment the file arrives.'
                })
        }

        # -----------------------------------------------------------------------------
        # TRIAGE-004 - a name Windows does not store the way it was written.
        # -----------------------------------------------------------------------------
        $nameAnomalies = @(Get-UnsafeNameAnomaly $file.Name)
        if ($nameAnomalies.Count -gt 0) {
            [void] $candidatePaths.Add($file.FullName)
            Write-TriageFinding -Level 'Warning' `
                -Message 'A file name carries a form Windows accepts but does not store literally, so the name that is checked and the name that is opened can differ.' `
                -State (New-FileFindingState -RuleId 'TRIAGE-004' -File $file -SiteRoot $SiteRoot -Extra @{
                    anomalies = $nameAnomalies
                    sha256    = Get-TriageFileHash $file
                })
        }

        # -----------------------------------------------------------------------------
        # TRIAGE-006 - a hidden file whose name is a Unix timestamp.
        #
        # This is the shape that started the incident this script was written from: the file
        # Defender flagged was named for the second it was created. It is a marker a dropper
        # leaves so that a second stage can find its own work, and no legitimate WordPress
        # component names a file this way.
        # -----------------------------------------------------------------------------
        if ($file.Name -match '^\.\d{9,10}$') {
            [void] $candidatePaths.Add($file.FullName)

            $epoch = [long] $file.Name.Substring(1)
            $encoded = [datetimeoffset]::FromUnixTimeSeconds($epoch)

            Write-TriageFinding -Level 'Warning' `
                -Message 'A hidden file is named after a Unix timestamp. This is a dropper marker, not a WordPress artifact.' `
                -State (New-FileFindingState -RuleId 'TRIAGE-006' -File $file -SiteRoot $SiteRoot -Extra @{
                    encodedTimestampUtc = Format-TriageTimestamp $encoded
                    sha256              = Get-TriageFileHash $file
                })
        }

        # -----------------------------------------------------------------------------
        # TRIAGE-007 - created after it was last modified.
        #
        # A file whose creation time is later than its modification time was copied or rewritten
        # with a preserved timestamp. One is a backup tool. Hundreds, across a plugin tree, at a
        # steady cadence, is a mass-rewriter working through the site - which is exactly how the
        # infector in the incident became visible.
        #
        # Scoped to executable files and to the recent window, because an unfiltered version of
        # this check reports every file a migration ever touched.
        # -----------------------------------------------------------------------------
        if ($isExecutable -and
            $file.CreationTimeUtc -gt $file.LastWriteTimeUtc.AddMinutes(1) -and
            $file.CreationTimeUtc -gt $cutoff) {

            [void] $candidatePaths.Add($file.FullName)
            Write-TriageFinding -Level 'Warning' `
                -Message 'An executable file was created after the content it holds was written. At scale this is a mass-rewriter moving through the tree.' `
                -State (New-FileFindingState -RuleId 'TRIAGE-007' -File $file -SiteRoot $SiteRoot -Extra @{
                    skewSeconds = [long] ($file.CreationTimeUtc - $file.LastWriteTimeUtc).TotalSeconds
                    sha256      = Get-TriageFileHash $file
                })
        }

        # -----------------------------------------------------------------------------
        # TRIAGE-005 - PHP that can run what a request sends it.
        # -----------------------------------------------------------------------------
        $extensions = Get-ExtensionSegment $file.Name
        $isPhp = $false
        foreach ($extension in $extensions) {
            if ($script:PhpExecutableExtensions -contains $extension) { $isPhp = $true; break }
        }
        if (-not $isPhp -and (@($extensions) -contains 'inc')) { $isPhp = $true }

        if ($isPhp) {
            $text = Read-TriageFileText -File $file -Budget $MaximumFileBytes
            if ($null -ne $text) {
                $sinks = @(Get-MarkerHit -Text $text -Markers $script:ExecutionSinkMarkers)
                $inputs = @(Get-MarkerHit -Text $text -Markers $script:RequestInputMarkers)
                $obfuscation = @(Get-MarkerHit -Text $text -Markers $script:ObfuscationMarkers)

                # A sink alone is not a finding: WordPress core calls several of these. A sink
                # that a request can reach, or a sink wrapped in a decoder, is.
                $reportable =
                    (($sinks.Count -gt 0) -and ($inputs.Count -gt 0)) -or
                    (($sinks.Count -gt 0) -and ($obfuscation.Count -gt 0)) -or
                    ($obfuscation.Count -ge 4)

                if ($reportable) {
                    [void] $candidatePaths.Add($file.FullName)
                    Write-TriageFinding -Level 'Warning' `
                        -Message 'A PHP file can execute code chosen at runtime, and either a request reaches that code or it is obfuscated.' `
                        -State (New-FileFindingState -RuleId 'TRIAGE-005' -File $file -SiteRoot $SiteRoot -Extra @{
                            executionSinks = $sinks
                            requestInputs  = $inputs
                            obfuscation    = $obfuscation
                            sha256         = Get-TriageFileHash $file
                        })
                }
            }
        }
    }

    Write-Progress -Activity 'Examining files' -Completed
    return @($candidatePaths | Sort-Object -Unique)
}

<#
    TRIAGE-009 - what is installed, and at which version.

    No vulnerability database ships with this script, and none should: a list of CVEs baked into a
    file is out of date the day it is written, and an operator who trusts a stale one is worse off
    than one who looks the version up. So this reports names and versions and says where to check
    them. In the incident this script came from, that one line - LayerSlider 6.7.6 - was what
    identified the entry point.
#>
function Invoke-TriageInventory {
    param([string] $SiteRoot)

    foreach ($kind in @('plugins', 'themes')) {
        $root = Join-Path $SiteRoot ('wp-content\' + $kind)
        if (-not (Test-Path -LiteralPath $root)) { continue }

        $directories = @()
        try { $directories = @(Get-ChildItem -LiteralPath $root -Directory -ErrorAction Stop) }
        catch { $script:UnreadablePaths++; continue }

        foreach ($directory in $directories) {
            $version = $null
            $header = $null

            $candidates = @()
            try {
                $candidates = @(Get-ChildItem -LiteralPath $directory.FullName -Filter '*.php' -File -ErrorAction Stop |
                    Select-Object -First 12)
                if ($kind -eq 'themes') {
                    $styleSheet = Join-Path $directory.FullName 'style.css'
                    if (Test-Path -LiteralPath $styleSheet) {
                        $candidates = @(Get-Item -LiteralPath $styleSheet) + $candidates
                    }
                }
            }
            catch { $script:UnreadablePaths++ }

            foreach ($candidate in $candidates) {
                try {
                    $lines = Get-Content -LiteralPath $candidate.FullName -TotalCount 40 -ErrorAction Stop
                }
                catch { continue }

                $joined = $lines -join "`n"
                if ($joined -match '(?im)^\s*\*?\s*Version\s*:\s*(.+?)\s*$') {
                    $version = $Matches[1]
                    $header = $candidate.Name
                    break
                }
            }

            Write-TriageFinding -Level 'Information' `
                -Message 'Installed component. Check the version against the advisories for this component; this script ships no vulnerability database on purpose.' `
                -State @{
                    ruleId        = 'TRIAGE-009'
                    site          = $SiteRoot
                    componentKind = $kind
                    component     = $directory.Name
                    version       = $version
                    versionSource = $header
                    modifiedUtc   = Format-TriageTimestamp ([datetimeoffset] $directory.LastWriteTimeUtc)
                }
        }
    }
}

<#
    TRIAGE-010 to TRIAGE-015 - what the intruder left outside the web root.

    Everything above this point looks inside a WordPress site. That is the right scope for a tool
    named after WordPress, and it is the wrong scope for the question an operator actually has,
    which is "am I still compromised".

    A webshell is a foothold, not the whole of it. In the incident this tool comes from, the
    intruder had moved on to writing into C:\Windows\Temp - outside the web root, outside every
    check above, and untouched by stopping the site. Stopping IIS closes the door they came in by
    and does nothing about a scheduled task, a service, an autorun key or an account.

    So these read the host. They are opt-in behind -IncludeHost, because they answer a different
    question from the rest of the script and need elevation to answer it properly, and the summary
    always says whether they ran. A section that is silently absent reads exactly like a section
    that found nothing.

    Read-only, like everything else here. Nothing is disabled, deleted or repaired.
#>
function Invoke-TriageHostScan {
    $cutoff = [datetime]::UtcNow.AddDays(-$RecentDays)

    # ---------------------------------------------------------------------------------
    # TRIAGE-010 - scheduled tasks.
    #
    # The most durable persistence on Windows and the first place to look. Reported when the task
    # was registered inside the window, or when its action runs one of the interpreters that turns
    # a downloaded blob into code - regardless of when it was registered.
    # ---------------------------------------------------------------------------------
    $interpreters = 'powershell|pwsh|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|curl|wget|php'

    try {
        foreach ($task in (Get-ScheduledTask -ErrorAction Stop)) {
            $registered = $null
            try { if ($task.Date) { $registered = [datetime] $task.Date } } catch { }

            $actions = @()
            try {
                $actions = @($task.Actions | ForEach-Object {
                    (([string] $_.Execute) + ' ' + ([string] $_.Arguments)).Trim()
                })
            }
            catch { }

            $actionText = ($actions -join ' | ')
            $recent = ($null -ne $registered -and $registered.ToUniversalTime() -gt $cutoff)
            $suspicious = $actionText -match $interpreters

            if (-not $recent -and -not $suspicious) { continue }

            $reasons = New-Object System.Collections.Generic.List[string]
            if ($recent) { [void] $reasons.Add('registeredRecently') }
            if ($suspicious) { [void] $reasons.Add('runsAnInterpreter') }

            $registeredText = $null
            if ($null -ne $registered) {
                $registeredText = Format-TriageTimestamp ([datetimeoffset] $registered)
            }

            Write-TriageFinding -Level 'Warning' `
                -Message 'A scheduled task was registered recently, or runs an interpreter that can execute downloaded content. Scheduled tasks are the most durable persistence on Windows.' `
                -State @{
                    ruleId        = 'TRIAGE-010'
                    scope         = 'host'
                    taskPath      = ([string] $task.TaskPath + [string] $task.TaskName)
                    taskState     = [string] $task.State
                    registeredUtc = $registeredText
                    action        = $actionText
                    reasons       = @($reasons.ToArray())
                    author        = [string] $task.Author
                }
        }
    }
    catch {
        Write-TriageHost '  scheduled tasks could not be read; run elevated for this check.' 'Yellow'
    }

    # ---------------------------------------------------------------------------------
    # TRIAGE-011 - local accounts, and who is an administrator.
    #
    # The incident that produced this tool included an FTP account logging in mid-compromise. An
    # account is quieter than a webshell and survives every cleanup that only touches the web root.
    # ---------------------------------------------------------------------------------
    try {
        foreach ($account in (Get-LocalUser -ErrorAction Stop)) {
            $changed = $null
            try { if ($account.PasswordLastSet) { $changed = [datetime] $account.PasswordLastSet } } catch { }
            if ($null -eq $changed -or $changed.ToUniversalTime() -le $cutoff) { continue }

            $lastLogonText = $null
            try {
                if ($account.LastLogon) {
                    $lastLogonText = Format-TriageTimestamp ([datetimeoffset] $account.LastLogon)
                }
            }
            catch { }

            Write-TriageFinding -Level 'Warning' `
                -Message 'A local account had its password set inside the window. On a server nobody administers daily, that is worth explaining.' `
                -State @{
                    ruleId             = 'TRIAGE-011'
                    scope              = 'host'
                    account            = [string] $account.Name
                    enabled            = [bool] $account.Enabled
                    passwordLastSetUtc = Format-TriageTimestamp ([datetimeoffset] $changed)
                    lastLogonUtc       = $lastLogonText
                }
        }
    }
    catch {
        Write-TriageHost '  local accounts could not be read.' 'Yellow'
    }

    # Membership of the local Administrators group, resolved from its well-known SID rather than
    # its name: the group is "Administradores" on a Spanish Windows, and a check written against
    # the English name finds nothing there and says so in the reassuring direction.
    try {
        $administrators = (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate(
            [System.Security.Principal.NTAccount]).Value

        $members = @(Get-LocalGroupMember -Group $administrators -ErrorAction Stop |
            ForEach-Object { [string] $_.Name })

        Write-TriageFinding -Level 'Information' `
            -Message 'Members of the local Administrators group. Read this list and confirm every entry belongs.' `
            -State @{
                ruleId  = 'TRIAGE-011'
                scope   = 'host'
                group   = $administrators
                members = $members
            }
    }
    catch { }

    # ---------------------------------------------------------------------------------
    # TRIAGE-012 - services whose binary is somewhere a service binary has no business being.
    # ---------------------------------------------------------------------------------
    $suspectRoots = @('\temp\', '\tmp\', '\appdata\', '\users\public\', '\inetpub\', '\downloads\')

    try {
        foreach ($service in (Get-CimInstance -ClassName Win32_Service -ErrorAction Stop)) {
            $binary = [string] $service.PathName
            if ([string]::IsNullOrWhiteSpace($binary)) { continue }

            $lowered = $binary.ToLowerInvariant()
            $hit = @($suspectRoots | Where-Object { $lowered.Contains($_) })
            if ($hit.Count -eq 0) { continue }

            Write-TriageFinding -Level 'Warning' `
                -Message 'A Windows service runs a binary from a temporary, user or web directory. Legitimate services live under Program Files or System32.' `
                -State @{
                    ruleId      = 'TRIAGE-012'
                    scope       = 'host'
                    service     = [string] $service.Name
                    displayName = [string] $service.DisplayName
                    binary      = $binary
                    startMode   = [string] $service.StartMode
                    account     = [string] $service.StartName
                    matched     = @($hit)
                }
        }
    }
    catch {
        Write-TriageHost '  services could not be read.' 'Yellow'
    }

    # ---------------------------------------------------------------------------------
    # TRIAGE-013 - autorun keys.
    # ---------------------------------------------------------------------------------
    $runKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    )

    foreach ($key in $runKeys) {
        if (-not (Test-Path -LiteralPath $key)) { continue }

        $entry = $null
        try { $entry = Get-ItemProperty -LiteralPath $key -ErrorAction Stop }
        catch { continue }

        foreach ($property in $entry.PSObject.Properties) {
            if ($property.Name -like 'PS*') { continue }

            Write-TriageFinding -Level 'Information' `
                -Message 'An autorun entry. Confirm it belongs; on a server this list should be short and familiar.' `
                -State @{
                    ruleId  = 'TRIAGE-013'
                    scope   = 'host'
                    key     = $key
                    name    = [string] $property.Name
                    command = [string] $property.Value
                }
        }
    }

    # ---------------------------------------------------------------------------------
    # TRIAGE-014 - recently written code in staging directories.
    #
    # This is the check that would have found what the intruder was doing on the day this tool was
    # written: writing hidden files into C:\Windows\Temp, an hour before anybody looked. Nothing
    # under the web root sees that, which is the whole reason this section exists.
    # ---------------------------------------------------------------------------------
    $stagingDirectories = @(
        (Join-Path $env:windir 'Temp'),
        (Join-Path $env:SystemDrive 'Temp'),
        (Join-Path $env:SystemDrive 'tmp'),
        $env:TEMP,
        (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\StartUp')
    )

    $codeExtensions = @('exe', 'dll', 'ps1', 'bat', 'cmd', 'vbs', 'js', 'jse', 'wsf', 'hta', 'scr', 'php', 'jar')

    foreach ($directory in ($stagingDirectories | Sort-Object -Unique)) {
        if ([string]::IsNullOrWhiteSpace($directory)) { continue }
        if (-not (Test-Path -LiteralPath $directory)) { continue }

        $entries = @()
        try { $entries = @(Get-ChildItem -LiteralPath $directory -Force -File -ErrorAction Stop) }
        catch { continue }

        foreach ($file in $entries) {
            $isCode = $false
            foreach ($extension in (Get-ExtensionSegment $file.Name)) {
                if ($codeExtensions -contains $extension) { $isCode = $true; break }
            }

            # The dropper marker from the incident: a hidden file named for the second it was
            # created. It has no extension at all, so the check above cannot see it.
            $isMarker = $file.Name -match '^\.\d{9,10}$'

            if (-not $isCode -and -not $isMarker) { continue }
            if ($file.LastWriteTimeUtc -le $cutoff -and $file.CreationTimeUtc -le $cutoff) { continue }

            Write-TriageFinding -Level 'Warning' `
                -Message 'Executable content was written recently into a staging directory. Stopping a website does not touch anything here.' `
                -State @{
                    ruleId      = 'TRIAGE-014'
                    scope       = 'host'
                    path        = $file.FullName
                    sizeBytes   = [long] $file.Length
                    createdUtc  = Format-TriageTimestamp ([datetimeoffset] $file.CreationTimeUtc)
                    modifiedUtc = Format-TriageTimestamp ([datetimeoffset] $file.LastWriteTimeUtc)
                    sha256      = Get-TriageFileHash $file
                    marker      = $isMarker
                }
        }
    }

    # ---------------------------------------------------------------------------------
    # TRIAGE-015 - what the antivirus already knows.
    #
    # Defender's own history is evidence somebody else already collected, and it is the one source
    # here that can name a threat family rather than describing a shape.
    # ---------------------------------------------------------------------------------
    try {
        foreach ($detection in (Get-MpThreat -ErrorAction Stop)) {
            $detectedText = $null
            try {
                if ($detection.InitialDetectionTime) {
                    $detectedText = Format-TriageTimestamp ([datetimeoffset] $detection.InitialDetectionTime)
                }
            }
            catch { }

            Write-TriageFinding -Level 'Warning' `
                -Message 'Microsoft Defender has a record of this threat on the host.' `
                -State @{
                    ruleId          = 'TRIAGE-015'
                    scope           = 'host'
                    threat          = [string] $detection.ThreatName
                    severity        = [string] $detection.SeverityID
                    active          = [bool] $detection.IsActive
                    resources       = @(@($detection.Resources) | Select-Object -First 8 | ForEach-Object { [string] $_ })
                    firstDetectedUtc = $detectedText
                }
        }
    }
    catch {
        Write-TriageHost '  Defender history could not be read.' 'Yellow'
    }
}

<#
    TRIAGE-008 - what the IIS logs remember about each flagged artifact.

    A suspicious file is a hypothesis. The log line that shows it answering a request, the day it
    started answering, and the addresses that asked, is the evidence. This is the step that turns
    "there is a PHP file in uploads" into "it has been reachable since February 2021 and two
    addresses have been using it", which is a different conversation.

    The logs are read once into a lookup keyed by request path, rather than searched once per
    candidate, because a web root with thirty findings and a year of logs would otherwise be
    thirty full passes over several gigabytes.
#>
function Invoke-TriageLogCorrelation {
    param(
        [string] $LogRoot,
        [string] $SiteRoot,
        [string[]] $CandidatePaths
    )

    if ([string]::IsNullOrWhiteSpace($LogRoot) -or -not (Test-Path -LiteralPath $LogRoot)) {
        Write-TriageHost ('No IIS logs at: ' + $LogRoot + ' - skipping request correlation.') 'Yellow'
        return
    }

    if ($CandidatePaths.Count -eq 0) { return }

    $wanted = @{}
    $records = New-Object System.Collections.Generic.List[object]

    foreach ($path in $CandidatePaths) {
        $relative = $path.Substring($SiteRoot.Length).TrimStart('\', '/')
        $requestPath = ('/' + ($relative -replace '\\', '/')).ToLowerInvariant()

        $record = [pscustomobject] @{
            Path        = $path
            RequestPath = $requestPath
            Count       = 0
            First       = $null
            Last        = $null
            Clients     = New-Object System.Collections.Generic.HashSet[string]
            Statuses    = New-Object System.Collections.Generic.HashSet[string]
            Methods     = New-Object System.Collections.Generic.HashSet[string]
        }
        $records.Add($record)

        # Two keys for one record. IIS writes cs-uri-stem percent-encoded, so a file whose name
        # contains a space - which WordPress upload names do constantly - is logged as
        # /wp-content/uploads/my%20file.php and would never match the name read off the disk.
        # Matching only the literal form would silently lose the request history of exactly the
        # files most likely to have one.
        $wanted[$requestPath] = $record

        $encoded = (@($requestPath.Split('/') | ForEach-Object {
            [Uri]::EscapeDataString($_)
        }) -join '/').ToLowerInvariant()

        if ($encoded -ne $requestPath) { $wanted[$encoded] = $record }
    }

    $cutoff = [datetime]::UtcNow.AddDays(-$RecentDays)
    $logFiles = @()
    try {
        $logFiles = @(Get-ChildItem -LiteralPath $LogRoot -Recurse -Filter '*.log' -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTimeUtc -gt $cutoff } |
            Sort-Object LastWriteTimeUtc -Descending)
    }
    catch { $script:UnreadablePaths++ }

    if ($logFiles.Count -eq 0) {
        Write-TriageHost ('No IIS log files written in the last ' + $RecentDays + ' days under: ' + $LogRoot) 'Yellow'
        return
    }

    $bytesRead = [long] 0
    $filesRead = 0

    foreach ($logFile in $logFiles) {
        if ($bytesRead -ge $MaximumLogBytes) { break }
        $bytesRead += $logFile.Length
        $filesRead++

        Write-Progress -Activity 'Reading IIS logs' -Status $logFile.Name `
            -PercentComplete ([Math]::Min(100, (100.0 * $filesRead / $logFiles.Count)))

        # Column order is not fixed: it is whatever the site's logging configuration selected, and
        # it is restated by a #Fields directive whenever it changes mid-file. Reading the
        # directive is the only correct way to find cs-uri-stem; counting from the left is how a
        # log parser silently reports the wrong column for a year.
        $fields = @()
        $indexDate = -1; $indexTime = -1; $indexStem = -1
        $indexClient = -1; $indexStatus = -1; $indexMethod = -1

        try {
            $reader = [System.IO.File]::Open(
                $logFile.FullName,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read,
                [System.IO.FileShare]::ReadWrite)
            $streamReader = New-Object System.IO.StreamReader($reader)
        }
        catch {
            $script:UnreadablePaths++
            continue
        }

        try {
            while ($null -ne ($line = $streamReader.ReadLine())) {
                if ($line.StartsWith('#')) {
                    if ($line.StartsWith('#Fields:')) {
                        $fields = @($line.Substring(8).Trim() -split '\s+')
                        $indexDate = [array]::IndexOf($fields, 'date')
                        $indexTime = [array]::IndexOf($fields, 'time')
                        $indexStem = [array]::IndexOf($fields, 'cs-uri-stem')
                        $indexClient = [array]::IndexOf($fields, 'c-ip')
                        $indexStatus = [array]::IndexOf($fields, 'sc-status')
                        $indexMethod = [array]::IndexOf($fields, 'cs-method')
                    }
                    continue
                }

                if ($indexStem -lt 0) { continue }

                $columns = $line.Split(' ')
                if ($columns.Length -le $indexStem) { continue }

                $stem = $columns[$indexStem].ToLowerInvariant()
                if (-not $wanted.ContainsKey($stem)) { continue }

                $record = $wanted[$stem]
                $record.Count++

                if ($indexDate -ge 0 -and $indexTime -ge 0 -and $columns.Length -gt $indexTime) {
                    $stamp = $columns[$indexDate] + ' ' + $columns[$indexTime]
                    if ($null -eq $record.First -or $stamp -lt $record.First) { $record.First = $stamp }
                    if ($null -eq $record.Last -or $stamp -gt $record.Last) { $record.Last = $stamp }
                }

                if ($indexClient -ge 0 -and $columns.Length -gt $indexClient -and $record.Clients.Count -lt 64) {
                    [void] $record.Clients.Add($columns[$indexClient])
                }
                if ($indexStatus -ge 0 -and $columns.Length -gt $indexStatus) {
                    [void] $record.Statuses.Add($columns[$indexStatus])
                }
                if ($indexMethod -ge 0 -and $columns.Length -gt $indexMethod) {
                    [void] $record.Methods.Add($columns[$indexMethod])
                }
            }
        }
        finally {
            $streamReader.Dispose()
            $reader.Dispose()
        }
    }

    Write-Progress -Activity 'Reading IIS logs' -Completed

    # Iterating the records rather than the keys, because two keys can name the same record and a
    # file whose name needed encoding would otherwise be reported twice.
    foreach ($record in $records) {
        if ($record.Count -eq 0) { continue }

        Write-TriageFinding -Level 'Warning' `
            -Message 'A flagged artifact has been answering HTTP requests. These are the requests that reached it, from the logs.' `
            -State @{
                ruleId       = 'TRIAGE-008'
                site         = $SiteRoot
                path         = $record.Path
                requestPath  = $record.RequestPath
                requestCount = [long] $record.Count
                firstSeen    = $record.First
                lastSeen     = $record.Last
                clients      = @($record.Clients)
                statuses     = @($record.Statuses | Sort-Object)
                methods      = @($record.Methods | Sort-Object)
                logBytesRead = $bytesRead
            }
    }

    if ($bytesRead -ge $MaximumLogBytes) {
        Write-TriageHost ('The log budget of ' + $MaximumLogBytes + ' bytes was reached; older logs were not read. Raise -MaximumLogBytes to read further back.') 'Yellow'
    }
}

# =====================================================================================
#  Main.
# =====================================================================================

Write-TriageHost ''
Write-TriageHost 'WPShield triage - read-only. Nothing is deleted, quarantined, repaired or executed.' 'Cyan'
Write-TriageHost ('Host: ' + $env:COMPUTERNAME + '    Started: ' + (Format-TriageTimestamp ([datetimeoffset]::UtcNow)))

$sites = @()
if ($null -ne $SitePath -and $SitePath.Count -gt 0) {
    foreach ($candidate in $SitePath) {
        if (-not (Test-Path -LiteralPath $candidate)) {
            throw ("Site path does not exist: " + $candidate)
        }
        $resolved = (Resolve-Path -LiteralPath $candidate).ProviderPath
        if (-not (Test-WordPressRoot $resolved)) {
            Write-TriageHost ('Warning: no wp-config.php or wp-includes under ' + $resolved + '. Scanning it anyway.') 'Yellow'
        }
        $sites += $resolved
    }
}
else {
    Write-TriageHost 'No -SitePath given. Asking IIS what it serves.'
    $sites = Find-TriageSite
}

if ($sites.Count -eq 0) {
    Write-TriageHost 'No WordPress installation found. Pass -SitePath explicitly.' 'Red'
    return
}

Write-TriageHost ''
Write-TriageHost 'Sites to examine:' 'Cyan'
foreach ($site in $sites) {
    $version = Get-WordPressVersion $site
    if ($null -eq $version) { $version = 'unknown' }
    Write-TriageHost ('  ' + $site + '   (WordPress ' + $version + ')')
}

if ($DiscoverOnly) {
    Write-TriageHost ''
    Write-TriageHost 'Discovery only. Nothing was scanned. Re-run without -DiscoverOnly to triage these.' 'Cyan'
    return
}

if (-not $PSBoundParameters.ContainsKey('IisLogPath')) {
    $IisLogPath = 'C:\inetpub\logs\LogFiles'
}

$outputDirectory = Split-Path -Parent $OutputPath
if ([string]::IsNullOrWhiteSpace($outputDirectory)) { $outputDirectory = (Get-Location).ProviderPath }
if (-not (Test-Path -LiteralPath $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

# UTF-8 without a byte order mark. Every value written has already been escaped into the
# printable ASCII range, so these bytes are ASCII bytes and any reader decodes them identically.
$script:Writer = New-Object System.IO.StreamWriter(
    $OutputPath,
    $false,
    (New-Object System.Text.UTF8Encoding($false)))

try {
    foreach ($site in $sites) {
        Write-TriageHost ''
        Write-TriageHost ('Scanning ' + $site) 'Cyan'

        $files = Get-TriageFile -Root $site -Limit $MaximumFilesScanned
        Write-TriageHost ('  files enumerated: ' + $files.Count)

        if ($files.Count -ge $MaximumFilesScanned) {
            Write-TriageHost ('  the file limit of ' + $MaximumFilesScanned + ' was reached; this site was not fully examined.') 'Yellow'
        }

        $candidates = Invoke-TriageSiteScan -SiteRoot $site -Files $files
        Write-TriageHost ('  artifacts flagged: ' + $candidates.Count)

        Invoke-TriageInventory -SiteRoot $site

        if (-not [string]::IsNullOrWhiteSpace($IisLogPath)) {
            Invoke-TriageLogCorrelation -LogRoot $IisLogPath -SiteRoot $site -CandidatePaths $candidates
        }
    }

    # Once for the machine, not once per site: persistence belongs to the host.
    if ($IncludeHost) {
        Write-TriageHost ''
        Write-TriageHost 'Scanning the host: tasks, accounts, services, autoruns, staging directories' 'Cyan'
        Invoke-TriageHostScan
    }
}
finally {
    $script:Writer.Flush()
    $script:Writer.Dispose()
    $script:Writer = $null
}

# =====================================================================================
#  Summary.
# =====================================================================================

$warnings = @($script:Findings | Where-Object { $_.Level -eq 'Warning' })

# The coverage question is asked only of executable artifacts, because it is a question about a
# rule family that decides whether to refuse a request that would reach code. Folding a marker
# file or a web.config into the answer would make the one number a reader acts on mean less.
$fileFindings = @($warnings | Where-Object { $null -ne $_.Verdict -and $_.Verdict -ne 'not-applicable' })
$blocked = @($fileFindings | Where-Object { $_.Verdict -eq 'blocked' })
$observed = @($fileFindings | Where-Object { $_.Verdict -eq 'observed' })
$uncovered = @($fileFindings | Where-Object { $_.Verdict -eq 'not-covered' })
$notApplicable = @($warnings | Where-Object { $_.Verdict -eq 'not-applicable' })

Write-TriageHost ''
Write-TriageHost '================================================================================' 'Cyan'
Write-TriageHost ' Summary' 'Cyan'
Write-TriageHost '================================================================================' 'Cyan'
Write-TriageHost ('Findings written: ' + $script:Findings.Count + '   ->  ' + $OutputPath)
Write-TriageHost ('Warnings: ' + $warnings.Count)

if ($script:UnreadablePaths -gt 0) {
    Write-TriageHost ($script:UnreadablePaths.ToString() + ' path(s) could not be read. Re-run elevated for a complete picture.') 'Yellow'
}
if ($script:FindingsTruncated) {
    Write-TriageHost ('The finding limit of ' + $MaximumFindings + ' was reached. The report is incomplete; raise -MaximumFindings.') 'Yellow'
}

if ($warnings.Count -gt 0) {
    Write-TriageHost ''
    $script:Findings |
        Where-Object { $_.Level -eq 'Warning' } |
        Group-Object RuleId |
        Sort-Object Name |
        Format-Table @{ Label = 'Rule'; Expression = { $_.Name } },
                     @{ Label = 'Findings'; Expression = { $_.Count } } -AutoSize |
        Out-String -Width 80 |
        Write-Host
}

# The number this script exists to print.
if ($fileFindings.Count -gt 0) {
    Write-TriageHost 'Would WPShield refuse a request to the executable artifacts above?' 'Cyan'
    Write-TriageHost ('  blocked outright: ' + $blocked.Count)
    Write-TriageHost ('  scored but forwarded: ' + $observed.Count)
    Write-TriageHost ('  not covered by any request-path rule: ' + $uncovered.Count) $(if ($uncovered.Count -gt 0) { 'Yellow' } else { 'Gray' })

    if ($notApplicable.Count -gt 0) {
        Write-TriageHost ('  (' + $notApplicable.Count + ' further artifact(s) are not executable; a request-path rule is not the control that covers them.)')
    }

    if ($uncovered.Count -gt 0) {
        Write-TriageHost ''
        Write-TriageHost 'WPShield would forward a request to each of these. Gateway coverage is not containment:' 'Yellow'
        foreach ($finding in ($uncovered | Select-Object -First 25)) {
            Write-TriageHost ('  ' + $finding.Path)
        }
        if ($uncovered.Count -gt 25) {
            Write-TriageHost ('  ... and ' + ($uncovered.Count - 25) + ' more, in the report.')
        }
    }
}

if ($IncludeHost) {
    $hostFindings = @($script:Findings | Where-Object { $_.RuleId -like 'TRIAGE-01*' })
    Write-TriageHost ''
    Write-TriageHost ('Host checks ran: ' + $hostFindings.Count + ' finding(s) outside the web root.') 'Cyan'
}
else {
    Write-TriageHost ''
    Write-TriageHost 'Host checks did NOT run. Nothing here says anything about scheduled tasks, accounts,' 'Yellow'
    Write-TriageHost 'services, autorun keys or staging directories. Stopping a site does not touch any of' 'Yellow'
    Write-TriageHost 'those. Re-run elevated with -IncludeHost.' 'Yellow'
}

Write-TriageHost ''
if ($warnings.Count -eq 0) {
    Write-TriageHost 'Nothing was flagged. That is not a clean bill of health: this script reads what is on disk today, and an intruder who cleaned up leaves a disk that looks like this one.' 'Green'
}
else {
    Write-TriageHost 'Findings are a starting point, not a verdict. Read each file yourself before acting on it.' 'Yellow'
    Write-TriageHost 'The report deliberately contains no file contents, so it is safe to attach to an issue or a support thread.'
}

Write-TriageHost ''
Write-TriageHost ('Report: ' + $OutputPath) 'Green'
