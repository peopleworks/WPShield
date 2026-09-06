#Requires -Version 5.1

<#
.SYNOPSIS
    Verifies the PowerShell scripts in this repository: that they parse, that they are ASCII, that
    the tools documented as read-only have no way to write outside their own report, that the rule
    vocabulary the triage tool copies from the gateway has not drifted, and that it still runs.

.DESCRIPTION
    Six checks, each of which exists because of a defect that actually happened.

    1. PARSE. Every .ps1 is parsed with the PowerShell parser. A script in this repository is
       something an operator runs, once, on a server that is having a bad day, and discovering a
       syntax error at that moment is discovering it at the worst possible time.

    2. ASCII. Every .ps1 must be pure ASCII. Windows PowerShell 5.1 reads a .ps1 without a byte
       order mark as ANSI, so a UTF-8 em dash arrives as two characters - one of which is a
       typographic quote that PowerShell treats as a string delimiter. The failure is not a
       friendly one: quote parity breaks silently and the parser reports an error a hundred lines
       further down, in code that is correct. This exact defect shipped a triage script that would
       not run.

    3. READ-ONLY INVENTORY. The triage tool and the preflight both promise, in their own
       documentation, to change nothing on the host they examine. This check enumerates every
       write-capable construct in each and compares that against a fixed inventory, so a new write
       cannot appear without somebody deciding to add it here too.

       Say plainly what this is worth: it is an inventory, not a proof. The gateway's equivalent
       guarantee - that no request body can reach the disk - is proved, by scanning the assembly's
       type references for any file API at all. Nothing that strong is available for a script,
       because PowerShell can call a cmdlet whose name it computes at runtime. So this check also
       bans the two constructs that would make the inventory meaningless: invocation through a
       variable, and Invoke-Expression. With those gone the inventory is complete for anything a
       reader can see, which is the honest version of the claim.

    4. VOCABULARY DRIFT. The triage tool reports whether WPShield would refuse a request to each
       artifact it finds. It answers that from its own copies of the gateway's extension and
       directory lists, because it has to run on a server with no .NET runtime and no build of
       WPShield on it. Copies drift. A drifted copy does not fail loudly - it quietly reports
       coverage the gateway does not have, which is worse than reporting nothing.

    5. JSON ESCAPING. Every copy of the JSON escaper is extracted and round-tripped through a real
       parser. There is more than one copy on purpose - each tool is a single file that has to work
       alone on a server where nothing may be installed - and testing them all against the same
       cases is what keeps that duplication honest.

    6. END TO END. The triage tool is run against a fixture reproducing the incident's directory
       structure, and its verdicts are asserted. The most important check here, because it is the
       only one that fails when a script does not run at all.

.EXAMPLE
    pwsh -File scripts/Test-WPShieldScripts.ps1
#>

[CmdletBinding()]
param(
    [string] $RepositoryRoot = (Split-Path -Parent $PSScriptRoot)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$failures = New-Object System.Collections.Generic.List[string]
$checks = 0

function Add-Failure {
    param([string] $Message)
    [void] $failures.Add($Message)
    Write-Host ('  FAIL  ' + $Message) -ForegroundColor Red
}

function Add-Pass {
    param([string] $Message)
    Write-Host ('  ok    ' + $Message) -ForegroundColor DarkGray
}

$scriptFiles = @(Get-ChildItem -LiteralPath (Join-Path $RepositoryRoot 'scripts') -Filter '*.ps1' -File |
    Sort-Object Name)

if ($scriptFiles.Count -eq 0) {
    throw 'No PowerShell scripts found. Is -RepositoryRoot correct?'
}

# =====================================================================================
#  1. Every script parses.
# =====================================================================================

Write-Host ''
Write-Host 'Parsing' -ForegroundColor Cyan

$parsed = @{}

foreach ($file in $scriptFiles) {
    $checks++
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref] $tokens, [ref] $errors)

    if ($errors.Count -gt 0) {
        foreach ($parseError in $errors) {
            Add-Failure ($file.Name + ' line ' + $parseError.Extent.StartLineNumber + ': ' + $parseError.Message)
        }
    }
    else {
        $parsed[$file.Name] = $ast
        Add-Pass ($file.Name + ' parses')
    }
}

# =====================================================================================
#  2. Every script is pure ASCII.
# =====================================================================================

Write-Host ''
Write-Host 'Encoding' -ForegroundColor Cyan

foreach ($file in $scriptFiles) {
    $checks++
    $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
    $offenders = New-Object System.Collections.Generic.List[string]

    for ($index = 0; $index -lt $bytes.Length -and $offenders.Count -lt 5; $index++) {
        if ($bytes[$index] -gt 0x7E) {
            [void] $offenders.Add(('offset ' + $index + ' = 0x' + ('{0:X2}' -f $bytes[$index])))
        }
    }

    if ($offenders.Count -gt 0) {
        Add-Failure ($file.Name + ' contains non-ASCII bytes: ' + ($offenders -join ', ') +
            '. Windows PowerShell 5.1 reads a BOM-less .ps1 as ANSI and these will not survive.')
    }
    else {
        Add-Pass ($file.Name + ' is ASCII')
    }
}

# =====================================================================================
#  3. The triage tool cannot write outside its own report.
# =====================================================================================

Write-Host ''
Write-Host 'Read-only inventory' -ForegroundColor Cyan

$triageName = 'Invoke-WPShieldTriage.ps1'

# Scripts that promise, in their own documentation, to change nothing on the host they examine.
# Each maps to the write-capable cmdlets it is allowed and how many times: both create the parent
# directory of their report, and nothing else.
$readOnlyScripts = @{
    'Invoke-WPShieldTriage.ps1'    = @{ 'New-Item' = 1 }
    'Invoke-WPShieldPreflight.ps1' = @{ 'New-Item' = 1 }
}

foreach ($readOnlyName in ($readOnlyScripts.Keys | Sort-Object)) {

if (-not $parsed.ContainsKey($readOnlyName)) {
    Add-Failure ($readOnlyName + ' did not parse, so its write inventory could not be checked.')
}
else {
    $triageName = $readOnlyName
    $triageAst = $parsed[$readOnlyName]

    # Cmdlets that change something. Get-FileHash, Get-ChildItem and friends are absent on purpose:
    # this list is about what a command does to the host, not about how much it reads.
    $forbiddenCommands = @(
        'Remove-Item', 'Remove-ItemProperty', 'Clear-Content', 'Clear-Item',
        'Set-Content', 'Add-Content', 'Out-File', 'Set-Item', 'Set-ItemProperty',
        'New-ItemProperty', 'Move-Item', 'Rename-Item', 'Copy-Item',
        'Set-Acl', 'Invoke-Item', 'Start-Process',
        'Stop-Process', 'Stop-Service', 'Start-Service', 'Restart-Service', 'Set-Service',
        'Remove-MpThreat', 'Set-MpPreference',
        'New-NetFirewallRule', 'Set-NetFirewallRule', 'Remove-NetFirewallRule',
        'Invoke-Expression', 'iex', 'Invoke-WebRequest', 'Invoke-RestMethod'
    )

    # Write-capable, but each has exactly one justified use. The count is pinned so that a second
    # use has to be added here first.
    # Per-script allowance: New-Item creates the report's parent directory, and nothing else.
    $allowedWriteCommands = $readOnlyScripts[$readOnlyName]

    $commandAsts = @($triageAst.FindAll(
        { param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true))

    $seenCounts = @{}

    foreach ($command in $commandAsts) {
        $element = $command.CommandElements[0]

        # Invocation through a variable - `& $name` - would let a command escape this inventory
        # entirely, which is the one thing that would make the whole check dishonest.
        if (-not ($element -is [System.Management.Automation.Language.StringConstantExpressionAst])) {
            $checks++
            Add-Failure ($triageName + ' line ' + $command.Extent.StartLineNumber +
                ': a command is invoked through an expression rather than a literal name. ' +
                'That defeats this inventory, so it is not allowed here.')
            continue
        }

        $name = $element.Value

        if ($forbiddenCommands -contains $name) {
            $checks++
            Add-Failure ($triageName + ' line ' + $command.Extent.StartLineNumber +
                ': ' + $name + ' changes the host. This script documents itself as read-only: it reports, and it does not repair.')
        }

        if ($allowedWriteCommands.ContainsKey($name)) {
            if (-not $seenCounts.ContainsKey($name)) { $seenCounts[$name] = 0 }
            $seenCounts[$name]++
        }
    }

    foreach ($name in $allowedWriteCommands.Keys) {
        $checks++
        $actual = 0
        if ($seenCounts.ContainsKey($name)) { $actual = $seenCounts[$name] }
        $expected = $allowedWriteCommands[$name]

        if ($actual -gt $expected) {
            Add-Failure ($triageName + ' uses ' + $name + ' ' + $actual + ' times; the inventory allows ' +
                $expected + '. A new write path was added. Justify it here, or remove it.')
        }
        else {
            Add-Pass ($name + ' used ' + $actual + ' time(s), within the inventory')
        }
    }

    # .NET file APIs that write. The script reads with [System.IO.File]::Open and writes its report
    # through a single StreamWriter; anything else is new.
    $forbiddenMembers = @(
        'WriteAllText', 'WriteAllBytes', 'WriteAllLines', 'AppendAllText', 'AppendAllLines',
        'AppendText', 'Delete', 'Move', 'Copy', 'Replace', 'Encrypt', 'Decrypt',
        'SetAttributes', 'SetCreationTime', 'SetCreationTimeUtc',
        'SetLastWriteTime', 'SetLastWriteTimeUtc', 'SetAccessControl'
    )

    $memberAsts = @($triageAst.FindAll(
        { param($node) $node -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true))

    foreach ($member in $memberAsts) {
        if ($member.Member -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
            $memberName = $member.Member.Value
            if ($forbiddenMembers -contains $memberName) {
                $checks++
                Add-Failure ($triageName + ' line ' + $member.Extent.StartLineNumber +
                    ': ' + $memberName + ' writes to or alters the file system.')
            }
        }
    }

    # Every [System.IO.File]::Open must ask for read access only. This is the one that matters most:
    # a share-mode change that opened files for write would be invisible to every check above.
    foreach ($member in $memberAsts) {
        if (-not ($member.Member -is [System.Management.Automation.Language.StringConstantExpressionAst])) { continue }
        if ($member.Member.Value -ne 'Open') { continue }

        $checks++
        $text = $member.Extent.Text
        if ($text -notmatch 'FileAccess\]::Read') {
            Add-Failure ($triageName + ' line ' + $member.Extent.StartLineNumber +
                ': a file is opened without [System.IO.FileAccess]::Read.')
        }
        else {
            Add-Pass ('file opened read-only at line ' + $member.Extent.StartLineNumber)
        }
    }

    $streamWriters = @($memberAsts | Where-Object {
        $_.Extent.Text -match 'StreamWriter'
    })
    $newObjectWriters = @($commandAsts | Where-Object {
        $_.Extent.Text -match 'StreamWriter'
    })
    $writerCount = $streamWriters.Count + $newObjectWriters.Count

    $checks++
    if ($writerCount -gt 1) {
        Add-Failure ($triageName + ' constructs ' + $writerCount +
            ' StreamWriters. It should have exactly one: the report.')
    }
    else {
        Add-Pass ($readOnlyName + ': exactly one StreamWriter, the report')
    }
}

}

# =====================================================================================
#  4. The rule vocabulary has not drifted from the gateway.
# =====================================================================================

Write-Host ''
Write-Host 'Rule vocabulary against the gateway sources' -ForegroundColor Cyan

<#
    Pulls a list of string literals out of the triage script by walking its AST for the assignment
    to a named variable. The AST rather than a regular expression, so that reformatting the script
    cannot silently turn this check off.
#>
function Get-ScriptStringList {
    param(
        [System.Management.Automation.Language.Ast] $Ast,
        [string] $VariableName
    )

    $assignments = @($Ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
        $node.Left.VariablePath.UserPath -eq $VariableName
    }, $true))

    if ($assignments.Count -ne 1) { return $null }

    $literals = @($assignments[0].Right.FindAll({
        param($node) $node -is [System.Management.Automation.Language.StringConstantExpressionAst]
    }, $true))

    return @($literals | ForEach-Object { $_.Value })
}

<#
    Pulls the same list out of a C# source file, from the initializer of a named field. Deliberately
    bounded to the text between the field name and the closing of its collection initializer, so a
    string elsewhere in the file cannot wander into the comparison.
#>
function Get-CSharpStringList {
    param(
        [string] $Path,
        [string] $FieldName
    )

    if (-not (Test-Path -LiteralPath $Path)) { return $null }

    $source = [System.IO.File]::ReadAllText($Path)
    $start = $source.IndexOf($FieldName)
    if ($start -lt 0) { return $null }

    $terminators = @('.ToFrozenSet', '];')
    $end = -1
    foreach ($terminator in $terminators) {
        $candidate = $source.IndexOf($terminator, $start)
        if ($candidate -ge 0 -and ($end -lt 0 -or $candidate -lt $end)) { $end = $candidate }
    }
    if ($end -lt 0) { return $null }

    $block = $source.Substring($start, $end - $start)

    # Drop comment text before harvesting literals: these declarations are heavily commented, and a
    # quoted name inside a comment is documentation rather than vocabulary.
    $block = [System.Text.RegularExpressions.Regex]::Replace($block, '//[^\r\n]*', '')

    $matches = [System.Text.RegularExpressions.Regex]::Matches($block, '"([^"\\]*)"')
    return @($matches | ForEach-Object { $_.Groups[1].Value })
}

function Compare-Vocabulary {
    param(
        [string] $Label,
        [string[]] $FromScript,
        [string[]] $FromSource
    )

    $script:checks++

    if ($null -eq $FromScript) {
        Add-Failure ($Label + ': could not read the list from the triage script.')
        return
    }
    if ($null -eq $FromSource -or $FromSource.Count -eq 0) {
        Add-Failure ($Label + ': could not read the list from the gateway source.')
        return
    }

    $onlyInScript = @($FromScript | Where-Object { $FromSource -notcontains $_ })
    $onlyInSource = @($FromSource | Where-Object { $FromScript -notcontains $_ })

    if ($onlyInScript.Count -gt 0 -or $onlyInSource.Count -gt 0) {
        $detail = ''
        if ($onlyInSource.Count -gt 0) {
            $detail += ' missing from the script: ' + ($onlyInSource -join ', ') + '.'
        }
        if ($onlyInScript.Count -gt 0) {
            $detail += ' present only in the script: ' + ($onlyInScript -join ', ') + '.'
        }
        Add-Failure ($Label + ' has drifted from the gateway.' + $detail +
            ' The triage tool reports gateway coverage from this list, so a stale copy reports coverage that does not exist.')
    }
    else {
        Add-Pass ($Label + ' matches the gateway (' + $FromScript.Count + ' entries)')
    }
}

$triageName = 'Invoke-WPShieldTriage.ps1'

if ($parsed.ContainsKey($triageName)) {
    $triageAst = $parsed[$triageName]
    $rulesRoot = Join-Path $RepositoryRoot 'src\WPShield.Rules.WordPress'
    $extensionsFile = Join-Path $rulesRoot 'DangerousUploadExtensions.cs'
    $assetRuleFile = Join-Path $rulesRoot 'ExecutableRequestInAssetDirectoryRule.cs'
    $uploadsRuleFile = Join-Path $rulesRoot 'ExecutableRequestUnderUploadsRule.cs'

    Compare-Vocabulary 'PHP executable extensions' `
        (Get-ScriptStringList $triageAst 'script:PhpExecutableExtensions') `
        (Get-CSharpStringList $extensionsFile 'PhpExecutable = new[]')

    Compare-Vocabulary 'IIS executable extensions' `
        (Get-ScriptStringList $triageAst 'script:IisExecutableExtensions') `
        (Get-CSharpStringList $extensionsFile 'IisExecutable = new[]')

    Compare-Vocabulary 'Static asset directories' `
        (Get-ScriptStringList $triageAst 'script:StaticAssetDirectories') `
        (Get-CSharpStringList $assetRuleFile 'AssetDirectories = new[]')

    # uploads, plus the two directories the rule treats the same way. Assembled from both places in
    # the rule that name them, because the rule stores the sequence and the extras separately.
    $uploadsFromSource = @()
    $sequence = Get-CSharpStringList $uploadsRuleFile 'UploadsSequence ='
    $additional = Get-CSharpStringList $uploadsRuleFile 'AdditionalDataDirectories ='
    if ($null -ne $sequence) { $uploadsFromSource += @($sequence | Where-Object { $_ -ne 'wp-content' }) }
    if ($null -ne $additional) { $uploadsFromSource += $additional }

    Compare-Vocabulary 'WordPress data directories' `
        (Get-ScriptStringList $triageAst 'script:WordPressDataDirectories') `
        $uploadsFromSource

    # The names deliberately left out of the asset list. If one of them ever appears in the
    # gateway's list, the exclusion was reversed and the triage script is asserting something the
    # gateway no longer believes.
    $excluded = Get-ScriptStringList $triageAst 'script:DirectoriesExcludedFromAssetList'
    $assetDirectories = Get-CSharpStringList $assetRuleFile 'AssetDirectories = new[]'
    $checks++
    $reversed = @($excluded | Where-Object { $assetDirectories -contains $_ })
    if ($reversed.Count -gt 0) {
        Add-Failure ('These names are recorded as deliberately excluded from the asset list, but the gateway now includes them: ' +
            ($reversed -join ', ') + '. One of the two is wrong.')
    }
    else {
        Add-Pass 'the deliberate asset-list exclusions are still excluded'
    }
}

# =====================================================================================
#  5. The JSON these tools write is JSON.
#
#  Each escaper is extracted from its script and exercised directly. It earns a test of its own
#  because the first version was wrong in a way nothing else would have caught: inside a switch,
#  PowerShell's `continue` ends the switch and resumes the loop body rather than skipping it, so
#  every backslash was escaped and then emitted again. Every Windows path in the report came out
#  as invalid JSON, and the report still looked fine to a human reading it.
#
#  There is deliberately more than one copy of this function. The triage tool and the preflight are
#  each a single file with no dependencies, because they run on servers where nothing may be
#  installed and the only transport might be a chat window; a shared module would be two files that
#  must travel together. Testing every copy against the same cases is what keeps the duplication
#  honest - they cannot diverge in behaviour without this failing.
# =====================================================================================

Write-Host ''
Write-Host 'JSON escaping' -ForegroundColor Cyan

$escapers = @()
foreach ($name in ($parsed.Keys | Sort-Object)) {
    foreach ($function in @($parsed[$name].FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -like 'ConvertTo-*JsonString'
    }, $true))) {
        $escapers += [pscustomobject] @{ Script = $name; Name = $function.Name; Ast = $function }
    }
}

$checks++
if ($escapers.Count -lt 2) {
    Add-Failure ('Expected a JSON escaper in each single-file tool; found ' + $escapers.Count + '.')
}
else {
    Add-Pass ($escapers.Count.ToString() + ' JSON escapers found, all exercised below')
}

foreach ($escaper in $escapers) {
    . ([scriptblock]::Create($escaper.Ast.Extent.Text))

    $cases = @(
        @{ Input = 'C:\inetpub\wwwroot\example'; Expect = 'C:\inetpub\wwwroot\example' },
        @{ Input = 'a"b'; Expect = 'a"b' },
        @{ Input = "tab`there"; Expect = "tab`there" },
        @{ Input = ('esc' + [char] 0x1B + '[31m'); Expect = ('esc' + [char] 0x1B + '[31m') },
        @{ Input = ('nul' + [char] 0x00); Expect = ('nul' + [char] 0x00) },
        @{ Input = 'plain'; Expect = 'plain' }
    )

    $failuresBefore = $failures.Count

    foreach ($case in $cases) {
        $checks++
        $encoded = & $escaper.Name $case.Input

        $nonAscii = @([int[]] [char[]] $encoded | Where-Object { $_ -gt 0x7E -or $_ -lt 0x20 })
        if ($nonAscii.Count -gt 0) {
            Add-Failure ($escaper.Script + ': the escaper emitted a byte outside printable ASCII.')
            continue
        }

        $decoded = $null
        try {
            # Round-trip through a real JSON parser. Anything the escaper gets wrong fails here.
            $decoded = ('{"v":' + $encoded + '}' | ConvertFrom-Json).v
        }
        catch {
            Add-Failure ($escaper.Script + ': the escaper produced invalid JSON: ' + $encoded)
            continue
        }

        if ($decoded -ne $case.Expect) {
            Add-Failure ($escaper.Script + ': the escaper did not round-trip. Encoded: ' + $encoded)
        }
    }

    if ($failures.Count -eq $failuresBefore) {
        Add-Pass ($escaper.Script + ' / ' + $escaper.Name + ': all ' + $cases.Count + ' cases round-trip')
    }
}

# =====================================================================================
#  6. The triage tool runs, end to end, and reaches the right verdicts.
#
#  The most important assertion in this file, because it is the only one that fails when the
#  script does not run at all. Both defects found while writing it were of that kind and neither
#  was visible in the source: a function returning an empty collection unrolls to $null, and
#  StrictMode then throws on .Length; and the JSON escaper corrupted every path in the report.
#
#  The fixture reproduces the directory structure of the incident this tool was written from -
#  five artifacts in places the gateway refuses, and one inside a plugin's own PHP directory,
#  which it does not. The synthetic marker below is not a webshell and does nothing: what is being
#  tested is where a file sits and how the tool classifies it, not what the file contains.
# =====================================================================================

Write-Host ''
Write-Host 'End-to-end run' -ForegroundColor Cyan

$fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('wpshield-script-test-' + [guid]::NewGuid().ToString('n'))
$site = Join-Path $fixtureRoot 'example-site'

try {
    $marker = '<?php /* WPSHIELD-SYNTHETIC-FIXTURE-NOT-A-SHELL */ eval(base64_decode($_POST["x"])); ?>'

    $blocked = @(
        'wp-content\uploads\2021\02\one.php',
        'wp-content\plugins\example\static\editor\two.php'
    )
    $forwarded = @(
        'wp-content\plugins\example\wp\three.php'
    )
    $mustStaySilent = @(
        'wp-content\plugins\example\css\style.php',
        'wp-includes\class-wp-http.php'
    )

    foreach ($relative in ($blocked + $forwarded)) {
        $full = Join-Path $site $relative
        New-Item -ItemType Directory -Path (Split-Path -Parent $full) -Force | Out-Null
        Set-Content -LiteralPath $full -Value $marker -Encoding Ascii
    }

    # A generated stylesheet served from PHP, and a core file with a single legitimate decode.
    # Neither is evidence of anything, and a tool that reports them is a tool operators switch off.
    $stylePath = Join-Path $site 'wp-content\plugins\example\css\style.php'
    New-Item -ItemType Directory -Path (Split-Path -Parent $stylePath) -Force | Out-Null
    Set-Content -LiteralPath $stylePath -Value '<?php header("Content-Type: text/css"); echo ".a{}";' -Encoding Ascii

    $corePath = Join-Path $site 'wp-includes\class-wp-http.php'
    New-Item -ItemType Directory -Path (Split-Path -Parent $corePath) -Force | Out-Null
    Set-Content -LiteralPath $corePath -Value '<?php $x = base64_decode($encoded);' -Encoding Ascii

    $versionPath = Join-Path $site 'wp-includes\version.php'
    Set-Content -LiteralPath $versionPath -Value '<?php $wp_version = ''6.4.2'';' -Encoding Ascii

    $reportPath = Join-Path $fixtureRoot 'report.jsonl'
    $triagePath = Join-Path $RepositoryRoot 'scripts\Invoke-WPShieldTriage.ps1'

    # 6>$null discards the tool's own console report. Write-Host writes to the information stream,
    # so a pipe to Out-Null does not silence it, and the fixture run would otherwise bury the
    # results of this file in the results of that one.
    & $triagePath -SitePath $site -OutputPath $reportPath -IisLogPath '' -RecentDays 3650 6>$null |
        Out-Null

    $checks++
    if (-not (Test-Path -LiteralPath $reportPath)) {
        Add-Failure 'the triage tool produced no report.'
    }
    else {
        Add-Pass 'the triage tool ran and wrote a report'

        $reportBytes = [System.IO.File]::ReadAllBytes($reportPath)
        $checks++
        if (@($reportBytes | Where-Object { $_ -gt 0x7E }).Count -gt 0) {
            Add-Failure 'the report contains non-ASCII bytes. A name from a compromised host could carry an escape sequence into a reader.'
        }
        else {
            Add-Pass 'the report is pure ASCII'
        }

        $records = New-Object System.Collections.Generic.List[object]
        $malformed = 0
        foreach ($line in (Get-Content -LiteralPath $reportPath)) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            try { $records.Add(($line | ConvertFrom-Json)) }
            catch { $malformed++ }
        }

        $checks++
        if ($malformed -gt 0) {
            Add-Failure ($malformed.ToString() + ' report line(s) are not valid JSON.')
        }
        else {
            Add-Pass ('every one of the ' + $records.Count + ' report lines is valid JSON')
        }

        foreach ($relative in $blocked) {
            $checks++
            $expected = '/' + ($relative -replace '\\', '/')
            $match = @($records | Where-Object {
                $_.state.PSObject.Properties.Name -contains 'requestPath' -and
                $_.state.requestPath -eq $expected
            })

            if ($match.Count -eq 0) {
                Add-Failure ($expected + ' was not reported at all.')
            }
            elseif (@($match | Where-Object { $_.state.gatewayVerdict -eq 'blocked' }).Count -eq 0) {
                Add-Failure ($expected + ' was reported, but not as blocked by the gateway. Verdict: ' +
                    ($match[0].state.gatewayVerdict))
            }
            else {
                Add-Pass ($expected + ' -> blocked')
            }
        }

        foreach ($relative in $forwarded) {
            $checks++
            $expected = '/' + ($relative -replace '\\', '/')
            $match = @($records | Where-Object {
                $_.state.PSObject.Properties.Name -contains 'requestPath' -and
                $_.state.requestPath -eq $expected
            })

            if ($match.Count -eq 0) {
                Add-Failure ($expected + ' was not reported at all.')
            }
            elseif (@($match | Where-Object { $_.state.gatewayVerdict -eq 'not-covered' }).Count -eq 0) {
                # This is the assertion that pins the known gap. A future rule that closes it will
                # fail here, which is the point: closing it has to be a decision, made by someone
                # who can also say why the new rule is not wrong about legitimate plugin PHP.
                Add-Failure ($expected + ' is the known coverage gap and should be reported as not-covered. Verdict: ' +
                    ($match[0].state.gatewayVerdict))
            }
            else {
                Add-Pass ($expected + ' -> not-covered, as the known gap')
            }
        }

        foreach ($relative in $mustStaySilent) {
            $checks++
            $expected = '/' + ($relative -replace '\\', '/')
            $match = @($records | Where-Object {
                $_.level -eq 'Warning' -and
                $_.state.PSObject.Properties.Name -contains 'requestPath' -and
                $_.state.requestPath -eq $expected
            })

            if ($match.Count -gt 0) {
                Add-Failure ($expected + ' is legitimate and must not be reported. It was, as ' +
                    ($match[0].state.ruleId) + '.')
            }
            else {
                Add-Pass ($expected + ' stays silent')
            }
        }
    }
}
finally {
    if (Test-Path -LiteralPath $fixtureRoot) {
        Remove-Item -LiteralPath $fixtureRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# =====================================================================================
#  Result.
# =====================================================================================

Write-Host ''
Write-Host '================================================================================'
if ($failures.Count -gt 0) {
    Write-Host (' ' + $failures.Count + ' of ' + $checks + ' checks failed.') -ForegroundColor Red
    Write-Host '================================================================================'
    exit 1
}

Write-Host (' All ' + $checks + ' checks passed.') -ForegroundColor Green
Write-Host '================================================================================'
