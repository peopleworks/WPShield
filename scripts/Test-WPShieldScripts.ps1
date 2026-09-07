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
#  7. The installer changes only what it says it changes.
#
#  AGENTS.md: "Never modify IIS, certificates, DNS, firewall rules, or Windows services
#  automatically." The installer is the one script here that changes the machine at all, so the
#  boundary has to be checkable rather than merely documented.
#
#  Two things are asserted. Neither is a proof - the same limitation as the read-only inventory
#  applies, and for the same reason - but both catch the realistic mistake.
#
#    a. No script here writes to IIS. Not a binding, not a rewrite rule, not a proxy setting.
#       Those changes take a live site down, they need a person looking at the site, and on a
#       shared host they affect applications that have nothing to do with WPShield. Preflight and
#       uninstall READ the IIS configuration, which is why the ban is on the writing cmdlets only.
#
#    b. A service-mutating cmdlet binds its name to a variable, never to a literal. The failure
#       this prevents is someone writing Stop-Service 'W3SVC' into an installer that runs on a
#       server hosting sixty applications.
# =====================================================================================

Write-Host ''
Write-Host 'Installer boundaries' -ForegroundColor Cyan

$iisWritingCommands = @(
    'Set-WebConfiguration', 'Set-WebConfigurationProperty', 'Add-WebConfiguration',
    'Add-WebConfigurationProperty', 'Remove-WebConfigurationProperty', 'Clear-WebConfiguration',
    'New-WebBinding', 'Remove-WebBinding', 'Set-WebBinding',
    'New-Website', 'Remove-Website', 'Set-Website',
    'New-WebAppPool', 'Remove-WebAppPool', 'Set-WebAppPool',
    'New-WebApplication', 'Remove-WebApplication',
    'New-WebVirtualDirectory', 'Remove-WebVirtualDirectory',
    'Start-Website', 'Stop-Website', 'Restart-WebAppPool', 'Start-WebAppPool', 'Stop-WebAppPool',
    'appcmd', 'appcmd.exe'
)

$serviceMutatingCommands = @(
    'Stop-Service', 'Start-Service', 'Restart-Service', 'Set-Service',
    'New-Service', 'Remove-Service', 'Suspend-Service', 'Resume-Service'
)

foreach ($name in ($parsed.Keys | Sort-Object)) {
    $ast = $parsed[$name]
    $commands = @($ast.FindAll(
        { param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true))

    $iisWrites = 0
    $literalServiceNames = 0

    foreach ($command in $commands) {
        $element = $command.CommandElements[0]
        if (-not ($element -is [System.Management.Automation.Language.StringConstantExpressionAst])) { continue }
        $commandName = $element.Value

        if ($iisWritingCommands -contains $commandName) {
            $checks++
            $iisWrites++
            Add-Failure ($name + ' line ' + $command.Extent.StartLineNumber + ': ' + $commandName +
                ' writes to the IIS configuration. Those changes take a live site down and belong to ' +
                'a person looking at the site, not to a script.')
        }

        if ($serviceMutatingCommands -notcontains $commandName) { continue }

        # Find what is bound to -Name, or the first positional argument if there is no -Name.
        $target = $null
        for ($index = 1; $index -lt $command.CommandElements.Count; $index++) {
            $current = $command.CommandElements[$index]

            if ($current -is [System.Management.Automation.Language.CommandParameterAst]) {
                if ($current.ParameterName -like 'Name*' -and
                    $index + 1 -lt $command.CommandElements.Count) {
                    $target = $command.CommandElements[$index + 1]
                    break
                }
                # Skip this parameter and, when it takes one, its argument.
                if ($current.ParameterName -match '^(ErrorAction|WarningAction|Verbose|Force|Confirm|WhatIf|PassThru|StartupType|BinaryPathName|DisplayName|Description)$') {
                    continue
                }
                continue
            }

            if ($null -eq $target) { $target = $current; break }
        }

        $checks++
        if ($target -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
            $literalServiceNames++
            Add-Failure ($name + ' line ' + $command.Extent.StartLineNumber + ': ' + $commandName +
                " names the service with the literal '" + $target.Value + "'. Bind it to the script's " +
                'service-name constant instead. This script runs on hosts carrying many services, ' +
                'and it must be unable to act on one it was not written for.')
        }
    }

    if ($iisWrites -eq 0 -and $literalServiceNames -eq 0) {
        Add-Pass ($name + ': writes no IIS configuration, names no service by literal')
    }
}

# =====================================================================================
#  8. The installer's directory hardening actually hardens the directory.
#
#  Set-RestrictedDirectoryAcl is extracted and run against a real directory. It earns a test
#  because it is the one piece of the installer whose failure is silent: an ACL that does not take
#  leaves the log directory readable by every account on the server, and nothing about the install
#  looks wrong afterwards. PRE-016 exists to report exactly that condition, so the install must not
#  be the thing that creates it.
#
#  The current user's SID stands in for the service account, which does not exist until the service
#  does. What is under test is the ACL construction, not the identity.
#
#  Writing this test is what found the defect where setting the owner threw and aborted the install
#  at step five - after the files were copied and the service was registered, which is the worst
#  place for an installer to stop.
# =====================================================================================

Write-Host ''
Write-Host 'Directory hardening' -ForegroundColor Cyan

$installerName = 'Install-WPShield.ps1'

if (-not $parsed.ContainsKey($installerName)) {
    $checks++
    Add-Failure ($installerName + ' did not parse, so its ACL logic could not be exercised.')
}
else {
    $aclFunction = @($parsed[$installerName].FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Set-RestrictedDirectoryAcl'
    }, $true))

    $checks++
    if ($aclFunction.Count -ne 1) {
        Add-Failure 'Set-RestrictedDirectoryAcl was not found in the installer.'
    }
    else {
        # A structural check beside the behavioural ones below, because the behavioural check can
        # only fail where the code path actually runs. Writing the owner needs SeSecurityPrivilege,
        # so on an unelevated machine the ownership step throws and is skipped entirely - it goes
        # wrong only on an elevated install, which is the one place it matters.
        #
        # What went wrong: a freshly constructed DirectorySecurity carries an empty, unprotected
        # DACL, and Set-Acl writes that too. Setting the owner through one silently undid the
        # permissions applied moments earlier, putting the log directory back to inheriting
        # C:\ProgramData and its read-for-BUILTIN\Users. The descriptor must be read back with
        # Get-Acl and modified, so exactly one is ever constructed here: the DACL itself.
        $constructed = @($parsed[$installerName].FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.CommandAst] -and
            $node.Extent.Text -match 'New-Object\s+System\.Security\.AccessControl\.DirectorySecurity'
        }, $true))

        $checks++
        if ($constructed.Count -ne 1) {
            Add-Failure ('the installer constructs ' + $constructed.Count +
                ' DirectorySecurity objects; there should be exactly one, the DACL. A fresh one ' +
                'carries an empty unprotected DACL that Set-Acl will write over the permissions ' +
                'just applied. Read the descriptor back with Get-Acl instead.')
        }
        else {
            Add-Pass 'exactly one security descriptor is constructed; the owner is set on one read back'
        }

        # The installer reports ownership failures through Write-Detail, which lives in its outer
        # scope. The extracted function needs one.
        function Write-Detail {
            param([string] $Text, [string] $Colour = 'DarkGray')
            Write-Host ('       ' + $Text) -ForegroundColor $Colour
        }

        . ([scriptblock]::Create($aclFunction[0].Extent.Text))

        $probe = Join-Path ([System.IO.Path]::GetTempPath()) ('wpshield-acl-' + [guid]::NewGuid().ToString('n'))
        New-Item -ItemType Directory -Path $probe -Force | Out-Null
        New-Item -ItemType File -Path (Join-Path $probe 'existing.txt') -Force | Out-Null

        try {
            $me = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User

            Set-RestrictedDirectoryAcl -Directory $probe `
                -ServiceRights ([System.Security.AccessControl.FileSystemRights]'Modify') `
                -ServiceSid $me

            $acl = Get-Acl -LiteralPath $probe
            $broadSids = @('S-1-5-32-545', 'S-1-1-0', 'S-1-5-11', 'S-1-5-32-568')

            function Get-BroadEntry {
                param($Access)
                return @($Access | Where-Object {
                    $broadSids -contains $_.IdentityReference.Translate(
                        [System.Security.Principal.SecurityIdentifier]).Value
                })
            }

            $checks++
            $broad = @(Get-BroadEntry $acl.Access)
            if ($broad.Count -gt 0) {
                Add-Failure ('the hardened directory still grants ' +
                    (($broad | ForEach-Object { $_.IdentityReference.Value }) -join ', ') +
                    '. A log directory readable by every account is the condition PRE-016 exists to report.')
            }
            else {
                Add-Pass 'no Users, Everyone, Authenticated Users or IIS_IUSRS entry survives'
            }

            $checks++
            if (-not $acl.AreAccessRulesProtected) {
                Add-Failure 'inheritance was not disabled, so the parent keeps granting access.'
            }
            else {
                Add-Pass 'inheritance disabled, and inherited entries discarded rather than copied'
            }

            $checks++
            if ($acl.Access.Count -ne 3) {
                Add-Failure ('expected exactly three access entries, found ' + $acl.Access.Count + '.')
            }
            else {
                Add-Pass 'exactly three entries: Administrators, SYSTEM, the service account'
            }

            # Without inheritance flags the restriction would apply to the directory alone and every
            # log file already inside it would keep the permissions it had.
            $checks++
            $childBroad = @(Get-BroadEntry (Get-Acl -LiteralPath (Join-Path $probe 'existing.txt')).Access)
            if ($childBroad.Count -gt 0) {
                Add-Failure 'a file already inside the directory kept its broad permissions.'
            }
            else {
                Add-Pass 'the restriction reaches files already in the directory'
            }
        }
        finally {
            Remove-Item -LiteralPath $probe -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# =====================================================================================
#  9. The log directory contract.
#
#  Three separate places have to agree on where the evidence goes, and for one release they did
#  not. The installer created C:\ProgramData\WPShield\logs, removed inheritance, granted the
#  service account Modify and printed the path. The gateway read Logging:File:Directory, which
#  shipped as the relative "logs", resolved it against its content root and tried to write beside
#  its own binaries - a directory the same installer deliberately leaves read-only for that
#  account. The write failed. The failure went to stderr, which a Windows service has no console
#  for. A by-the-book installation produced no evidence at all and said nothing about it.
#
#  Nothing in that chain was individually wrong. What was missing was anything asserting that the
#  directory the installer hardens is the directory the gateway writes to, which is what this
#  section is.
# =====================================================================================

Write-Host ''
Write-Host 'Log directory contract' -ForegroundColor Cyan

$shippedSettingsPath = Join-Path $RepositoryRoot 'src\WPShield.Gateway\appsettings.json'
$shippedLogDirectory = ''

$checks++
if (-not (Test-Path -LiteralPath $shippedSettingsPath)) {
    Add-Failure ('the shipped appsettings.json was not found at ' + $shippedSettingsPath + '.')
}
else {
    $shipped = Get-Content -LiteralPath $shippedSettingsPath -Raw | ConvertFrom-Json
    $shippedLogDirectory = [string] $shipped.Logging.File.Directory

    if (-not [System.IO.Path]::IsPathRooted($shippedLogDirectory)) {
        Add-Failure ('the shipped Logging:File:Directory is "' + $shippedLogDirectory +
            '", which is relative. A relative log directory resolves against the content root, so it ' +
            'follows wherever the build was unpacked - into a web root, or into the read-only ' +
            'installation directory. It must be absolute.')
    }
    else {
        Add-Pass ('the shipped Logging:File:Directory is absolute: ' + $shippedLogDirectory)
    }
}

# The installer's default and the shipped value must name the same place, or a default install
# rewrites the configuration to something the operator was never shown.
$checks++
$logPathDefault = @($parsed[$installerName].FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.ParameterAst] -and
    $node.Name.VariablePath.UserPath -eq 'LogPath'
}, $true))

if ($logPathDefault.Count -ne 1) {
    Add-Failure ('the installer declares ' + $logPathDefault.Count + ' -LogPath parameters; expected one.')
}
elseif ([string]::IsNullOrWhiteSpace($shippedLogDirectory)) {
    Add-Failure 'the shipped log directory could not be read, so -LogPath could not be compared against it.'
}
else {
    $declared = $logPathDefault[0].DefaultValue.Extent.Text.Trim("'", '"')
    if ($declared -ne $shippedLogDirectory) {
        Add-Failure ('the installer defaults -LogPath to "' + $declared + '" and the shipped ' +
            'appsettings.json says "' + $shippedLogDirectory + '". They must name the same directory.')
    }
    else {
        Add-Pass 'the installer default and the shipped configuration name the same log directory'
    }
}

# The refusal has to happen before anything is created, copied or registered.
$checks++
$installerText = Get-Content -LiteralPath (Join-Path $RepositoryRoot ('scripts\' + $installerName)) -Raw
$guardOffset = $installerText.IndexOf('Assert-NotUnderWebRoot -Path', [System.StringComparison]::Ordinal)
$firstMutationOffset = $installerText.IndexOf('Write-Step ''1.', [System.StringComparison]::Ordinal)

if ($guardOffset -lt 0) {
    Add-Failure 'the installer never calls Assert-NotUnderWebRoot, so it would install inside a web root.'
}
elseif ($firstMutationOffset -lt 0) {
    Add-Failure 'the installer''s first step could not be located, so the guard''s position could not be checked.'
}
elseif ($guardOffset -gt $firstMutationOffset) {
    Add-Failure 'the installer calls Assert-NotUnderWebRoot after it has started changing the machine. A refusal must leave the machine as it was found.'
}
else {
    Add-Pass 'the web-root refusal runs before the installer changes anything'
}

$checks++
if ($parsed['Invoke-WPShieldPreflight.ps1'].Extent.Text -notmatch "PRE-019") {
    Add-Failure 'the preflight has no PRE-019, so nothing reports an installation sitting inside a web root.'
}
else {
    Add-Pass 'the preflight reports an installation inside a web root as PRE-019'
}

# The behavioural half. A structural check cannot tell whether the edit produces valid JSON that
# still carries every other setting, and rewriting a configuration file is exactly where that goes
# wrong quietly.
$checks++
$editFunction = @($parsed[$installerName].FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Set-InstalledLogDirectory'
}, $true))

if ($editFunction.Count -ne 1) {
    Add-Failure 'Set-InstalledLogDirectory was not found in the installer, so nothing writes the hardened log path into the configuration the gateway reads.'
}
elseif ([string]::IsNullOrWhiteSpace($shippedLogDirectory)) {
    Add-Failure 'the shipped appsettings.json could not be read, so the configuration edit could not be exercised.'
}
else {
    . ([scriptblock]::Create($editFunction[0].Extent.Text))

    $probeDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ('wpshield-cfg-' + [guid]::NewGuid().ToString('n'))
    New-Item -ItemType Directory -Path $probeDirectory -Force | Out-Null
    $probeSettings = Join-Path $probeDirectory 'appsettings.json'

    try {
        Copy-Item -LiteralPath $shippedSettingsPath -Destination $probeSettings -Force
        $before = Get-Content -LiteralPath $probeSettings -Raw | ConvertFrom-Json

        Set-InstalledLogDirectory -ConfigurationFile $probeSettings -Directory 'D:\evidence\wpshield'

        $after = Get-Content -LiteralPath $probeSettings -Raw | ConvertFrom-Json

        if ($after.Logging.File.Directory -ne 'D:\evidence\wpshield') {
            Add-Failure ('the configuration edit left Logging:File:Directory as "' +
                [string] $after.Logging.File.Directory + '".')
        }
        elseif ($after.Sites.Count -ne $before.Sites.Count) {
            Add-Failure ('the configuration edit changed the site count from ' + $before.Sites.Count +
                ' to ' + $after.Sites.Count + '. Rewriting the file must not lose anything else in it.')
        }
        elseif ($after.Gateway.MaximumRequestBytes -ne $before.Gateway.MaximumRequestBytes) {
            Add-Failure 'the configuration edit changed Gateway:MaximumRequestBytes, so numbers are not surviving the JSON round trip.'
        }
        elseif ($after.Logging.File.Enabled -ne $before.Logging.File.Enabled) {
            Add-Failure 'the configuration edit changed Logging:File:Enabled, so booleans are not surviving the JSON round trip.'
        }
        else {
            Add-Pass 'the installer writes the log directory into appsettings.json and loses nothing else'
        }

        # A BOM is the failure this encoding choice avoids, and it is invisible in a diff.
        $checks++
        $firstBytes = [System.IO.File]::ReadAllBytes($probeSettings)
        if ($firstBytes.Length -ge 3 -and $firstBytes[0] -eq 0xEF -and $firstBytes[1] -eq 0xBB -and $firstBytes[2] -eq 0xBF) {
            Add-Failure 'the rewritten appsettings.json starts with a UTF-8 BOM.'
        }
        else {
            Add-Pass 'the rewritten appsettings.json has no BOM'
        }
    }
    finally {
        Remove-Item -LiteralPath $probeDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# =====================================================================================
#  10. What the preflight prints has to be correct as text.
#
#  The preflight prints an appsettings.Local.json for the operator to paste. It printed
#  "C:\\\\ProgramData\\\\WPShield\\\\logs" for a release, because a .NET replacement string treats
#  backslash as an ordinary character - only $ is special there - so '\\\\' emits four of them.
#  Windows normalises the doubled separators away, so the configuration worked and only the text was
#  wrong, which is the kind of defect that survives a long time.
# =====================================================================================

Write-Host ''
Write-Host 'Preflight output' -ForegroundColor Cyan

foreach ($name in ($parsed.Keys | Sort-Object)) {
    $text = Get-Content -LiteralPath (Join-Path $RepositoryRoot ('scripts\' + $name)) -Raw

    # Every backslash-doubling replacement in the repository, whatever it is doubling for.
    $replacements = [regex]::Matches($text, "-replace\s+'\\\\',\s*'(?<to>\\+)'")
    if ($replacements.Count -eq 0) { continue }

    foreach ($replacement in $replacements) {
        $checks++
        $to = $replacement.Groups['to'].Value
        if ($to.Length -ne 2) {
            Add-Failure ($name + ': a backslash is replaced with ' + $to.Length + ' backslashes. A .NET ' +
                'replacement string does not treat backslash as an escape, so JSON escaping needs exactly ' +
                'two. ' + $to.Length + ' produces a path with doubled separators.')
        }
        else {
            Add-Pass ($name + ': backslashes are doubled once, not twice')
        }
    }
}

<#
    The catch-all pattern list must include the wildcard the WordPress permalink rule actually uses.

    PRE-018 exists to find the rule the WPShield rule has to be ordered before, and for a release it
    required stopProcessing="true" together with a regex catch-all. WordPress writes
    patternSyntax="Wildcard" with match url="*" and no stopProcessing, so on a server with three
    WordPress sites PRE-018 reported nothing at all.
#>
$checks++
$preflightText = Get-Content -LiteralPath (Join-Path $RepositoryRoot 'scripts\Invoke-WPShieldPreflight.ps1') -Raw

if ($preflightText -notmatch "catchAllPatterns[^`r`n]*'\*'") {
    Add-Failure ('PRE-018 does not treat the wildcard "*" as a catch-all. That is the pattern the ' +
        'WordPress permalink rule uses, and it is the single rule this check exists to find.')
}
else {
    Add-Pass 'PRE-018 recognises the wildcard match the WordPress permalink rule uses'
}

$checks++
if ($preflightText -match '\$stops\s+-and\s+\$catchAllPatterns' -or
    $preflightText -match 'if\s*\(\$stops\s+-and') {
    Add-Failure ('PRE-018 requires stopProcessing before reporting a catch-all. A catch-all Rewrite ' +
        'without it still consumes the request: the WPShield rule then runs against the rewritten ' +
        'URL and every request reaches the gateway as the rewrite target.')
}
else {
    Add-Pass 'PRE-018 reports stopProcessing rather than requiring it'
}

<#
    The installer's closing notes must not instruct an operator to do what the installer just did.

    Passing -ConfigurationPath installs appsettings.Local.json, and the notes then said "Put
    appsettings.Local.json in place" underneath the step that had installed it. Small, but it is the
    same failure this repository keeps finding in larger forms: a tool describing a state it did not
    check.
#>
$checks++
if ($installerText -notmatch '\$configurationExpected') {
    Add-Failure ('the installer''s closing notes do not consider whether a configuration was ' +
        'supplied, so they tell an operator who passed -ConfigurationPath to install the file again.')
}
else {
    Add-Pass 'the closing notes adapt to whether a configuration was supplied'
}

# A hardcoded health-check port sends an operator who configured another one to test a port nothing
# listens on, and that failure is indistinguishable from a gateway that did not start.
$checks++
if ($installerText -match "Invoke-WebRequest\s+http://127\.0\.0\.1:\d+/_wpshield") {
    Add-Failure 'the installer prints a hardcoded health-check URL rather than one read from Gateway:Urls.'
}
else {
    Add-Pass 'the printed health-check URL is read from the configuration'
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
