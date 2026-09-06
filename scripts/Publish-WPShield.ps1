#Requires -Version 5.1

<#
.SYNOPSIS
    Builds a self-contained win-x64 deployment of the WPShield gateway, with a checksum.

.DESCRIPTION
    Runs on a build machine, not on the server. Produces a directory that can be copied to a Windows
    Server host and installed with Install-WPShield.ps1, plus an archive and a SHA-256 file so the
    transport can be verified rather than trusted.

    SELF-CONTAINED, DELIBERATELY. A framework-dependent build is smaller and works wherever the
    matching ASP.NET Core runtime is installed. This publishes self-contained anyway, because the
    host WPShield is written for is a shared one: a server running dozens of unrelated applications,
    where somebody else's patch to the shared runtime should not be able to stop the security
    gateway. The gateway carries its own runtime and is affected by nothing but its own files.

    NOT TRIMMED. Trimming would cut the size substantially and would also silently remove types that
    configuration binding and dependency injection resolve by reflection. A gateway that fails to
    start on a server at 3am because a trimmer removed a binder is a worse outcome than a large
    directory.

    THE ARTIFACT NAME SAYS WHAT THIS IS. WPShield is a research preview and is not approved for
    production traffic, and an archive gets renamed, forwarded and unpacked months later by someone
    who never saw the page that said so. The file name is the last place that warning survives, so
    it is in the file name.

.PARAMETER OutputPath
    Where to place the publish directory and the archive. Defaults to artifacts/ in the repository.

.PARAMETER SkipArchive
    Produce the directory only, without the archive and its checksum.

.EXAMPLE
    .\scripts\Publish-WPShield.ps1

.NOTES
    Part of WPShield, a research preview. Not approved for production traffic.
    https://github.com/peopleworks/WPShield
#>

[CmdletBinding()]
param(
    [string] $RepositoryRoot = (Split-Path -Parent $PSScriptRoot),
    [string] $OutputPath,
    [switch] $SkipArchive
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$projectPath = Join-Path $RepositoryRoot 'src\WPShield.Gateway\WPShield.Gateway.csproj'
if (-not (Test-Path -LiteralPath $projectPath)) {
    throw ('Gateway project not found at ' + $projectPath + '. Is -RepositoryRoot correct?')
}

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $RepositoryRoot 'artifacts'
}

# The version the assemblies will carry. Read from the same file the build reads, so the archive
# name and the binary metadata cannot disagree about what this is.
$propsPath = Join-Path $RepositoryRoot 'Directory.Build.props'
$version = $null
if (Test-Path -LiteralPath $propsPath) {
    $match = Select-String -LiteralPath $propsPath -Pattern '<Version>([^<]+)</Version>' | Select-Object -First 1
    if ($null -ne $match) { $version = $match.Matches[0].Groups[1].Value }
}
if ([string]::IsNullOrWhiteSpace($version)) {
    throw 'Could not read <Version> from Directory.Build.props.'
}

$name = 'wpshield-' + $version + '-win-x64-RESEARCH-PREVIEW-NOT-FOR-PRODUCTION'
$publishDirectory = Join-Path $OutputPath $name

Write-Host ''
Write-Host ('WPShield ' + $version + ' - self-contained win-x64 publish') -ForegroundColor Cyan
Write-Host ('Output: ' + $publishDirectory)
Write-Host ''

if (Test-Path -LiteralPath $publishDirectory) {
    Write-Host 'Removing the previous publish directory.' -ForegroundColor DarkGray
    Remove-Item -LiteralPath $publishDirectory -Recurse -Force
}

& dotnet publish $projectPath `
    --configuration Release `
    --runtime win-x64 `
    --self-contained true `
    --output $publishDirectory

if ($LASTEXITCODE -ne 0) {
    throw ('dotnet publish failed with exit code ' + $LASTEXITCODE + '.')
}

# =====================================================================================
#  Checks on what came out. Each of these has a way of being wrong quietly.
# =====================================================================================

Write-Host ''
Write-Host 'Verifying the artifact' -ForegroundColor Cyan

$executable = Join-Path $publishDirectory 'WPShield.Gateway.exe'
if (-not (Test-Path -LiteralPath $executable)) {
    throw 'The publish output has no WPShield.Gateway.exe.'
}
Write-Host '  ok    the executable is present' -ForegroundColor DarkGray

# The operator overlay carries real hostnames, destinations and topology. The csproj marks it
# CopyToPublishDirectory=Never, but that is one attribute away from not being true, and the
# consequence - a deployment package that leaks a customer's topology - is not one to leave to a
# setting nobody re-reads.
$localConfiguration = Join-Path $publishDirectory 'appsettings.Local.json'
if (Test-Path -LiteralPath $localConfiguration) {
    Remove-Item -LiteralPath $publishDirectory -Recurse -Force
    throw ('appsettings.Local.json was copied into the publish output. That file carries real ' +
           'hostnames and topology and must never enter a deployment package. The publish ' +
           'directory has been deleted. Check CopyToPublishDirectory in WPShield.Gateway.csproj.')
}
Write-Host '  ok    no operator configuration was packaged' -ForegroundColor DarkGray

# The assembly version and the archive name both come from Directory.Build.props, so a mismatch
# means the build did not read what this script read.
$fileVersion = (Get-Item -LiteralPath $executable).VersionInfo.ProductVersion
if ($null -eq $fileVersion -or -not $fileVersion.StartsWith($version)) {
    throw ('The published binary reports version "' + $fileVersion + '", which does not match the "' +
           $version + '" in Directory.Build.props.')
}
Write-Host ('  ok    the binary reports ' + $fileVersion) -ForegroundColor DarkGray

$description = (Get-Item -LiteralPath $executable).VersionInfo.FileDescription
Write-Host ('  ok    assembly description: ' + $description) -ForegroundColor DarkGray

$fileCount = @(Get-ChildItem -LiteralPath $publishDirectory -Recurse -File).Count
$totalBytes = (Get-ChildItem -LiteralPath $publishDirectory -Recurse -File |
    Measure-Object -Property Length -Sum).Sum
Write-Host ('  ok    ' + $fileCount + ' files, ' + [Math]::Round($totalBytes / 1MB, 1) + ' MB') -ForegroundColor DarkGray

# =====================================================================================
#  Archive and checksum.
# =====================================================================================

if (-not $SkipArchive) {
    Write-Host ''
    Write-Host 'Archiving' -ForegroundColor Cyan

    $archivePath = Join-Path $OutputPath ($name + '.zip')
    if (Test-Path -LiteralPath $archivePath) { Remove-Item -LiteralPath $archivePath -Force }

    Compress-Archive -Path (Join-Path $publishDirectory '*') -DestinationPath $archivePath -CompressionLevel Optimal

    $hash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash
    $checksumPath = $archivePath + '.sha256'

    # The format `sha256sum -c` understands, so the operator can verify with whatever they have.
    Set-Content -LiteralPath $checksumPath -Value ($hash.ToLowerInvariant() + ' *' + (Split-Path -Leaf $archivePath)) -Encoding Ascii

    Write-Host ('  archive : ' + $archivePath) -ForegroundColor DarkGray
    Write-Host ('  size    : ' + [Math]::Round((Get-Item -LiteralPath $archivePath).Length / 1MB, 1) + ' MB') -ForegroundColor DarkGray
    Write-Host ('  sha256  : ' + $hash) -ForegroundColor DarkGray
    Write-Host ('  checksum: ' + $checksumPath) -ForegroundColor DarkGray
}

Write-Host ''
Write-Host 'Done.' -ForegroundColor Green
Write-Host ''
Write-Host 'Next, on the server:' -ForegroundColor Cyan
Write-Host ('  1. Copy the directory or the archive across, and verify the SHA-256.')
Write-Host ('  2. Run Invoke-WPShieldPreflight.ps1 and clear every blocker.')
Write-Host ('  3. Run Install-WPShield.ps1 -Path <the copied directory> -WhatIf first, then without it.')
Write-Host ''
Write-Host 'This is a research preview. It is not approved for production traffic.' -ForegroundColor Yellow
