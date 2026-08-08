[CmdletBinding()]
param(
    [Uri]$GatewayUri = 'http://127.0.0.1:10000',
    [string]$SiteOneHost = 'peopleworks.com.do',
    [int]$SiteOnePort = 8081,
    [string]$SiteTwoHost = 'peopleworksgpt.com',
    [int]$SiteTwoPort = 8082,
    [string]$SiteOneStaticPath,
    [string]$SiteTwoStaticPath,
    [string]$GatewayLogPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$reservedTestPorts = @(80, 443, 10000)
$probeTimeout = [TimeSpan]::FromSeconds(15)
$sensitiveMarkers = @{
    Authorization = 'm13-authorization-marker'
    Cookie        = 'm13-cookie-marker'
    Nonce         = 'm13-nonce-marker'
    OAuth         = 'm13-oauth-marker'
    Query         = 'm13-query-marker'
}

function Assert-LoopbackUri {
    param([Uri]$Uri)

    $address = $null
    if (-not [Net.IPAddress]::TryParse($Uri.Host.Trim('[', ']'), [ref]$address) -or
        -not [Net.IPAddress]::IsLoopback($address)) {
        throw "GatewayUri must use an explicit loopback IP address."
    }
}

function Test-TcpPort {
    param(
        [string]$Address,
        [int]$Port
    )

    $client = [Net.Sockets.TcpClient]::new()
    try {
        $connectTask = $client.ConnectAsync($Address, $Port)
        return $connectTask.Wait([TimeSpan]::FromSeconds(2)) -and $client.Connected
    }
    finally {
        $client.Dispose()
    }
}

function Get-PublicListenerSnapshot {
    return @(
        Get-NetTCPConnection -State Listen -ErrorAction Stop |
            Where-Object LocalPort -In 80, 443 |
            Select-Object LocalAddress, LocalPort, OwningProcess |
            Sort-Object LocalAddress, LocalPort, OwningProcess
    )
}

function Invoke-SafeProbe {
    param(
        [string]$Name,
        [Uri]$BaseUri,
        [string]$HostName,
        [Net.Http.HttpMethod]$Method,
        [string]$PathAndQuery,
        [int[]]$ExpectedStatusCodes,
        [switch]$AddSensitiveMarkers
    )

    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $handler.UseCookies = $false
    $client = [Net.Http.HttpClient]::new($handler)
    $client.Timeout = $probeTimeout
    $request = [Net.Http.HttpRequestMessage]::new($Method, [Uri]::new($BaseUri, $PathAndQuery))
    $request.Headers.Host = $HostName

    if ($Method -eq [Net.Http.HttpMethod]::Post) {
        $request.Content = [Net.Http.ByteArrayContent]::new([byte[]]::new(0))
    }

    if ($AddSensitiveMarkers) {
        $request.Headers.Authorization =
            [Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $sensitiveMarkers.Authorization)
        $request.Headers.TryAddWithoutValidation('Cookie', "wordpress_test_cookie=$($sensitiveMarkers.Cookie)") | Out-Null
        $request.Headers.TryAddWithoutValidation('X-WP-Nonce', $sensitiveMarkers.Nonce) | Out-Null
    }

    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    try {
        $response = $client.SendAsync(
            $request,
            [Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        try {
            $statusCode = [int]$response.StatusCode
            return [pscustomobject]@{
                Name       = $Name
                Host       = $HostName
                Method     = $Method.Method
                Path       = $PathAndQuery.Split('?')[0]
                StatusCode = $statusCode
                DurationMs = $stopwatch.ElapsedMilliseconds
                Passed     = $ExpectedStatusCodes -contains $statusCode
            }
        }
        finally {
            $response.Dispose()
        }
    }
    catch {
        return [pscustomobject]@{
            Name       = $Name
            Host       = $HostName
            Method     = $Method.Method
            Path       = $PathAndQuery.Split('?')[0]
            StatusCode = $null
            DurationMs = $stopwatch.ElapsedMilliseconds
            Passed     = $false
        }
    }
    finally {
        $stopwatch.Stop()
        $request.Dispose()
        $client.Dispose()
        $handler.Dispose()
    }
}

function Test-LogMarkers {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Gateway log file '$Path' does not exist."
    }

    $matches = Select-String -LiteralPath $Path -SimpleMatch -Pattern @(
        $sensitiveMarkers.Authorization,
        $sensitiveMarkers.Cookie,
        $sensitiveMarkers.Nonce,
        $sensitiveMarkers.OAuth,
        $sensitiveMarkers.Query
    )

    if ($matches) {
        throw "Gateway logs contain one or more M1.3 sensitive test markers."
    }
}

Assert-LoopbackUri -Uri $GatewayUri

$sites = @(
    [pscustomobject]@{
        Name       = 'site-one'
        Host       = $SiteOneHost
        BackendUri = [Uri]"http://127.0.0.1:$SiteOnePort"
        StaticPath = $SiteOneStaticPath
    },
    [pscustomobject]@{
        Name       = 'site-two'
        Host       = $SiteTwoHost
        BackendUri = [Uri]"http://127.0.0.1:$SiteTwoPort"
        StaticPath = $SiteTwoStaticPath
    }
)

foreach ($site in $sites) {
    if ($site.BackendUri.Port -in $reservedTestPorts) {
        throw "Backend port $($site.BackendUri.Port) is reserved and cannot be used for an IIS loopback destination."
    }

    if (-not (Test-TcpPort -Address '127.0.0.1' -Port $site.BackendUri.Port)) {
        throw "$($site.Name) is not listening on 127.0.0.1:$($site.BackendUri.Port). No system changes were made."
    }
}

if (-not (Test-TcpPort -Address $GatewayUri.Host -Port $GatewayUri.Port)) {
    throw "WPShield is not listening at $GatewayUri. Start the gateway after verifying IIS loopback bindings."
}

$publicListenersBefore = Get-PublicListenerSnapshot
$results = [Collections.Generic.List[object]]::new()

foreach ($site in $sites) {
    $results.Add((Invoke-SafeProbe "$($site.Name) direct home" $site.BackendUri $site.Host ([Http.HttpMethod]::Get) '/' @(200, 301, 302, 307, 308)))
    $results.Add((Invoke-SafeProbe "$($site.Name) gateway home" $GatewayUri $site.Host ([Http.HttpMethod]::Get) '/' @(200, 301, 302, 307, 308)))
    $results.Add((Invoke-SafeProbe "$($site.Name) admin" $GatewayUri $site.Host ([Http.HttpMethod]::Get) '/wp-admin/' @(200, 301, 302, 307, 308)))
    $results.Add((Invoke-SafeProbe "$($site.Name) login" $GatewayUri $site.Host ([Http.HttpMethod]::Get) '/wp-login.php' @(200)))
    $results.Add((Invoke-SafeProbe "$($site.Name) REST" $GatewayUri $site.Host ([Http.HttpMethod]::Get) '/wp-json/' @(200)))
    $results.Add((Invoke-SafeProbe "$($site.Name) cron" $GatewayUri $site.Host ([Http.HttpMethod]::Head) '/wp-cron.php' @(200, 204)))
    $results.Add((Invoke-SafeProbe "$($site.Name) AJAX" $GatewayUri $site.Host ([Http.HttpMethod]::Post) '/wp-admin/admin-ajax.php' @(200, 400)))
    $results.Add((Invoke-SafeProbe "$($site.Name) HEAD" $GatewayUri $site.Host ([Http.HttpMethod]::Head) '/' @(200, 301, 302, 307, 308)))
    $results.Add((Invoke-SafeProbe "$($site.Name) 404" $GatewayUri $site.Host ([Http.HttpMethod]::Get) '/wpshield-m13-not-found' @(404)))

    $privacyPath = "/wp-json/?code=$($sensitiveMarkers.OAuth)&_wpnonce=$($sensitiveMarkers.Nonce)&probe=$($sensitiveMarkers.Query)"
    $results.Add((Invoke-SafeProbe "$($site.Name) privacy markers" $GatewayUri $site.Host ([Http.HttpMethod]::Get) $privacyPath @(200, 400, 401, 403) -AddSensitiveMarkers))

    if (-not [string]::IsNullOrWhiteSpace($site.StaticPath)) {
        if (-not $site.StaticPath.StartsWith('/')) {
            throw "Static asset paths must start with '/'."
        }

        $results.Add((Invoke-SafeProbe "$($site.Name) static asset" $GatewayUri $site.Host ([Http.HttpMethod]::Get) $site.StaticPath @(200, 304)))
    }
}

$results.Add((Invoke-SafeProbe 'gateway live health' $GatewayUri $sites[0].Host ([Http.HttpMethod]::Get) '/_wpshield/health/live' @(200)))
$results.Add((Invoke-SafeProbe 'gateway ready health' $GatewayUri $sites[1].Host ([Http.HttpMethod]::Get) '/_wpshield/health/ready' @(200)))
$results.Add((Invoke-SafeProbe 'unknown host' $GatewayUri 'invalid.example' ([Http.HttpMethod]::Get) '/' @(421)))

$publicListenersAfter = Get-PublicListenerSnapshot
$beforeJson = $publicListenersBefore | ConvertTo-Json -Compress
$afterJson = $publicListenersAfter | ConvertTo-Json -Compress
if ($beforeJson -ne $afterJson) {
    throw "Listeners on public ports 80 or 443 changed during validation."
}

if (-not [string]::IsNullOrWhiteSpace($GatewayLogPath)) {
    Test-LogMarkers -Path $GatewayLogPath
}

$results | Format-Table Name, Host, Method, Path, StatusCode, DurationMs, Passed -AutoSize

$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    throw "$($failed.Count) M1.3 probe(s) failed. Review status codes without exposing response bodies."
}

if ([string]::IsNullOrWhiteSpace($SiteOneStaticPath) -or
    [string]::IsNullOrWhiteSpace($SiteTwoStaticPath) -or
    [string]::IsNullOrWhiteSpace($GatewayLogPath)) {
    Write-Warning 'Static asset and/or gateway log validation remains pending because an optional path was not supplied.'
}

Write-Output 'Automated M1.3 probes passed. Complete the documented authenticated and plugin compatibility checklist manually.'
