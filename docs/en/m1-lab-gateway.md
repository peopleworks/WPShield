# M1: Multi-site laboratory HTTP gateway

This version listens only on `127.0.0.1:10000`. It must not be exposed to the Internet or replace IIS public bindings yet.

## Expected lab topology

- WPShield Gateway: `127.0.0.1:10000`
- IIS / peopleworks.com.do: `127.0.0.1:8081`
- IIS / peopleworksgpt.com: `127.0.0.1:8082`
- Declared legitimate upload: 5 MB (enforcement is planned for M2)

Keep the existing public ports 80 and 443 unchanged. Add and verify separate temporary loopback HTTP bindings for the two IIS sites before running the gateway.

Do not change certificates, public HTTPS, DNS, firewall rules, or Windows services during M1.

## M1.1 startup validation

WPShield refuses to start when:

- no sites are configured;
- a host is assigned more than once, including case-only duplicates;
- a listener is not an HTTP or HTTPS loopback IP;
- a destination does not use an absolute HTTP or HTTPS URI;
- a destination is outside loopback during M1; or
- a destination uses a WPShield listener port and could create a proxy loop.

These failures are configuration errors. Correct the configuration instead of weakening the validation.

## Run

```powershell
dotnet run --project src/WPShield.Gateway
```

## Check health

```powershell
curl.exe http://127.0.0.1:10000/_wpshield/health/live
curl.exe http://127.0.0.1:10000/_wpshield/health/ready
```

The complete `/_wpshield/health/` namespace is handled locally and is never proxied. Remote health access remains disabled by default.

## Test each site

```powershell
curl.exe -I -H "Host: peopleworks.com.do" http://127.0.0.1:10000/
curl.exe -I -H "Host: peopleworksgpt.com" http://127.0.0.1:10000/
```

An unconfigured host must return HTTP 421:

```powershell
curl.exe -i -H "Host: invalid.example" http://127.0.0.1:10000/
```

An unavailable backend returns a consistent HTTP 502 JSON response:

```json
{
  "error": "backend_unavailable",
  "requestId": "correlation-id"
}
```

The client response never includes the destination, exception details, credentials, cookies, request body, or query string. Gateway request logs contain only privacy-safe metadata such as request ID, site ID, method, and path. ASP.NET Core and YARP informational request logging is disabled to prevent query-string disclosure.

## M1.2 synthetic integration tests

Automated tests run two safe local Kestrel backends named `site-one` and `site-two`. They do not use IIS, WordPress, production hostnames, or production data. The gateway and both backends bind to loopback ports assigned dynamically by the operating system.

The integration suite verifies:

- each configured hostname reaches only its assigned backend;
- unknown hosts return HTTP 421 and reach neither backend;
- spoofed `X-Forwarded-For`, `X-Forwarded-Proto`, and `X-Forwarded-Host` values are replaced;
- a gateway-generated `X-WPShield-Request-ID` reaches the backend;
- the HTTP method, path, and query string are forwarded correctly;
- unavailable and timed-out backends produce a privacy-safe HTTP 502 response; and
- the health namespace remains local and reaches neither backend.

Automated tests assert that their bound ports are not 80, 443, 8081, 8082, or 10000. The configurable forwarding activity timeout is bounded from 1 to 300 seconds; the laboratory default remains 100 seconds.

## M1.3 local IIS validation

M1.3 is an operator-controlled laboratory procedure, not an automated deployment. WPShield does not create or modify IIS bindings. Before validation, an administrator must add and verify these temporary loopback bindings while leaving public ports 80 and 443 unchanged:

- `peopleworks.com.do` on `127.0.0.1:8081`
- `peopleworksgpt.com` on `127.0.0.1:8082`

Run the gateway only after both loopback destinations respond directly. The read-only probe script refuses to continue when either destination or the gateway is unavailable and never prints response bodies, cookies, or authorization data:

```powershell
.\scripts\Test-WPShieldIisLab.ps1 `
  -SiteOneStaticPath "/wp-includes/css/dashicons.min.css" `
  -SiteTwoStaticPath "/wp-includes/css/dashicons.min.css" `
  -GatewayLogPath "C:\path\to\captured-gateway.log"
```

The script checks direct and gateway home pages, `/wp-admin/`, login, REST, cron, AJAX, redirects, HEAD, a known static asset, a synthetic 404, local health endpoints, unknown-host rejection, privacy markers, and unchanged listeners on ports 80 and 443. Static paths should identify known public files that exist on each installation. The log path must point to the captured output from the same probe run.

### Manual authenticated checklist

Use a dedicated laboratory administrator account and a private browser window. Do not paste credentials, cookies, nonces, OAuth codes, or production logs into issues or test reports.

| Check | Expected result |
| --- | --- |
| WordPress login and logout | Authentication works through port 10000; no redirect loop or internal port appears |
| `/wp-admin/` navigation | Dashboard pages, CSS, JavaScript, images, and redirects load normally |
| Media upload | A benign file below 5 MB uploads and is retrievable; M1 does not inspect or block it |
| REST API | Authenticated and unauthenticated routes used by the site behave as they do directly through IIS |
| Cron and AJAX | Scheduled actions and `admin-ajax.php` operations complete without gateway errors |
| Elementor | Editor opens, assets load, preview works, and a harmless draft can be saved without publishing |
| Google Site Kit | Dashboard loads, existing connection state remains intact, and OAuth values are not exposed in logs |
| 404 and canonical redirects | Status codes and public canonical URLs match direct IIS behavior |
| Privacy review | Captured gateway logs contain no credentials, Authorization, Cookie, Set-Cookie, nonces, OAuth values, request bodies, or complete query strings |

Record only pass/fail, status codes, durations, request IDs, and sanitized observations. M1.3 is complete only after both sites pass the automated probes, the manual checklist, and the privacy review.

## Rollback

Stop WPShield to disable the laboratory. Because public IIS bindings remain unchanged, visitors continue to reach IIS directly on ports 80 and 443.
