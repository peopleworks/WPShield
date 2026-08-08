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

## Rollback

Stop WPShield to disable the laboratory. Because public IIS bindings remain unchanged, visitors continue to reach IIS directly on ports 80 and 443.
