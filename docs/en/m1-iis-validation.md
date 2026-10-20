# M1.3 — Local IIS Validation

This document describes the procedure for validating WPShield against a real IIS installation on
loopback, without touching the public bindings on ports 80 and 443. This is M1.3 work and a
prerequisite for M7 controlled activation.

## Topology

The laboratory uses two WordPress sites on IIS, each bound to a loopback port:

| Site | Host | IIS binding | WPShield destination |
|---|---|---|---|
| wordpress-one | wordpress-one.example | 127.0.0.1:8081 | http://127.0.0.1:8081/ |
| wordpress-two | wordpress-two.example | 127.0.0.1:8082 | http://127.0.0.1:8082/ |

The gateway listens on `127.0.0.1:10000`. Public bindings on 80 and 443 are never changed during
this validation.

```
Local test client
        │
        ▼
WPShield Gateway
127.0.0.1:10000
        │
        ├── wordpress-one.example
        │         ▼
        │   IIS 127.0.0.1:8081
        │
        └── wordpress-two.example
                  ▼
              IIS 127.0.0.1:8082
```

## Prerequisites

1. Windows Server with IIS 10 installed.
2. Two WordPress sites configured on IIS, bound to loopback ports 8081 and 8082.
3. Elementor and Google Site Kit installed on at least one site (compatibility targets).
4. The gateway binary built from the current commit:
   ```powershell
   dotnet build WPShield.slnx --configuration Release
   ```
5. Real values only in `appsettings.Local.json` — never committed, never published.

## Validation checklist

Run each item and record the result. Any failure stops the rollout for that site until fixed.

### 1. Gateway starts and resolves sites

Start the gateway and confirm it prints the resolved site table:

```powershell
dotnet run --project src/WPShield.Gateway
```

Expected output:

```text
info: WPShield.Gateway.Configuration[0]
      Gateway configuration resolved 2 site(s).
info: WPShield.Gateway.Configuration[0]
      Configured site. SiteId=wordpress-one Hosts=wordpress-one.example Destination=http://127.0.0.1:8081/ Mode=Monitor
info: WPShield.Gateway.Configuration[0]
      Configured site. SiteId=wordpress-two Hosts=wordpress-two.example Destination=http://127.0.0.1:8082/ Mode=Monitor
```

### 2. Unknown hosts fail closed with 421

```powershell
curl.exe -i -H "Host: unknown.example" http://127.0.0.1:10000/
```

Must return `421 Misdirected Request` with `{"error":"unknown_host","requestId":"…"}` and must
not reach either IIS backend.

### 3. Home page

```powershell
curl.exe -I -H "Host: wordpress-one.example" http://127.0.0.1:10000/
```

Must return `200 OK` from IIS site one, not from site two.

### 4. Administration and login

```powershell
curl.exe -I -H "Host: wordpress-one.example" http://127.0.0.1:10000/wp-admin/
curl.exe -I -H "Host: wordpress-one.example" http://127.0.0.1:10000/wp-login.php
```

Must return from site one. Do not submit credentials — only verify the route reaches the backend.

### 5. Static assets

```powershell
curl.exe -I -H "Host: wordpress-one.example" http://127.0.0.1:10000/wp-content/themes/example/style.css
curl.exe -I -H "Host: wordpress-one.example" http://127.0.0.1:10000/wp-content/plugins/elementor/assets/js/frontend.min.js
```

CSS, JS, images and other static assets must route to the correct site and return `200` or `304`.

### 6. REST API

```powershell
curl.exe -I -H "Host: wordpress-one.example" http://127.0.0.1:10000/wp-json/wp/v2/posts
```

Must reach site one's WordPress REST endpoint.

### 7. WordPress cron

```powershell
curl.exe -I -H "Host: wordpress-one.example" http://127.0.0.1:10000/wp-cron.php
```

Must reach site one and return `200`.

### 8. Administrative AJAX

```powershell
curl.exe -I -H "Host: wordpress-one.example" http://127.0.0.1:10000/wp-admin/admin-ajax.php?action=heartbeat
```

Must reach site one. `admin-ajax.php` receives legitimate Elementor and plugin traffic, so it must
not be refused by any path rule.

### 9. Redirects and HEAD

```powershell
curl.exe -I -H "Host: wordpress-one.example" http://127.0.0.1:10000/
curl.exe -X HEAD -H "Host: wordpress-one.example" http://127.0.0.1:10000/
```

HEAD must return the same status as GET without a body.

### 10. 404 responses

```powershell
curl.exe -I -H "Host: wordpress-one.example" http://127.0.0.1:10000/this-path-does-not-exist
```

Must return `404` from site one's WordPress, not a WPShield-generated error.

### 11. Uploads

POST a harmless synthetic file to `wp-admin/async-upload.php` and confirm it reaches site one:

```powershell
curl.exe -F "async-upload=@test-image.jpg" -H "Host: wordpress-one.example" http://127.0.0.1:10000/wp-admin/async-upload.php
```

In Monitor mode the upload is forwarded and recorded; in Block mode a finding past the threshold
refuses with `403`.

### 12. Elementor compatibility

Load an Elementor-edited page through the gateway:

```powershell
curl.exe -I -H "Host: wordpress-one.example" http://127.0.0.1:10000/elementor-test-page/
```

Must return `200` with Elementor assets loaded from site one.

### 13. Google Site Kit compatibility

Load a page with Google Site Kit through the gateway:

```powershell
curl.exe -I -H "Host: wordpress-one.example" http://127.0.0.1:10000/site-kit-page/
```

Must return `200`. Site Kit makes REST and admin-AJAX calls; all must route to the correct site.

### 14. Public bindings unchanged

Confirm IIS public bindings on ports 80 and 443 are untouched:

```powershell
Import-Module WebAdministration
Get-WebBinding | Select-Object protocol, bindingInformation
```

Ports 80 and 443 must still point to the original IIS sites, not to WPShield.

### 15. No secrets in logs

Review the gateway log file for the duration of this validation. Confirm none of the following
appear:

- `Authorization`, `Cookie`, `Set-Cookie` headers
- WordPress nonces
- API keys, tokens, passwords
- Full query strings
- Complete request bodies or upload contents

Logs must record only: request ID, site ID, method, path (without query string), status code,
rule IDs, and scores.

### 16. Rollback

Stop the gateway process. Traffic to IIS on 8081/8082 resumes directly, exactly as it did before
WPShield was started. Because IIS bindings 80/443 were never changed, public traffic was never
affected.

## Exit criteria

All 16 items pass, and the gateway log contains no secrets. The operator has read the resolved
site table line by line and confirmed it matches the intended routing.

## Automation

The test suite in `tests/WPShield.Gateway.Tests/IISValidationTests.cs` automates items 2–10 and
15 against a local IIS installation. It skips automatically when IIS is not available, so it is
safe to run on any machine — including the Linux CI leg — without failing.