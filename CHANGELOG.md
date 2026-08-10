# Changelog

All notable changes to WPShield are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project will follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it reaches its first release.

WPShield has **not** been released yet. Everything below is unreleased research-preview work, and
none of it is approved for production traffic. See [ROADMAP.md](ROADMAP.md) for the milestones that
must complete first.

## [Unreleased]

### Security

- Removed production topology from the public repository. The shipped `appsettings.json` had mapped
  two real hostnames to their internal IIS ports since the first gateway commit. Operator values now
  live in a gitignored `appsettings.Local.json` that is never copied into a published artifact.
- Startup now fails closed when real hostnames appear alongside the shipped documentation
  placeholders. JSON configuration merges arrays element by element, including the nested `Hosts`
  array, so a partial operator overlay used to leave example hosts active and routable.
- Closed four file name evasions that defeated `WP-UPLOAD-001`. `shell.php.`, `shell.php `,
  `shell.php::$DATA` and `photo.php.jpg` all reach disk as executable scripts on Windows but passed
  the previous extension check. Rules now match a Windows-aware normalization of the name.
- Added `IIS-CONFIG-001`, which detects a `web.config` upload. On IIS this converts an arbitrary file
  write into remote code execution without uploading a script, and no protection layer written for
  Linux hosting covers it.
- Added `IIS-UPLOAD-001` for extensions IIS executes: `.aspx`, `.asp`, `.ashx`, `.asmx`, `.ascx`,
  `.axd`, `.cshtml`, `.vbhtml`, `.razor`, `.svc`, `.soap`, `.rem`, `.asax`, `.master`.
- The gateway now strips the complete untrusted forwarding set rather than three headers. This adds
  every `X-Forwarded-*` variant by prefix, the RFC 7239 `Forwarded` header, the client-address family
  (`X-Real-IP`, `X-Client-IP`, `X-Cluster-Client-IP`, `True-Client-IP`, `CF-Connecting-IP`,
  `Fastly-Client-IP`, `X-Azure-*`) and the path-override headers `X-Original-URL` and
  `X-Rewrite-URL`, which are authentication-bypass vectors against IIS URL Rewrite.
- Enforced bounded request bodies: a 6 MiB default, a 64 MiB configuration ceiling, early rejection
  of an oversized `Content-Length` and streamed enforcement for unknown-length bodies.

### Added

- `NormalizedFileName`, which reproduces the collapse Windows performs on write and exposes every
  extension segment plus a flag for each anomaly removed.
- `WP-UPLOAD-002` for executable extensions disguised behind a benign one, and `FILE-NAME-001` for
  structural anomalies including reserved Windows device names.
- Architecture decision record [ADR 0001](docs/en/adr/0001-production-traffic-path.md), which decides
  how production traffic reaches the gateway on a host where IIS already owns ports 80 and 443, and
  specifies the `Gateway:TrustedProxies` design that M3 rate limiting depends on.
- Bilingual documentation for upload rules and operator configuration.
- Community infrastructure: CodeQL analysis, issue forms including a dedicated false-positive report,
  `SUPPORT.md` and this changelog.
- A Linux CI job that builds and tests `WPShield.Abstractions`, `WPShield.Core` and
  `WPShield.Rules.WordPress`, verifying the platform-independence the project claims.
- A formatting CI gate, and a `.gitattributes` that pins line endings to LF so the gate behaves
  identically for Windows, Linux and macOS contributors.
- Multi-site laboratory gateway on loopback with strict startup validation, health endpoints,
  privacy-safe `502` responses, request correlation identifiers and synthetic integration coverage.
- Explainable inspection engine with stable rule identifiers, scoring, and Monitor, Block and
  Disabled protection modes.

### Changed

- Configuration is no longer watched for changes. Options were validated once and captured for the
  process lifetime, so `reloadOnChange` promised hot reload that never happened. The gateway now logs
  its resolved site table at startup instead, making effective routing visible on every run.
- Rule evidence reports the normalized file name rather than the raw client value, so a name carrying
  control characters cannot reach a log consumer intact.
- GitHub Actions are pinned to commit SHAs rather than mutable tags.
- Test coverage grew from 42 to 215, including the evasion table as regression coverage, a
  benign-upload suite that must stay silent across every rule, and engine-level scoring calibration.

### Known limitations

- `PHP-CONTENT-001` searches a bounded UTF-8 sample and can be evaded by placing the tag beyond the
  sample window, encoding as UTF-16, or splitting it across the boundary. It is a supporting signal,
  never a sole reason to block.
- Multipart parsing is not connected to gateway traffic yet, so the upload rules are exercised through
  the inspection engine rather than on live requests.
- An embedded executable extension cannot be distinguished from a benign name such as
  `readme.php.txt` by name alone. Stay in Monitor mode until you have reviewed your own traffic.
