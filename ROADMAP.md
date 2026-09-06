# Roadmap

WPShield remains a research-stage defensive gateway. M1 and M2 are loopback-only, and no milestone may modify production IIS bindings, public ports, DNS, certificates, firewall rules, or Windows services automatically.

## M0 — Foundation

- [x] .NET 10 solution with nullable reference types and warnings as errors.
- [x] Platform-independent inspection abstractions.
- [x] Multi-site configuration and explicit host resolution.
- [x] Explainable findings and Monitor/Block semantics.
- [x] Initial WordPress upload rules.
- [x] English and Spanish architecture documentation.
- [x] GitHub Actions restore, Release build, and Release test validation.
- [x] Repository-wide and path-specific agent instructions.
- [ ] Configuration schema and localized validation messages.

## M1 — Safe HTTP gateway

### M1.1 — Gateway hardening

- [x] Validate at least one configured site and reject duplicate hosts.
- [x] Accept only supported destination URI schemes.
- [x] Reject public laboratory destinations and destinations that point back to the gateway.
- [x] Preserve loopback-only listeners and prevent proxy loops.
- [x] Keep health endpoints local and add readiness behavior.
- [x] Return consistent privacy-safe 502 responses for unavailable backends.
- [x] Add configurable forwarding timeout and graceful shutdown behavior.
- [x] Ensure logs omit query strings, secrets, sensitive headers, and request bodies.
- [x] Add unit and integration coverage for configuration, routing, errors, headers, and request IDs.

### M1.2 — Synthetic backends and integration tests

- [x] Route each configured host exclusively to its assigned synthetic backend.
- [x] Prove unknown hosts return 421 without reaching a backend.
- [x] Replace spoofed inbound `X-Forwarded-*` headers.
- [x] Forward `X-WPShield-Request-ID`.
- [x] Preserve methods, paths, and query strings without logging full queries.
- [x] Handle slow and unavailable backends safely.
- [x] Keep health endpoints local.
- [x] Allocate dynamic test ports; never use 80, 443, 8081, 8082, or 10000.

### M1.3 — Local IIS validation

- [ ] Validate loopback routing to IIS destinations 127.0.0.1:8081 and 127.0.0.1:8082.
- [ ] Leave public IIS bindings on ports 80 and 443 unchanged.
- [ ] Validate home pages, administration, login, static assets, REST, cron, AJAX, redirects, HEAD, uploads, and 404 responses.
- [ ] Validate Elementor and Google Site Kit compatibility.
- [ ] Confirm credentials, cookies, nonces, tokens, and full query strings do not appear in logs.

## M2 — Bounded multipart inspection

> The inspection engine now runs on gateway traffic. Before this milestone the rules executed only
> from the `WPShield.Service` console demonstration and the gateway did not reference the rules
> project at all, so none of the detection this repository documents happened on a real request.
> See [bounded multipart inspection](docs/en/m2-multipart-inspection.md) for the complete behaviour.

- [x] Enforce a configurable 6 MiB request limit and a fixed 64 MiB configuration ceiling.
- [x] Reject oversized `Content-Length` early and count unknown-length bodies while streaming.
- [x] Enforce file-count, field-count, part-header, boundary, file-name, and multipart-read timeout limits, each with a hard ceiling that configuration may lower and never raise.
- [x] Never write a request body to disk; never buffer an unbounded one; buffer in memory only a `multipart/form-data` body, and only within the enforced request limit.
- [x] Normalize filenames, reject control characters and unsafe path forms, and bound metadata.
- [x] Extend inspection context with bounded per-file metadata and sample data only.
- [x] Implement high-confidence executable-extension, multiple-extension, PHP-content, and filename rules.
- [x] Cover the Windows attack surface: IIS-executable extensions and `web.config` upload.
- [x] Implement file-signature mismatch rules (`FILE-TYPE-001`, `PHP-CONTENT-002`).
- [x] Preserve Monitor forwarding where operationally safe and explicitly document absolute safety limits.
- [x] In Block mode, stop forwarding and return policy-appropriate 403, 408, 413, or 415 responses.
- [x] Add malformed, truncated, Unicode, cancellation, disconnect, limit, false-positive, and multi-file tests.

### Why the buffering line changed

That fourth line used to read *"Parse multipart requests without buffering complete uploads or
writing them to disk"*. It is restated rather than ticked as written, because the original wording
described something Block mode cannot be built on, and a reader who notices the change deserves the
reasoning rather than a quiet edit.

To **block**, the gateway must decide before forwarding. To **forward**, it must read the body a
second time. A network stream cannot be read twice. The choice was therefore between buffering a
multipart body and having no Block mode for uploads at all. What is actually guaranteed now is
narrower and checkable: **never to disk**, **never unbounded**, and **only for multipart**. The
buffer is a pooled in-memory structure that contains no file API at all, so disk-freedom is
structural rather than a threshold value a future edit could raise; the request-body limit is
enforced *before* buffering, so a chunked body with no declared length cannot grow it; and any
request that is not `multipart/form-data` still streams straight through with no added memory cost.

The declared `Content-Type` deliberately does not trigger `FILE-TYPE-001`, so the ninth line drops
the word *MIME*: browsers derive a part's `Content-Type` from the same extension, and every
non-browser client legitimately sends `application/octet-stream`, so a rule that fired on that
disagreement would fire on curl, wp-cli, mobile applications and the plupload fallback. The header is
recorded as a four-state token and never as a finding.

The eleventh line gains **408**. A body that does not fully arrive within the read timeout leaves a
partial buffer, and forwarding it would send WordPress a body shorter than its declared
`Content-Length`. That is answered with 408 in every mode, Monitor included, on the precedent the 413
already set: absolute resource controls are not findings and apply regardless of protection mode.

### What M2 does not cover

Not gaps discovered later — limits of the milestone as built, recorded so the ticked lines above are
not read as more than they claim:

- No non-multipart body is inspected: `application/x-www-form-urlencoded`, JSON, XML-RPC and
  `application/octet-stream` PUTs stream through untouched, as do `multipart/*` subtypes other than
  `form-data`.
- Form field parts are counted but never sampled or inspected, by design.
- There is no per-file size limit. A single upload is bounded only by the whole-request limit.
- Only the leading `SampleBytes` of each file are examined.
- [ ] Inspect the contents of uploaded archives. A `.zip` plugin or theme containing a webshell is
  not detected today, and plugin installation is a genuine WordPress upload path. This is the
  largest single gap and it has no milestone assigned yet.

## M3 — Rate limiting and automated behavior

> Per-IP limiting is meaningless until WPShield can resolve the real client address. Under the
> traffic path chosen in [ADR 0001](docs/en/adr/0001-production-traffic-path.md) every request
> arrives from a local proxy, so `Gateway:TrustedProxies` had to exist before this milestone could
> start. **It now does**, pulled forward from M7 because it is a prerequisite for both milestones and
> because leaving it undone makes WordPress generate `http://` URLs behind an HTTPS site. See
> [operator configuration](docs/en/operator-configuration.md#trusted-proxies).
>
> M2 also left a resource control unfinished. Nothing bounds how many multipart bodies may be
> buffered at once, and `KestrelServerLimits.MaxConcurrentConnections` is unlimited by default, so
> the loopback-only restriction is currently the only thing bounding that memory.

- [ ] Bound the number of concurrent buffered multipart inspections, which M2 deliberately left unbounded.
- [ ] Add per-IP and per-site burst controls with IPv4 and IPv6 support.
- [ ] Define separate policies for login, XML-RPC, uploads, REST, and administrative AJAX.
- [ ] Add expiring temporary blocks and configurable exceptions.
- [ ] Preserve Elementor and legitimate `admin-ajax.php` traffic.
- [ ] Document that WPShield does not provide volumetric DDoS mitigation.

## M4 — Observability

- [ ] Emit structured gateway, routing, inspection, rule, backend, and configuration events.
- [ ] Add per-site request, action, rule, byte, error, and duration metrics.
- [ ] Store privacy-safe JSON Lines with rotation, size limits, retention, and restricted permissions.
- [ ] Add automated redaction tests for sensitive headers, secrets, forms, query strings, and upload content.

## M5 — Local multilingual dashboard

- [ ] Bind management access to 127.0.0.1 initially.
- [ ] Add English and Spanish views for summary, sites, events, rules, health, configuration, versions, export, and diagnostics.
- [ ] Add CSRF protection and design Windows-authenticated administrative access before any remote use.
- [ ] Keep detailed rule evidence available only to authorized administrators.

## M6 — Windows Service and releases

- [ ] Publish self-contained `win-x64` artifacts.
- [ ] Run as a least-privilege Windows service account.
- [ ] Provide installation, update, uninstall, bypass, rollback, and recovery procedures.
- [ ] Add restricted configuration and log directories.
- [ ] Produce signed releases, checksums, versions, and bilingual release notes.

## M7 — Controlled public activation

The traffic path is decided in [ADR 0001](docs/en/adr/0001-production-traffic-path.md): IIS keeps
ports 80 and 443 and forwards to the loopback gateway through URL Rewrite and ARR, because bypass
must remain a single rule toggle. Installing ARR is a prerequisite, and the trusted-proxy design that
ADR requires must land before M3 rate limiting can identify clients correctly.

- [ ] Install and configure ARR with the validated loop-safe rewrite rule.
- [x] Implement `Gateway:TrustedProxies` with an empty, strip-everything default.
- [ ] Complete synthetic and loopback IIS validation.
- [ ] Verify backups, alternate administrative access, monitoring, bypass, and rollback.
- [ ] Run one test site, then one real site, then both sites in Monitor mode.
- [ ] Review privacy-safe logs and operational stability.
- [ ] Enable only approved high-confidence rules in Block mode, gradually and per site.

## M8 — Community readiness

Community infrastructure was pulled forward from M8, because the repository is already public and
contributors need somewhere safe to report before the project is otherwise ready.

- [x] Complete contributor, support, security, conduct, changelog, and template documentation.
- [x] Add issue forms, including a dedicated false-positive report.
- [x] Enable CodeQL and Dependabot, and pin GitHub Actions to commit SHAs.
- [x] Verify the platform-independent projects on Linux in CI.
- [ ] Enable private vulnerability reporting and Discussions in repository settings.
- [ ] Enable branch protection on `main` with required CI checks.
- [ ] Define reviewed, versioned community rule packages.
- [ ] Require rule descriptions, signals, risk, false positives, actions, benign tests, bilingual documentation, and compatibility metadata.
