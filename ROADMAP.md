# Roadmap

WPShield remains a research-stage defensive gateway. M1 and M2 are loopback-only, and no milestone may modify production IIS bindings, public ports, DNS, certificates, Windows Firewall rules, or Windows services automatically. The one network-layer action WPShield takes is [ADR 0006](docs/en/adr/0006-network-layer-blocking.md)'s, and it is Proposed: in Block mode only, `network-filter` drops packets from the addresses on its own block list, through WinDivert handles that close, and lift every block, when the process ends.

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

## M2.5 — Request path inspection

> Unplanned, and pulled in ahead of M3 because of a real compromise rather than a threat model. A
> WordPress site on IIS was found running six webshells; the server logs recorded every request that
> reached one. **Every single one was an ordinary `GET` or `POST` to an existing `.php` file, with no
> body at all** — so not one was visible to any rule this project had, because M2 inspects
> `multipart/form-data` bodies and nothing else. M2 can refuse a shell as it arrives. It cannot see a
> shell that is already there being used.
>
> See [request path inspection](docs/en/m2-5-request-path-inspection.md) for the complete behaviour.

- [x] Normalize the request path to what a Windows web server resolves: case, backslash separators,
      traversal, empty segments, trailing dots and spaces, NTFS alternate data streams, control
      characters, and a bounded length.
- [x] Evaluate a second view when one further percent-decode changes the path, because some IIS
      rewrite chains decode twice and `%252e%252e%252f` is inert until they do.
- [x] Match every path segment and every extension position, so PHP path-info execution
      (`/uploads/shell.php/logo.jpg`) and `shell.php.jpg` are both covered.
- [x] `WP-PATH-001` — refuse an executable requested from `wp-content/uploads`, `upgrade` or
      `updraft`.
- [x] `WP-PATH-002` — refuse an executable requested from a build-output or asset-only directory.
- [x] `IIS-PATH-001` — report an unsafe path form as an observation.
- [x] Run before the body is touched, so a refusal costs no buffer, no parse and no sample.
- [x] Prove on real gateway traffic that Block refuses and Monitor forwards, and that ordinary
      WordPress, Elementor and Site Kit paths stay untouched in Block mode.

### What M2.5 does not cover

- **A shell in a directory that legitimately contains PHP.** The sixth shell in the incident sat in
  its plugin's own PHP directory under a name one character from a real one, and nothing about the
  path distinguishes it. Five of the six are refused; this one is not, and the test suite asserts
  that gap so closing it has to be deliberate.
- **Query strings and request bodies.** Only the path is inspected, and body inspection is unchanged
  from M2.
- **Responses.** The exploitation traffic was distinguishable by its responses — 200 with a 24-byte
  body for a probe, 500 for the payload — and WPShield does not look at responses at all.

## M2.6 — Triage tool

> The other half of what the compromise taught. M2.5 closed the gap the incident exposed in the
> gateway; this puts the investigation itself into the repository, so that the next person to find a
> strange file on a Windows WordPress host does not have to reinvent an afternoon of ad-hoc
> PowerShell. A gateway protects a site going forward. It says nothing about a site that was already
> compromised before the gateway arrived — which was the situation this project was actually
> deployed into.
>
> See [triage tool](docs/en/triage-tool.md) for the complete behaviour.

- [x] `scripts/Invoke-WPShieldTriage.ps1` — read-only triage, fully parameterized, with no real
      hostname, path or topology anywhere in it.
- [x] Discover WordPress installations from IIS rather than assuming a layout, with an explicit
      `-DiscoverOnly` first pass for a host the operator does not know.
- [x] Nine checks, each traceable to something the incident actually showed: executables in data and
      asset directories, a `web.config` below the site root, names Windows will not store literally,
      PHP that can run what a request sends it, timestamp-named dropper markers, the creation-after-
      modification skew a mass-rewriter leaves, IIS log correlation per artifact, and a component
      inventory.
- [x] Emit findings as JSON Lines **in the gateway's own log envelope**, so a forensic report and a
      gateway log are read by one parser and correlated on the same field names.
- [x] Report, for every artifact, whether WPShield would refuse a request to it — including when it
      would not.
- [x] Carry no file contents and nothing outside ASCII, so a report is safe to attach to a public
      issue and cannot carry an escape sequence into whoever reads it.
- [x] Verify the scripts in CI: they parse under PowerShell 7 and Windows PowerShell 5.1, they are
      pure ASCII, the triage tool has no write path but its own report, its copy of the gateway's
      rule vocabulary has not drifted, and it runs end to end against a fixture and reaches the
      right verdicts.

### What M2.6 does not cover

- **A verdict.** It reports; it does not decide, and it never repairs. Deleting a webshell before
  understanding how it arrived destroys the evidence and leaves the way in.
- **A clean bill of health.** It reads what is on disk today. An intruder who cleaned up leaves a
  disk that looks healthy, and a run with no findings says only that.
- **The database.** Injected `wp_posts` and `wp_options` content, and an attacker's administrator
  account, are invisible to it.
- **Alternate data streams.** A stream suffix in a *name* is reported; the tool does not ask each
  file whether it carries hidden streams, which would be one more system call per file across tens
  of thousands of them.
- **Proof of read-only-ness.** The gateway's disk-freedom guarantee is proved by scanning assembly
  type references. A script has no equivalent, so what CI enforces is an inventory of write-capable
  constructs plus a ban on the two — invocation through a variable, and `Invoke-Expression` — that
  would let a command escape it. That is weaker, and the documentation says so rather than implying
  otherwise.

## M2.7 — Network-layer blocking

> Pulled forward because a production host crashed repeatedly with `0x00000133 —
> DPC_WATCHDOG_VIOLATION` traced to `mwac.sys` (Malwarebytes Web Access Control), and because four
> weeks of that tool's log showed 17% of blocked inbound connections going to services the gateway
> never sees. The first implementation (2026-10-20) could not block and was replaced; the decision to
> block at the network layer at all is [ADR 0006](docs/en/adr/0006-network-layer-blocking.md), which
> supersedes the network half of ADR 0002 and is **Proposed** until a maintainer accepts it.
>
> See the [network filter design](docs/en/network-filter-design.md).

Implemented and tested through a fake driver:

- [x] Enforcement through WinDivert `DROP` handles whose filter matches only the block set. No
  reinjection exists: `WinDivertSend` is not declared.
- [x] Observation through a `SNIFF | RECV_ONLY` handle on new inbound SYNs only.
- [x] `WP-NET-001` block list, `WP-NET-002` connection attempts per minute, `WP-NET-003` distinct
  ports per minute, with bounded per-source state.
- [x] Monitor by default; Monitor never constructs the enforcer.
- [x] Allow-list applied at insertion and at filter build; lockout guard on the registry's RDP port.
- [x] SYN evidence blocks only with `--syn-rules-may-block`.
- [x] Dynamic blocks expire; the block set has a ceiling; nothing is persisted.
- [x] `WINDIVERT_FLAG_NO_INSTALL` unless `--install-driver`; `WinDivert.dll` from the assembly
  directory only.
- [x] Self-test with the real library's compile and evaluate helpers gates Block mode; `--check`.

Not yet done:

- [ ] ADR 0006 accepted.
- [ ] Self-test passed against the real WinDivert 2.2.2 library.
- [ ] First run against the driver on a development machine (the test plan in the design document).
- [ ] A week of Monitor mode on a production host before any Block mode there.

### What M2.7 does not cover

- **Outbound, UDP and ICMP traffic.** The observer sees inbound TCP connection attempts only.
- **Payloads and TLS.** Only IP and TCP headers are read.
- **Persistence.** Blocks do not survive a restart, by design.
- **Kernel code.** WPShield ships none; WinDivert is an external, signed driver the operator installs.

## M2.8 — Security event log monitoring

> Pulled forward because a production host was observed receiving sustained attacks on Remote
> Desktop. `wpshield security-monitor` reads the Windows Security event log and reports RDP
> brute-force and failed-logon patterns.
>
> See the [security monitor design](docs/en/security-monitor-design.md).

- [x] `src/WPShield.SecurityMonitor/`, read-only, Windows-only; `WP-SEC-001` and `WP-SEC-002`.
- [x] `security-monitor` CLI verb.
- [x] `WPShield.Integration.NetworkFilterBlockListSink` turns a Block finding into a block request on
  the network filter, graded as non-spoofable evidence.
- [ ] Read the Security log by subscription (`EventLogWatcher`, new events only). The current reader
  replays the whole log into memory on its first scan.
- [ ] `WP-SEC-001` to recognise failed RDP logons under NLA, which are recorded as `LogonType 3`.
- [ ] Wire the sink into `network-filter` once the reader reads new events only.

### What M2.8 does not cover

- **Other event logs.** Only the Security log is read; System and Application logs are out of scope.
- **RDP session contents.** Only authentication events (logon success/failure) are visible, not
  session contents or credentials.

## M3 — Rate limiting and automated behavior

> **M3 refuses requests. It does not touch the firewall.** [ADR 0002](docs/en/adr/0002-host-level-brute-force-defence.md) records why HTTP brute-force defence belongs here, inline, where the real client address is already resolved. Its network half (RDP, FTP, SMTP, SQL) is superseded by [ADR 0006](docs/en/adr/0006-network-layer-blocking.md), Proposed: handle-scoped drops in `network-filter` (M2.7), never Windows Firewall rules.

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
- [x] Store privacy-safe JSON Lines with rotation, size limits and retention. **Restricted permissions are not done here**: the gateway creates the log directory but does not set its ACL, because logs carry real hostnames, real paths and real client addresses, and locking that down belongs to the M6 installation procedure rather than to configuration. Documented in [operator configuration](docs/en/operator-configuration.md#log-files).
- [ ] Add automated redaction tests for sensitive headers, secrets, forms, query strings, and upload content.

## M5 — Local multilingual dashboard

- [ ] Bind management access to 127.0.0.1 initially.
- [ ] Add English and Spanish views for summary, sites, events, rules, health, configuration, versions, export, and diagnostics.
- [ ] Add CSRF protection and design Windows-authenticated administrative access before any remote use.
- [ ] Keep detailed rule evidence available only to authorized administrators.

## M6 — Windows Service and releases

- [x] Publish self-contained `win-x64` artifacts. `wpshield publish` builds them, refuses to package `appsettings.Local.json`, checks the binary version against `Directory.Build.props`, and emits an archive with a SHA-256 beside it. Self-contained on purpose: the target is a shared host, and somebody else's patch to a shared runtime must not be able to stop the gateway.
- [x] Run under the Windows service control manager, under the **virtual account `NT SERVICE\WPShield`**: no password stored anywhere, no account to manage, and a per-service identity that can be named in an ACL. It gets read and execute on the program files and modify on the logs, and nothing else.
- [x] **Preflight.** `wpshield preflight` checks, read-only, that the ADR 0001 traffic path can work here before anything is installed: the two ARR settings that fail silently on the live site, port ownership, the site inventory, existing rewrite rules, and whether unprivileged accounts can read the log directory. It prints the configuration and the rewrite rule to use, filled in from what it found, and writes nothing.
- [x] Provide installation, update, uninstall, bypass, rollback, and recovery procedures. `wpshield install` and `wpshield uninstall`, both with `-WhatIf`, neither touching IIS. The bypass is documented as what it actually is: **once the rewrite rule is live, stopping the service does not bypass WPShield, it takes the site down** - the rollback control is the rule, not the service. The uninstaller refuses to run while it can see an enabled WPShield rewrite rule, and equally refuses when it cannot read IIS at all.
- [x] Add restricted configuration and log directories. The install replaces the permissions on both with three entries - SYSTEM, Administrators, and the service account - granted by well-known SID rather than by name, with inheritance disabled and the inherited entries discarded rather than copied. A CI check exercises that code against a real directory.
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
