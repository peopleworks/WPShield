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
- [x] **The exposure family**, chosen against a week of real IIS logs: `.env` (`EXPOSE-PATH-001`),
      version control (`002`), credential stores (`003`), backup copies (`004`) and database dumps
      (`005`, observes), IIS and ASP.NET configuration (`IIS-PATH-002`), ASP.NET Core settings
      (`NET-PATH-001`, observes), PHPUnit (`PHP-PATH-001`) and `phpinfo` pages (`PHP-PATH-002`,
      observes). Every one a shape in any segment, never a scanner catalogue's list of paths, and
      ordinary .NET and Blazor traffic asserted to score zero. `/admin` is deliberately not a rule.
- [x] Assert that every rule the packages ship is a rule the gateway runs, so a forgotten
      registration fails a test instead of shipping a rule that never evaluates.

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

## M2.7 — Network layer packet filtering

The legacy WinDivert engine opened a sniff handle, which copies packets. Discarding a copy
leaves the original in transit. The CLI refuses `network-filter` before accessing a driver.

- [x] Network inspection contracts and unit-tested block-list, rate and port-scan rules.
- [ ] Host-wide packet enforcement. [Draft PR #86](https://github.com/peopleworks/WPShield/pull/86)
  tracks a replacement using Windows Filtering Platform dynamic sessions and its validation on a
  disposable host. Acceptance includes proving that a connection is blocked and access returns
  after the enforcing process exits.

## M2.8 — Security event log monitoring

The CLI reads the Windows Security event log and reports RDP brute-force and failed-logon
findings. The integration library has an in-memory block-list sink. Packet enforcement remains
pending under M2.7. [Security monitor design](docs/en/security-monitor-design.md)

- [x] `src/WPShield.SecurityMonitor/` — Windows-only Security event log reader (`net10.0`, declared
  `SupportedOSPlatform("windows")`), and the evidence collector the service hosts (ADR 0007).
- [x] `SecurityInspectionContext`, `SecurityInspectionResult`, `ISecurityInspectionRule`, and
  `ISecurityEventSink` contracts in `WPShield.Abstractions`.
- [x] `WP-SEC-001` — RDP brute force detection (failed Logon Type 10 per source IP per window).
- [x] `WP-SEC-002` — Generic failed logon detection (Event ID 4625 per source IP per window).
- [x] `SecurityEventMonitor` — read-only Security log scanner with sliding-window failure counting.
- [x] `SecurityEventBuilder` — assembles default rule set from `SecurityEventConfiguration`.
- [x] Same JSON Lines log envelope as the gateway and triage tool for forensic correlation.
- [x] Windows-only project; requires Administrator privileges to read the Security log;
  platform-independent projects remain buildable and testable on Linux.
- [x] `src/WPShield.Integration/` — optional bridge project targeting `net10.0-windows`.
- [x] `NetworkFilterBlockListSink` — `ISecurityEventSink` implementation that adds
  blocking source IPs to `WPShield.NetworkFilter.Rules.BlockListRule`.
- [ ] End-to-end enforcement from an authentication finding, including expiry and recovery.

### What M2.8 does not cover

- **Real-time blocking.** `ScanOnce()` is polling-based; it does not subscribe to live event streams.
- **Other event logs.** Only the Security log is read; System and Application logs are out of scope.
- **RDP session contents.** Only authentication events (logon success/failure) are visible, not
  session contents or credentials.

## M3 — Rate limiting and automated behavior

> **M3 refuses requests. It does not touch the firewall.** [ADR 0002](docs/en/adr/0002-host-level-brute-force-defence.md) records why: a brute-force blocker's job is to modify firewall rules automatically, which is the inverse of an invariant this project depends on for deployment onto shared hosts. The HTTP half belongs here, inline, where the real client address is already resolved; RDP, FTP, SMTP and SQL belong to a sibling project with its own safety contract.

> Per-IP limiting is meaningless until WPShield can resolve the real client address. Under the
> traffic path chosen in [ADR 0001](docs/en/adr/0001-production-traffic-path.md) every request
> arrives from a local proxy, so `Gateway:TrustedProxies` had to exist before this milestone could
> start. **It now does**, pulled forward from M7 because it is a prerequisite for both milestones and
> because leaving it undone makes WordPress generate `http://` URLs behind an HTTPS site. See
> [operator configuration](docs/en/operator-configuration.md#trusted-proxies).
>
> The multipart buffer limit now covers reading, inspection and forwarding, until the buffer is
> disposed. `Gateway:Multipart:MaximumConcurrentInspections` defaults to 10, with a ceiling of 50.
> Monitor forwards uninspected with a warning at capacity; Block returns 429.

- [x] Bound concurrent retained multipart buffers, including during forwarding.
- [x] Add fixed-window budgets per resolved client, site and configured rule, with IPv4 and IPv6 support. Normalized path aliases, including the extra decode view, share a budget.
- [ ] Define separate policies for login, XML-RPC, uploads, REST, and administrative AJAX.
- [ ] Add expiring temporary blocks and configurable exceptions.
- [ ] Preserve Elementor and legitimate `admin-ajax.php` traffic.
- [ ] Document that WPShield does not provide volumetric DDoS mitigation.

## M4 — Observability

- [x] Isolate the active gateway policy from offline analysis. Default options readers share the validated startup settings, and final evidence identifies the activation that served the request. See [operator configuration](docs/en/operator-configuration.md#configuration-is-not-hot-reloaded).

- [x] Emit versioned final request evidence with build/configuration activation identifiers, separate path/upload completeness, and actual forwarding/refusal/failure outcomes. See [request evidence](docs/en/request-evidence.md).
- [x] Measure observed evidence loss independently of file logging, report source coverage and provide a per-site community export. See [metrics and limits](docs/en/request-evidence.md#measuring-evidence-loss).
- [x] Add bounded offline comparison of recorded inspection scores against candidate Monitor/Block thresholds, with per-site coverage and explicit exclusions. See [policy preview](docs/en/policy-preview.md); content-rule replay, policy application and durable-log completeness remain outside this feature.
- [ ] Emit structured gateway, routing, inspection, rule, backend, and configuration events.
- [ ] Add per-site request, action, rule, byte, error, and duration metrics.
- [x] Store privacy-safe JSON Lines with rotation, size limits and retention. **Restricted permissions are not done here**: the gateway creates the log directory but does not set its ACL, because logs carry real hostnames, real paths and real client addresses, and locking that down belongs to the M6 installation procedure rather than to configuration. Documented in [operator configuration](docs/en/operator-configuration.md#log-files).
- [x] Add automated redaction tests for sensitive headers, secrets, forms, query strings, and upload content. Request log paths use normalized values so control characters cannot reach log consumers.

### Host traffic monitor for Windows Server

- [x] Add a passive TCP/UDP flow view for one operator-selected adapter. Explicit port selection,
      read-only local display, direction, observed IP bytes, bounded retention and capture counters
      are implemented in [the flow view](docs/en/network-sensor-design.md#host-flow-view).
- [x] Verify with synthetic traffic that an incoming HTTPS-port connection and its replies share
      a flow, a separately initiated outbound connection appears independently and midstream TCP
      and UDP report an unknown initiator.
- [ ] Validate live capture on Windows Server with Npcap and named service ports.
- [x] Offer versioned offline registry names in the local listener inventory. [Offline port hints](docs/en/network-sensor-design.md#offline-port-hints)
- [x] Filter local listeners by protocol and exact bound address with numeric IPv4 and IPv6 ordering. [Local listener inventory](docs/en/network-sensor-design.md#local-listener-inventory)
- [x] Export a minimal reference for one selected RDP, SQL or IIS observation from a saved CLI snapshot. [Selected audit reference](docs/en/network-sensor-design.md#selected-audit-reference)
- [x] Report timestamped owner PIDs for local TCP and UDP endpoints on IPv4 and IPv6. [Observed owner PID](docs/en/network-sensor-design.md#observed-owner-pid)
- [x] Inventory local TCP listeners and UDP bindings with per-protocol timestamps and coverage. [Local listener inventory](docs/en/network-sensor-design.md#local-listener-inventory)
- [x] Report capture state, port scope and audit source availability in local monitor snapshots. [Source status](docs/en/network-sensor-design.md#source-status)
- [x] List local Npcap device IDs and IP families before choosing one adapter for flow monitoring.
- [x] Add bounded CLI traffic history with observed IP bytes per second in each direction,
      UTC intervals and explicit gaps. [Traffic history](docs/en/network-sensor-design.md#traffic-history)
- [x] Correlate observed incoming Remote Desktop flows with local Windows Security logon events
      and show the matching record IDs. Missing or ambiguous evidence leaves the outcome unknown.
- [x] Read existing SQL Server login outcomes for a single local instance from the Windows
      Application log. Preserve its record IDs and keep TCP flow attribution unknown.
- [x] Inspect site-scoped W3C records for IIS login evidence, including unknown attribution and
      corroborated Windows logon failures. [Offline reader](docs/en/iis-login-evidence.md)
- [ ] Corroborate service activity and authentication outcomes with Windows Security and richer SQL Server audit
      evidence. Keep the outcome unknown when the records are missing. On shared
      hosts, site attribution requires independent evidence.

### Windows service protection benchmark

- [ ] Compare WPShield with RdpGuard across the 14 service surfaces in the
      [benchmark plan](docs/en/host-protection-benchmark.md). Prioritize Remote Desktop, SQL Server
      and IIS web logins because those are the services the operator needs to defend first.
- [ ] Publish results by service and version for attribution, false positives, time to detection,
      resource use and recovery. Record observation, detection and verified prevention separately.
      A packet seen on a service port does not establish an authentication outcome.
- [ ] Evaluate host-wide enforcement separately under [ADR 0002](docs/en/adr/0002-host-level-brute-force-defence.md).
      The monitoring benchmark starts in Monitor mode and leaves firewall policy under operator control.

## M5 — Local multilingual dashboard

- [x] Open the local listener inventory in a bilingual Windows desktop window with keyboard navigation and manual or timed refresh. [Desktop monitor](docs/en/network-sensor-design.md#desktop-monitor)
- [x] Chart Windows adapter counters with explicit measurement gaps and pause the display independently of sampling. [Adapter traffic](docs/en/network-sensor-design.md#adapter-traffic)

- [x] Select a saved RDP, SQL Server or IIS audit reference with the keyboard and copy its minimal JSON from the desktop monitor. [Selected audit reference](docs/en/network-sensor-design.md#selected-audit-reference)
- [x] Plot interval history from the host monitor for one adapter and selected ports. Pausing the view keeps capture running. [Traffic history](docs/en/network-sensor-design.md#traffic-history)
- [x] **Server posture, the dashboard's first data source.** `wpshield audit` reads, and never
  changes, the IIS configuration that decides whether one compromised site stays one: pools running
  as an administrator, pools sharing a built-in identity, PHP mapped for every site, site folders
  anyone can write, and a catch-all site over the others. See [Audit](docs/en/audit.md). Its checks
  are tested against constructed snapshots; the IIS reader has not yet run against a real IIS host.
- [ ] Extend the posture audit beyond IIS: module and system binary signatures, WMI subscriptions,
  cleared event logs, firewall rules open to any address, Defender history, and a web shell's
  signature in the IIS logs. Read-only, like the rest. Listening ports with their owner PIDs and
  live Remote Desktop logon outcomes already exist in the host monitor
  ([local listener inventory](docs/en/network-sensor-design.md#local-listener-inventory),
  [Remote Desktop logon evidence](docs/en/network-sensor-design.md#remote-desktop-logon-evidence));
  the audit does not read them yet, compares no port with the firewall, and keeps no history of
  sign-ins by source.
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
