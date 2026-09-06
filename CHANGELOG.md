# Changelog

All notable changes to WPShield are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) with one addition — a `Known limitations`
section, because in a research preview what a change does not yet cover matters as much as what it
changes — and the project will follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it reaches its first release.

WPShield has **not** been released yet. Everything below is unreleased research-preview work, and
none of it is approved for production traffic. See [ROADMAP.md](ROADMAP.md) for the milestones that
must complete first.

## [Unreleased]

### Security

- **WPShield now inspects the request line of every request, and this one is not from a threat
  model.** A WordPress site on IIS was found running six webshells, and its server logs held the
  exploitation traffic in full. Every request that reached one was an ordinary `GET` or `POST` to an
  existing `.php` file, and **not one carried a body** — so not one was visible to any rule this
  project had. M2 inspects `multipart/form-data` and nothing else: it can refuse a shell as it
  arrives, and it cannot see a shell that is already there being used. Three rules close that half.
  `WP-PATH-001` refuses an executable requested from `wp-content/uploads`, `upgrade` or `updraft`,
  which are data directories WordPress never routes execution through. `WP-PATH-002` refuses one
  requested from a build-output or asset-only directory — `dist`, `build`, `node_modules`, `static`,
  `fonts`, `images` and their kin — where a script is either an intruder or a packaging accident.
  `IIS-PATH-001` reports an unsafe path form as an observation. **Five of the six recovered shell
  locations reach the default block threshold from the request line alone; the sixth does not, and
  the test suite asserts that gap** rather than leaving it as an impression.
- **Paths are normalized to what a Windows web server resolves, in two views.** Case, backslash
  separators, traversal, empty segments, trailing dots and spaces, NTFS alternate data stream
  suffixes and control characters, all bounded in segment count and length. Every segment is checked
  and every extension position within it, because `cgi.fix_pathinfo` makes
  `/uploads/shell.php/logo.jpg` execute `shell.php` while the last segment is an image. A second view
  is built when one further percent-decode changes the path, because some IIS rewrite chains decode
  twice and `%252e%252e%252f` is inert until they do — the same reasoning that made the upload rules
  evaluate WordPress's filename rewrite alongside the Windows one.
- The pass runs **before anything reads a body**, so a refused request costs no buffer, no multipart
  parse and no sample — strictly less than a forwarded one — and applies to the overwhelming majority
  of traffic that carries no body at all.
- **`assets`, `css`, `js`, `media` and `vendor` are deliberately absent** from the asset directory
  list, and that absence is the reason `WP-PATH-002` can score 100. Older plugins genuinely serve
  generated stylesheets and scripts from PHP, and a security tool that breaks a working site gets
  switched off, taking the rules that were right with it.

### Fixed

- **The triage tool's JSON escaper corrupted every Windows path it wrote.** Inside a `switch`,
  PowerShell's `continue` ends the switch and resumes the enclosing loop body rather than skipping
  it, so a matched character was escaped and then emitted again: every path separator came out as
  three backslashes and no parser would accept the report — which still looked fine to a person
  reading it. Rewritten with `if`/`elseif`, and the escaper now has a round-trip test of its own
  through a real JSON parser.
- **The triage tool could not read the one file most worth reading.** A name ending in a dot or a
  space cannot be opened through the ordinary Win32 path layer, which normalizes the name away
  before the request reaches NTFS — so the artifact whose name was itself the anomaly was also the
  artifact whose hash came back null. It now falls back to the verbatim `\\?\` form.
- **The synthetic backend in the integration suite could not serve any path containing a dot.** It
  used `MapFallback(handler)`, whose default `{**path:nonfile}` pattern rejects a path whose last
  segment contains one — the same defect this project already found and fixed in the gateway itself,
  surviving in the harness that was supposed to catch it. Every path in the suite was extensionless,
  so nothing noticed, and no test could have exercised `/wp-login.php` or a stylesheet even after the
  gateway was corrected.

### Added

- **A preflight check, because the production traffic path has four ways to fail on the live site
  with an error that does not say what is wrong.** `scripts/Invoke-WPShieldPreflight.ps1` is
  read-only and changes nothing. Two of the checks are the reason it exists: **ARR's server-level
  proxy switch is off by default**, and with it off a rewrite to `http://127.0.0.1:10000` does not
  proxy - it returns 404 for every request with nothing in the log explaining why; and **ARR does
  not preserve the client `Host` header by default**, and WPShield resolves the site from that
  header and fails closed with HTTP 421, so the whole site answers 421 the moment the rule goes
  live. It also reports port ownership, the site inventory, existing rewrite rules that the WPShield
  rule must be ordered against, whether a service already exists, and whether unprivileged accounts
  can read the log directory.
- **Preflight prints the configuration and the rewrite rule to use**, filled in from the sites it
  found, because those are exactly the values that get retyped and mistyped - and a mistyped
  hostname here is a 421 on a live site. The configuration is printed and never written: it belongs
  on that server, and a script documented as read-only stays read-only.
- **`PRE-016` is a blocker, not a warning.** `C:\ProgramData` is the conventional home for a log
  directory and its default ACL grants `BUILTIN\Users` read, so a WPShield log carrying request
  paths, rule hits and client addresses would be readable by every account on a server that runs
  other people's applications.
- **A triage tool, because a gateway says nothing about a site that was already compromised before
  it arrived.** `scripts/Invoke-WPShieldTriage.ps1` is the investigation that produced the rules
  above, generalized into something anyone can run: read-only, fully parameterized, discovering
  WordPress installations from IIS rather than assuming a layout. Nine checks, each traceable to
  something the incident actually showed — executables in data and asset directories, a `web.config`
  below the site root, names Windows accepts but does not store literally, PHP that can run what a
  request sends it, timestamp-named dropper markers, the creation-after-modification skew a
  mass-rewriter leaves behind, IIS log correlation per artifact, and a component inventory. It
  reads, and it never deletes, quarantines, renames, moves, repairs or executes anything: deleting a
  webshell before understanding how it arrived destroys the evidence and leaves the way in.
- **Every triage finding carries the verdict WPShield would return for a request to that file** —
  computed from the same directory lists, extension lists, summed scoring and thresholds the gateway
  uses. The run ends by counting how many artifacts the gateway would block and how many it would
  forward, and printing the second list in full. **A tool that only reported what its own product
  catches would be an advertisement**; this one prints the number that is sometimes not zero, and on
  the incident that produced it, was not. A fourth verdict, `not-applicable`, keeps `not-covered`
  meaningful: an uploaded `web.config` is remote code execution on IIS but not because anyone
  requests it, and folding it into the gap count would inflate the one number a reader acts on with
  a case no request-path rule could ever close.
- **Triage findings use the gateway's own log envelope**, field for field and timestamp format
  included, so a forensic report and a gateway log are read by one parser, sort together as text,
  and correlate on the same field names.
- **The triage report carries no file contents and nothing outside ASCII.** A report is written to
  be attached to a support thread or a public issue: one that reproduced the payload would
  distribute the webshell to everyone who read it, and a file name recovered from a compromised host
  can carry a control character or an ANSI escape sequence into a terminal, a log viewer, or a
  browser rendering an issue. Marker names, sizes, hashes and timestamps identify a file without
  republishing it.
- **CI now verifies the PowerShell scripts, which `dotnet build` never looked at.** They must parse
  under PowerShell 7 *and* under Windows PowerShell 5.1 — the version a Windows Server host has
  without anything installed on it — and they must be pure ASCII, because 5.1 reads a BOM-less
  `.ps1` as ANSI and a UTF-8 em dash becomes a typographic quote that silently breaks quote parity a
  hundred lines further down. That defect had already shipped a triage script that would not run.
  Both tools documented as read-only are additionally checked to have no write path but their own
  report, every copy of the JSON escaper is round-tripped through a real parser, and the triage tool
  is run end to end against a fixture reproducing the incident's directory structure, reaching the
  documented verdicts including the known gap. There is more than one copy of the escaper on
  purpose - each tool is a single file that has to work alone on a server where nothing may be
  installed - and testing every copy against the same cases is what keeps that duplication honest.
- **The triage tool's copy of the gateway's rule vocabulary is compared against the C# sources on
  every build.** It carries copies because it has to run on a server with no .NET runtime and no
  build of WPShield on it. Copies drift, and a drifted copy does not fail loudly — it quietly
  reports coverage the gateway does not have, which is worse than reporting nothing.
- **A JSON Lines log destination, because in Monitor mode the log is the only thing WPShield
  produces.** Until now every line went to the console, and under a Windows service the console is
  nowhere: a gateway could observe an entire rollout and tell no one. One JSON object per line, with
  both the rendered message and the structured fields, so the file is readable by a person tailing it
  and parseable by whatever aggregates it later. Rotation by size and by UTC date, retention by file
  count, and a bounded queue that **drops rather than blocks** when the disk cannot keep up — because
  blocking the request path on disk I/O turns a slow disk into an outage and an unbounded queue turns
  it into an out-of-memory failure, while dropping is the only one of the three the log can
  afterwards admit to. It does: the count of lost entries is written into the file as soon as the
  pressure clears. Disabled by default in code and enabled in the shipped `appsettings.json`, so a
  deployment gets a log while the test host, which configures itself in memory, never opens a file.
- **`WPShield.Logging`, a separate assembly, for one structural reason.** `AGENTS.md` requires the
  gateway's disk-freedom to be a property of the code rather than of a configured threshold, and a
  test enforces it by scanning the `WPShield.Gateway` assembly for any reference to `File`,
  `FileStream`, `Directory` or `FileBufferingReadStream`. That scan is assembly-wide and cannot tell a
  log line from a request body, so putting the writer in `WPShield.Gateway` would have forced the
  guard to be relaxed — and a guard relaxed once is a guard that erodes. The only code that opens a
  file now lives in its own assembly, which leaves the test exactly as strict as it was written and
  makes the claim stronger than an exclusion list could: the assembly that handles requests does not
  merely avoid the file APIs, it cannot name them.
- **The gateway runs as a Windows service** when the service control manager starts it, and is
  unchanged when anything else does. The content root is pinned to the installation directory before
  the host is built, because a service starts in `C:\Windows\System32` and the host refuses a content
  root that changes afterwards. The Windows Event Log is attached as a second destination, so a
  gateway that fails to start says why somewhere an operator will find it.

### Fixed

- **Log retention would have deleted the newest files of a busy day and kept the oldest.** Rotated
  names used a `-` ordinal, and `-` (0x2D) sorts before `.` (0x2E), so `wpshield-20260906-1.jsonl`
  compared as older than the `wpshield-20260906.jsonl` it actually succeeds. Found before the code
  shipped rather than after; the separator is now `_`, which sorts after the extension dot, and the
  ordinal is zero-padded so `_0002` stays below `_0010`.

### Security

- **`Gateway:TrustedProxies` makes the "never trust forwarding headers" invariant conditional, and
  narrowly.** ADR 0001 places WPShield behind IIS, where every request arrives from a local proxy;
  stripping every forwarding header there attributes every visitor to `127.0.0.1` and — the part
  that breaks a live site rather than degrading it — tells WordPress the request arrived over HTTP,
  so it generates `http://` canonical URLs, redirects and login targets behind an HTTPS site.
  Trust is now granted to a **peer address**, never to a header, and it unlocks exactly two headers:
  `X-Forwarded-For` and `X-Forwarded-Proto`. `Forwarded`, every other `X-Forwarded-*` variant, the
  whole client-address family, the `X-Original-URL` and `X-Rewrite-URL` path-override vectors and
  `X-WPShield-Request-ID` stay stripped from every peer, trusted included — a path-override header
  does not become legitimate because a proxy presented it, and the loop-prevention condition in the
  IIS rewrite rule depends on a client being unable to set the correlation header. The list is empty
  by default, which reproduces the previous behaviour exactly, so an operator who never configures it
  is never less safe than before.
- **The rightmost `X-Forwarded-For` entry wins, and trusted entries are deliberately not skipped.**
  A proxy appends the address it actually saw, so the rightmost entry is the only one the trusted hop
  wrote and everything to its left is client-supplied. The conventional right-to-left walk that skips
  entries matching a trusted proxy is the classic spoof: a client sends
  `X-Forwarded-For: 8.8.8.8, 127.0.0.1`, the skip steps over the trusted-looking entry, and the
  attacker has pinned their own address. WPShield resolves that request to `127.0.0.1`. Configuration
  accepts exact IP addresses only; a CIDR range is refused rather than unimplemented, because these
  entries decide whose headers become authoritative and a range one bit too wide hands that to
  strangers. A resolved scheme is a canonical `http` or `https` literal rather than the received
  bytes, so nothing attacker-controlled reaches `$_SERVER` even after the comparison succeeds.
- **The inspection engine now runs on gateway traffic.** Until this change it never had.
  `GatewayApplication` resolved the site, checked the request size and forwarded, and the
  `WPShield.Gateway` project did not even reference `WPShield.Rules.WordPress` — every rule this
  repository documents executed only from the `WPShield.Service` console demonstration. WPShield was,
  in practice, a reverse proxy with a size limit and an unknown-host rejection, while its own README
  described detection that never happened on a real request. `multipart/form-data` requests are now
  parsed, sampled, evaluated by all eight rules, and forwarded or refused according to the site's
  protection mode.
- **Routing could never have reached a WordPress upload.** `app.MapFallback(handler)` defaults to the
  pattern `{**path:nonfile}`, and the `nonfile` constraint rejects any path whose last segment
  contains a dot. That default is written for single-page applications; in a reverse proxy it is
  catastrophic and silent. Measured on this build before the fix, `GET /wp-login.php` returned 404
  from WPShield with the backend untouched while `GET /wp-login` returned 200 — so `/index.php`,
  `/wp-admin/async-upload.php` and every `.css`, `.js` and `.jpg` were never proxied, and the
  existing integration suite never caught it because all of its paths are extensionless. It mattered
  specifically for this milestone: WordPress uploads post to `/wp-admin/async-upload.php`, so the new
  inspection step could not have run on a single real upload no matter how correctly it was wired.
  The pattern is now explicit.
- Added a bounded multipart reader that fails closed on anything it cannot parse the same way the
  backend will. Exactly one `Content-Type` header line is accepted, because Kestrel does not reject
  duplicates and `HttpRequest.ContentType` joins them with `", "` — if WPShield parses one value
  while IIS or PHP parses the other, WPShield inspected a different request than the one that
  executes. Boundaries are limited to RFC 2046 `bchars` and 70 characters, keeping CR, LF, `"`, `;`
  and `\` out of the parser. A part carrying two `filename` parameters is refused, because this
  parser takes the first and PHP's takes the last. Both `filename` and `filename*` are read and each
  is inspected, because ASP.NET Core's own `AsFileSection()` prefers `filename*` while PHP reads only
  `filename`, so `filename*=UTF-8''photo.jpg` alongside `filename="shell.php"` is a request that is
  deliberately two files at once.
- **Exceeding a reader limit is itself a finding, never a silent forward.** File, field, part-header,
  boundary and file-name limits each have a default and a hard ceiling that configuration may lower
  and never raise, and hitting one is reported under the gateway pseudo-rule `GATEWAY-MULTIPART-001`.
  Had "the reader gave up" meant "forward it", an attacker could prefix a payload with twenty-one
  dummy files and buy an uninspected forward for the twenty-second — a zero-knowledge bypass of every
  rule WPShield ships.
- Added `FILE-TYPE-001`, which compares the final extension against the leading bytes: script text or
  an `MZ`/ELF header where a binary format was claimed scores 70, plain text scores 40, and neither
  blocks alone. The declared `Content-Type` deliberately never triggers it — browsers derive it from
  the same extension and curl, wp-cli, mobile applications and the plupload fallback all legitimately
  send `application/octet-stream` — so it is recorded as a four-state token and no attacker-supplied
  header text reaches a log.
- Added `PHP-CONTENT-002`, which detects the `GIF89a;`-plus-PHP polyglot that has defeated WordPress
  upload validation for a decade. It scores 85 and blocks alone, but fires only on structural proof:
  a `getimagesize()`-set signature at offset 0 plus a validated PHP marker that a bounded walk shows
  lies after the GIF trailer, after PNG `IEND`, after JPEG `EOI`, or beyond a BMP or RIFF declared
  length. It has to be a proof rather than a heuristic, because it is a strict subset of
  `PHP-CONTENT-001`, whose 75 is therefore always already on the board — so any co-firing score of 5
  or more crosses the block threshold and there is no score at which the rule is a moderate signal.
  A marker inside XMP, EXIF or a `tEXt` chunk is below the boundary and never searched, so a
  developer who uploads a screenshot of PHP code with the code in its caption gets an Observe from
  `PHP-CONTENT-001` and nothing from this rule.
- Block mode now refuses uploads instead of only recording them: 403 `upload_blocked` for a content
  decision, 415 `multipart_not_inspectable` for a body that could not be inspected, and 408
  `request_timeout` for a body that did not fully arrive. The 408 applies in Monitor too, on the
  precedent the 413 already set — a half-arrived body is not a finding but a request the client
  failed to deliver, and forwarding it would hand WordPress a body shorter than its declared
  `Content-Length`. Refusal bodies carry the request identifier and the triggering rule identifiers,
  and never the file name, the field name, the sample, the evidence, the site identifier, or the
  score. The identifiers are disclosed because the complete rule catalogue is already published here,
  so withholding them protects nothing an attacker cannot read while the cost falls entirely on a
  site owner staring at an opaque refusal. The score is withheld for the opposite reason: a binary
  allow/deny forces a blind search, while a numeric score turns evasion into hill-climbing.
- Fixed a header bug that had made two documented promises false. `HttpResponse.Clear()` is an
  extension method that clears the status code, the reason phrase **and the headers**, and both the
  413 and the 502 writers called it — wiping the `X-WPShield-Request-ID` and `X-Content-Type-Options`
  headers the first middleware had set. The README claimed every response, forwarded or generated,
  carried both. The 421 path never called `Clear()` and was unaffected, which is exactly why the
  inconsistency survived: it was invisible unless you compared two failure responses side by side.
  Every generated response now goes through one writer that re-sets both headers plus
  `Cache-Control: no-store`, so there is one place to review rather than four. A test asserts all
  three headers on a generated 403; the suite previously asserted the correlation header only on a
  forwarded 200, which is precisely why the gap went unnoticed.
- The request-body limit is now installed before the inspection step rather than immediately before
  the forward. A chunked body declaring no `Content-Length` would otherwise have been buffered
  without a limit — the exact hole that stream exists to close.
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
- Vulnerability reporting no longer depends on a single repository setting. `SECURITY.md` now
  carries an email fallback with a subject tag, because private vulnerability reporting is a setting
  that can be off — it is off today — and the advisory form it pointed at returns 404 to everyone
  who is not a maintainer. A security policy that forbids public issues while its only reporting
  route is dead leaves a researcher with nowhere to go.

### Added

- A `Gateway:Multipart` configuration section, and a bilingual document for it at
  [bounded multipart inspection](docs/en/m2-multipart-inspection.md) and
  [inspección multipart acotada](docs/es/m2-inspeccion-multipart.md), covering every limit and its
  ceiling, the Monitor/Block matrix with its status codes, the memory the buffered path now costs and
  the operator levers that bound it, and a section naming what M2 still does not do. Out-of-range
  values prevent startup rather than being clamped, because an operator who asks for
  `"MaximumFileCount": 100000` and quietly gets 100 has been told nothing. `SampleBytes` has a floor
  of 512, not 1: below that the text-versus-binary classification degrades and the two content rules
  would be disabled by a number that reads like a performance knob while the configuration still said
  `"Enabled": true`.
- `Gateway:Multipart:Enabled: false` as an operator escape hatch. It returns the gateway to pure
  streaming, and it logs a warning on every start while it is off, because a gateway with inspection
  disabled is a reverse proxy with a size limit and nobody should end up in that state without
  noticing.
- Project identity and figures: a hero image in light and dark, a social preview card, and the two
  figures the README argues with — the gap between the extensions a rule set written for Linux
  hosting watches and the ones IIS executes, and how host resolution fails closed on an unknown
  `Host`. Every figure carries paragraph-length alternative text stating its argument rather than
  naming the picture. Until now the README argued only through mermaid, which no screen reader
  reads and which does not render outside GitHub.
- A project site at `site/index.html`, published by `.github/workflows/pages.yml`, for the evaluator
  who will not read a four-hundred-line README. It is also the one surface where the
  not-approved-for-production framing is unmissable instead of a callout to scroll past.
- A release workflow on `v*` tags. It runs the full suite, refuses to publish when the tag and
  `<Version>` disagree, starts the published gateway on loopback and requires it to report ready and
  print its resolved site table before anything ships, publishes a SHA-256 checksum beside the
  archive because these builds are not code signed, and marks every release a prerelease so the
  "Latest release" link never points at a runnable research preview. NuGet packages, a .NET tool and
  a container image are deliberately not published, and the workflow records why.
- `<Version>0.2.0</Version>`, assembly ownership metadata, deterministic builds and Source Link in
  `Directory.Build.props`. Every assembly previously took the SDK default and reported
  `AssemblyVersion 1.0.0.0`, so a `WPShield.Gateway.dll` sitting on an operator's disk announced
  itself as version 1.0 of a component the README calls a research preview. Source Link answers the
  question that matters before a binary goes into a request path: was it built from the commit I
  read?
- The complete Contributor Covenant 2.1, with a named enforcement contact and a section specific to
  this project — never paste a real hostname, credential, customer log or working payload into an
  issue, and offensive use of the project is itself a conduct violation. The previous file claimed
  adherence in five lines and named nobody to report to.
- `NOTICE.md`, which states that the project is independent of Microsoft, of Automattic and of every
  plugin vendor, names the third-party marks the documentation uses, and records that the rules
  encode publicly-known attack surface while no working exploit code is distributed.
- A Spanish translation of the threat model at `docs/es/modelo-de-amenazas.md`. It was the only
  substantive user-facing document without a Spanish counterpart, in a project whose own rule is
  that user-facing documentation exists in both languages.
- `docs/README.md`, a bilingual index of everything under `docs/`, carrying the same list as the
  README so a reader who opens the folder and a reader who arrives from the README see the same set.
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

- **The "avoid buffering complete uploads in memory" invariant was restated rather than quietly
  broken.** `AGENTS.md` carried that line and `ROADMAP.md` carried "parse multipart requests without
  buffering complete uploads or writing them to disk". Both predate Block mode existing. To block,
  the gateway must decide before forwarding; to forward, it must read the body a second time; and a
  network stream cannot be read twice. The choice was between buffering a multipart body and having
  no Block mode for uploads at all. What is guaranteed now is narrower and checkable: **never to
  disk**, **never unbounded**, and **only for multipart**. The buffer is a pooled in-memory structure
  that contains no file API at all, so disk-freedom is structural rather than a threshold value a
  future edit could raise — `FileBufferingReadStream` was rejected for precisely that reason, since a
  guarantee a contributor can undo by changing one number is not the guarantee an unqualified "do not
  store suspicious uploads on disk" asks for. Chunks are 64 KiB because `ArrayPool<byte>.Shared`
  rounds a 6 MiB rental up to 8 MiB, wasting a third of it and parking a large-object-heap allocation
  per concurrent request. `AGENTS.md` also gained the three invariants this milestone froze:
  non-multipart traffic must never pay the buffering cost, a reader limit breach must fail in the
  safe direction, and inspection evidence uses the normalized name only.
- `THREAT_MODEL.md` grew from twenty-one lines of unadorned bullets into thirteen numbered threats,
  each stating the attacker capability assumed, the rule identifier or gateway behavior that answers
  it, its status, and what stays unmitigated — followed by the safeguards, the residual risk and the
  assumptions that would invalidate the whole model. It had not been touched since the project
  became Windows-specific, so `web.config` as remote code execution, the extensions IIS executes,
  the Windows file name collapse and the path-override headers — the four things recent commits were
  written to address — were all missing from the document that the README, `SECURITY.md` and
  `AGENTS.md` point at as this project's security reasoning.
- The internal Spanish master plan moved from `DEVELOPMENT_PLAN.md` at the repository root to
  `docs/es/plan-de-desarrollo.md`. Two plans sat at the root with nothing saying which one governed;
  the moved file now states that `ROADMAP.md` wins wherever the two disagree. Its section that
  reproduced `AGENTS.md` verbatim was replaced by pointers to the live files: that copy had aged
  into "do not trust inbound X-Forwarded-* headers" long after the gateway began stripping the whole
  untrusted set, and an agent following the plan literally would have reopened a hole that was
  closed on purpose. Instruction files get exactly one copy each.
- The issue chooser no longer routes people to features that are switched off. Private vulnerability
  reporting and Discussions are both disabled on the repository, so both contact links were dead
  ends for anyone who is not a maintainer. They now point at `SECURITY.md`, which carries the
  private form and the email fallback, at operator configuration for the questions that do not need
  an issue, at the privacy rules in `SUPPORT.md` — a pasted log is the mistake this project's issues
  will attract — and at the vendors who own a WordPress or plugin vulnerability, which
  `SECURITY.md` already declares out of scope here.
- The pull request template gained the reasoning the reference projects put in theirs: prompts under
  every heading, a checklist whose items state why they exist, and conditional sections for a change
  that adds a rule and for a change that touches a figure or the landing page. It is also now named
  `PULL_REQUEST_TEMPLATE.md`, matching the sibling repositories.
- Configuration is no longer watched for changes. Options were validated once and captured for the
  process lifetime, so `reloadOnChange` promised hot reload that never happened. The gateway now logs
  its resolved site table at startup instead, making effective routing visible on every run.
- Rule evidence reports the normalized file name rather than the raw client value, so a name carrying
  control characters cannot reach a log consumer intact.
- GitHub Actions are pinned to commit SHAs rather than mutable tags.
- Test coverage grew from 42 to 475, including the evasion table as regression coverage, a
  benign-upload suite that must stay silent across every rule, engine-level scoring calibration, and
  end-to-end upload coverage against real synthetic backends: malformed and truncated bodies, Unicode
  and bidirectional-override file names, cancellation, client disconnect mid-upload, every limit,
  per-site mode isolation, and assertions that no raw name, sample, query string or header value
  reaches a log line or a refusal body. Two structural tests assert that reading bodies of every
  shape creates no file on disk and that the gateway assembly references no type that could write
  one.

### Removed

- `BOOTSTRAP-MANIFEST.txt`, a generated list of the files the project was scaffolded with. It had
  already missed forty-three tracked files, including every security-relevant one added since —
  `NormalizedFileName`, the IIS rules, the gateway validator, the ADRs and two entire test projects.
  `git ls-files` is the manifest, and it is never stale. A stale inventory in a security repository
  invites a reader to treat it as authoritative.

### Known limitations

- `PHP-CONTENT-001` searches a bounded UTF-8 sample and can be evaded by placing the tag beyond the
  sample window, encoding as UTF-16, or splitting it across the boundary. It is a supporting signal,
  never a sole reason to block.
- An embedded executable extension cannot be distinguished from a benign name such as
  `readme.php.txt` by name alone. Stay in Monitor mode until you have reviewed your own traffic.
- **Only `multipart/form-data` bodies are inspected.** Urlencoded forms, JSON, XML-RPC,
  `application/octet-stream` PUTs and other `multipart/*` subtypes stream through untouched, as do
  form field parts within a multipart body, which are counted but never sampled — sampling them would
  fire `PHP-CONTENT-001` on every WordPress post body containing a code snippet.
- **Archive contents are never opened.** A `.zip` plugin or theme carrying a webshell is not
  detected, and installing a plugin is a genuine WordPress upload path. This is the largest single
  gap and no milestone is assigned to it yet.
- **Buffering is a new denial-of-service surface, and it is a real regression.** Before this
  milestone the gateway held no per-request body memory. A multipart request now holds roughly
  6.15 MiB at the defaults for up to 30 seconds, and nothing bounds how many may be buffered at once:
  `KestrelServerLimits.MaxConcurrentConnections` is unlimited by default and the gateway sets only
  `MaxRequestBodySize`. `Gateway:MaximumRequestBytes` and `ReadTimeoutSeconds` are the levers that
  exist today; an explicit bound is M3 work. The loopback-only restriction has changed character
  accordingly — it used to be a statement about project maturity, and it is now also the only thing
  bounding this memory.
- **Three conditions will meet legitimate traffic before an attacker.** A boundary of 71 to 128
  characters is refused by WPShield although Kestrel and probably PHP accept it; a 30-second read
  deadline against a 6 MiB body implies a sustained floor of roughly 205 KiB/s, so a slow mobile or
  satellite client uploading a full-size image can receive a 408; and a page builder or form plugin
  that posts a large form *with* a file attached can exceed the 200-field default. Each logs at
  Warning with the observed value in Monitor mode, which is the whole reason Monitor is the default.
- `FILE-TYPE-001` is silent on unrecognized bytes by construction, because with a 6 MiB request cap
  every large media upload arrives as plupload chunks and chunk 2 onward has no signature at
  offset 0. The cost is a UTF-16 webshell without a byte order mark, and a marker past the sample
  window. `PHP-CONTENT-002` proves only the minimal-carrier polyglot; on a real photograph the JPEG
  `EOI` sits far past the sample window and the rule stays silent.

[Unreleased]: https://github.com/peopleworks/WPShield/compare/81ab7500e8446e86c64a30640dc61f9f020c2693...HEAD
