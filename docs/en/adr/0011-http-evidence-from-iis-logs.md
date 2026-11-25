# ADR 0011 — HTTP evidence from the IIS logs

- **Status:** Accepted on 2026-11-25, with amendment 1 below
- **Deciders:** Pedro Hernández (maintainer)
- **Affects:** the evidence collector, `WPShield.Evidence`, the request-path rules, `wpshield`, the
  desktop, the MCP tools

## Context

Every compromise on the incident host arrived over HTTP. The LayerSlider shells were fetched with a
GET and no body, and a botnet later drove webshells with POST requests. WPShield's gateway would see
those requests, but the gateway is not in front of any production site during M1 and M2, by design.
The evidence store today records failed Windows logons only.

IIS already writes down every request to every site. On the incident host, checked on 2026-11-25:

- All 66 sites log in W3C format, with daily files under the default `LogFiles` directory, one
  `W3SVC<site id>` folder per site.
- Every site logs the same 17 fields: date, time, client IP, user name, server IP, method, URI stem,
  URI query, status, Win32 status, bytes sent and received, time taken, server port, user agent,
  referer and substatus.
- No site sits behind a CDN or a proxy, so the client IP is the TCP peer that completed the
  handshake with IIS. That is the evidence grade ADR 0006, section 5 requires before an address may
  be blocked. A request over HTTPS is logged after decryption, so HTTPS is covered too.

The request-path rules exist and are portable: `WP-PATH-001` and `-002`, `IIS-PATH-001` and `-002`,
the exposure family `EXPOSE-PATH-001` to `-005`, `NET-PATH-001` and `PHP-PATH-001` and `-002`. They
were chosen against a week of this host's own logs. Today they run only on gateway traffic.

## Decision

**The evidence collector reads the IIS W3C logs of every site as they are written and runs the
request-path rules on each request. It records findings and bounded aggregates, never the request
itself.** This ADR decides evidence only. Engine rules that turn this evidence into decisions come
from a week of data, in an amendment to ADR 0009. Enforcement comes through the same path as logon
decisions (ADR 0006 and the ADR that connects the engine to it).

### 1. What is read, and what is never read

**Read:** date and time (W3C writes UTC), client IP, server port, method, URI stem, status,
substatus, Win32 status, bytes received, time taken and user agent.

**Never read, never stored, never logged:**

- **URI query.** It carries tokens, password-reset links and API keys. Its column is skipped while
  the line is parsed, so the value never reaches a string WPShield keeps. This is AGENTS.md's "full
  query strings" rule, applied to a source that holds them.
- **Referer**, for the same reason: it is a full URL.
- **User name**, which names an authenticated user of the site.

The column order is taken from each file's `#Fields:` directive and never assumed. A file whose
directive lacks a field this ADR needs is reported as uncovered, not guessed at.

### 2. Which file belongs to which site

Sites, their IDs and their log directories are read from the IIS configuration, read-only, with the
same reader `wpshield audit` and `preflight` use. They are read at start and again every 15 minutes,
so a site added later is picked up. A folder with no site in the configuration is ignored and
reported. **Central logging mode** (one file for all sites) is reported as unsupported in this
phase, as a coverage gap.

### 3. Live, bounded, and honest about gaps

- **Tailing.** Each site's current file is opened with read, write and delete sharing, because IIS
  holds it open, and read from the last offset. The offset is kept per file in `collector_state`.
  Daily rollover is followed by file name. HTTP.sys flushes its log buffer about once a minute, so
  evidence arrives up to a minute late. That is acceptable for scanners and brute force, and it is
  why per-request blocking belongs to the gateway, not to this sensor.
- **Catch-up at start** reads at most the last 15 minutes of each site's file, into history only.
  As with logons (ADR 0009, section 1), nothing read at start ever reaches the decision engine.
- **Bounds:**
  - a line longer than 16 KB is skipped and counted, never parsed in part;
  - at most 50,000 lines per site per tick;
  - a file that shrinks or is replaced is restarted from its beginning, and the restart is recorded.
- **Coverage per site.** A site whose log cannot be read records a gap with its reason, such as
  access denied, central mode or a missing field, so a quiet site and a site nobody could read never
  look alike.
- **Permissions.** The log directory admits Administrators and SYSTEM by default. The service needs
  read access granted to `NT SERVICE\WPShield`. That is a server setting, so it stays manual. The
  coverage gap names the exact remedy, as the Security log does with Event Log Readers.

### 4. What is stored

- **Findings:** time, site ID, client address, method, the **normalized** path (cleaned, bounded at
  512 characters, never the raw stem), status, the rule IDs with their scores, and the user agent
  cleaned and bounded at 256 characters. Findings go to a dedicated table with the same retention
  rules as logon attempts (ADR 0007).
- **Hourly aggregates per site:** requests, 4xx, 5xx and findings, plus the bytes-received total.
  This is the context that tells an attack from a busy day.
- **Hourly aggregates per site and address,** only for addresses that produced a finding or more
  than 50 client errors in that hour. That covers the scanners that fire no rule, without recording
  every visitor of 66 sites.
- **Nothing else.** Ordinary requests leave only counts.

### 5. Addresses this evidence never counts against

The same protections as ADR 0009, section 4: the allow-list, the host's own addresses, loopback,
link-local and private ranges. On a shared host, sites behind IIS Application Request Routing call
each other through the host's own addresses. A new setting, `http.proxied_sites`, lists sites that
sit behind a proxy. Their findings are recorded, marked `proxied`, and are never eligible for a
host-wide decision, because their client IP is the proxy's.

### 6. Visible

- **CLI:** `wpshield web [--range ...] [--site ...] [--source ...]`, read-only like `attacks`.
- **Desktop:** a Web tab in the Attacks view: by site, by address and by rule, with the same "no
  data" honesty.
- **MCP and the analyst:** `web_summary`, `web_top_sources` and `web_findings` tools. Findings are
  aggregated by default, and paths are returned under `untrusted`, because the attacker chose them.

## Consequences

- **The botnet and the shells of the incident become visible** without putting the gateway in the
  path: a GET to a PHP file under `uploads` is `WP-PATH-001`, wherever IIS logged it.
- **Detection is up to a minute late, and nothing here stops a request.** Stopping one request
  needs the gateway (M3 and later). Stopping an address needs the engine and enforcement.
- **The service needs read access to the logs.** Until it has it, every site shows as uncovered,
  with the remedy.
- **Volume.** Sixty-six sites produce many lines; the tick bound and the aggregates keep the store
  small. The first week measures it.
- **A query-string attack is invisible to these rules**, because the query is never read. SQL
  injection in parameters is a gateway concern, where the query can be inspected without being
  stored.

## Alternatives considered

- **Put the gateway in front of every site now.** That is M3. It changes the traffic path of 66
  production sites. The logs give evidence today without that risk.
- **ETW from HTTP.sys** (`Microsoft-Windows-HttpService`). It is faster than the log, but carries
  more than this needs, the query string included, and needs a real-time session with its own
  permissions. Reconsider if a minute proves too slow.
- **Read the URI query and redact it.** Redaction is a list that is always one parameter name short.
  Not reading the column is the only version that cannot leak.
- **Record every request.** That would be a copy of the IIS logs with the same privacy problems and
  none of the bounds.

## Revisiting this decision

- After one week on the incident host: the volume per day, the findings per rule, and which
  addresses would have triggered which candidate engine rule. Then write the ADR 0009 amendment for
  web rules.
- When the gateway sits in front of a site (M3): decide whether that site's log evidence is still
  read, or whether the gateway's own evidence replaces it.

## Amendment 1 - observations, and as built (2026-11-25)

### Why the rules alone are not enough

The request-path rules miss the incident this ADR starts from. Its botnet drove webshells with POST
requests to PHP files in folders that legitimately hold PHP: a theme's templates, a plugin's admin
modules, one modified WordPress core file. That is the known gap no path rule can close without
refusing legitimate plugins. On 2026-11-19, after the plugins were removed, `php-cgi` on that host
called out to the attacker again. A path rule never sees the status code, and the status code is what
gave the shells away: they answered.

### Observations

The sensor adds **observations**: evidence only. An observation has no score, is not a rule, and is
never enough to decide anything alone. The IDs are stable, untranslated, and their own family:

- **`WEB-OBS-001`:** a 2xx answer to a `.php` path that is not a WordPress entry point. The script is
  the first segment ending in `.php`, path-info included. The entry points are, by name at any install
  depth:
  - `index.php`, `wp-login.php`, `xmlrpc.php`, `wp-cron.php`, `wp-comments-post.php`,
    `wp-trackback.php`, `wp-signup.php`, `wp-activate.php`, `wp-mail.php`, `wp-links-opml.php`;
  - plus `wp-admin/*.php`, `wp-admin/network/*.php` and `wp-admin/user/*.php`.

  Nothing under `wp-content` or `wp-includes` is ever an entry point. Every such request is stored as a
  finding row with its method, so a POST is told from a GET.
- **`WEB-OBS-002`:** a POST to `wp-login.php`.
- **`WEB-OBS-003`:** a POST to `xmlrpc.php`.

`002` and `003` are counted per site, address and hour, never stored one by one: brute force runs to
thousands of requests an hour. All three count toward the per-address aggregate threshold of
section 4.

On a site without WordPress, every PHP answer is an observation. That is deliberate: on such a site a
PHP file answering is exactly what the incident looked like. It is also why an observation decides
nothing. The first week measures how much legitimate traffic it catches.

### As built

- **The stem is the once-decoded path.** HTTP.sys decodes the URL once before IIS logs it. The HTTP
  Server API writes a `+` for a character that would break the line, a space among them. The stem is
  therefore the same path the gateway sees as `Request.Path`, with `+` read back as a space. Windows
  strips a trailing space at open time, and a literal plus means nothing to any path rule. The
  normalized path, the second-decode view included, is built from it exactly as in the gateway: a
  double-encoded `%252e` reaches the log as `%2e`, as it reaches the gateway.
- **One rule catalog.** `RequestPathRuleCatalog`, in `Rules.WordPress`, is what the gateway registers
  and what the sensor evaluates. A test proves the gateway's set equals it.
- **Where the code lives.**
  - The parsing, the rules, the observations and the tailing are in a new portable project,
    `WPShield.WebEvidence`, tested on the Linux leg.
  - The store stays SQLite only.
  - The IIS configuration is read by the CLI, which hands the site list in.
- **Schema 2, additive.** Four tables:
  - `web_findings`;
  - `web_hourly_sites`;
  - `web_hourly_sources`;
  - `web_sites`, the per-site state with reason and remedy.

  A schema-1 store keeps every row it holds. Read positions are kept in `collector_state`, one per site
  and file, written in the same transaction as what was read up to them.
- **Bounds added.**
  - At most 200 finding rows per address, site and hour; past that they are counted, not stored.
  - At most 200,000 addresses counted per hour in memory; past that the period is recorded as limited.
  - A catch-up with no position in a file finds where the 15-minute window starts by a binary search
    on the lines' own times, so it reads a few probes, not the file. If the times cannot be read, it
    falls back to the last 32 MB, and says so if that cut into the window.
- **Protection.** A finding from a protected address is recorded with the reason, and the address is
  never listed against. Protected addresses are this host, the allow-list, loopback, link-local and
  private ranges. An address of a site in `http.proxied_sites` (IIS site names) is treated the same.
- **Not wired into the service yet.** `wpshield evidence collect` reads the IIS logs. The collector the
  gateway hosts as a service does not yet. The IIS configuration reader is the CLI's, and the service
  account would first need the manual read grant on the log folders, which is printed as the remedy of
  an `access-denied` site.
- **No web record reaches the decision engine**, live or catch-up, and a test asserts it. The `live`
  flag on a finding is kept for the ADR 0009 amendment that may one day use it.
- **The desktop Web tab** reads through `WebEvidenceQueries`.
- **The MCP tools, as built (2026-11-25).** `web_summary`, `web_top_sources` and `web_findings` read
  `WebEvidenceQueries` only and take the ranges `wpshield web` takes. A fourth tool, `address_report`,
  joins one address's failed logons, decisions, web evidence, label and allow-list status in one
  answer. Without `mcp.detailed_records` they return site IDs, counts, rule and observation IDs,
  methods and statuses; with it they add site names, normalized paths, user agents and site remedies,
  each wrapped as untrusted. The analyst gets all four, with fewer optional parameters than an MCP
  client sees, to stay within the strict-schema budget (see `docs/en/analyst.md`).

## Amendment 2 - WordPress's placeholder files (2026-11-25)

The first `WEB-OBS-001` on the real host was a scanner's `GET /wp-content/index.php`, answered 200 by a
WordPress site. That file is WordPress core's empty "Silence is golden" placeholder, and every healthy
install answers it the same way; scanners request it to learn that a site runs WordPress. It is not a
webshell answering.

`WEB-OBS-001` therefore excuses a **GET or HEAD** of exactly three core placeholders, requested by name as
the last segment: `wp-content/index.php`, `wp-content/plugins/index.php` and
`wp-content/themes/index.php`, at any install depth. Nothing else changes:

- a **POST** to one of them is still observed - nothing legitimate posts to a placeholder, and a placeholder
  replaced by a shell is driven with POST;
- an `index.php` **inside** a plugin or a theme is still observed, because that is where the incident's
  shells were hidden;
- `wp-content/uploads/index.php` is not a core placeholder and is still observed;
- path-info after the placeholder (`wp-content/index.php/x.jpg`) is still observed.

The week of data decides whether plugin-level placeholders deserve the same treatment; they are not
excused on a guess.
