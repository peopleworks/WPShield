# ADR 0011 — HTTP evidence from the IIS logs

- **Status:** Proposed
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
