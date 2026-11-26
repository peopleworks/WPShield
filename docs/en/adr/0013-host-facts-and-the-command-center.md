# ADR 0013 — Host facts and the command center

- **Status:** Accepted (2026-11-25, Pedro Hernández), with the six decisions recorded at the end
- **Deciders:** Pedro Hernández (maintainer)
- **Affects:** the evidence collector, `WPShield.Evidence`, `wpshield` (a new `host` verb, and
  `audit`), the MCP server and the analyst, the desktop

## Context

WPShield's evidence answers "who is attacking". The maintainer also wants "how is this server
doing", on one screen with gauges: a command center. The incident host keeps showing why:

- **It restarts on its own.** In October 2026 a kernel dump tied four restarts to bugcheck 0x133
  (`DPC_WATCHDOG_VIOLATION`) inside a third-party network filter driver. On 2026-11-25 it restarted
  again while a read-only script ran. Nobody sees this until someone opens Event Viewer.
- **Its posture changes slowly, by hand.** `wpshield audit` found 80 of 81 application pools running
  as the local Administrator. The plan is to move them one at a time. Nothing shows the progress
  ("1 of 80") or a pool that slips back.
- **Its exposure is known only from a one-off script.** SMB, three database engines, VNC and WinRM
  were open to any address in November 2026. That came from a script run once, in a chat.
- **Persistence lives in the inventory.** The triage of 2026-11-01 searched scheduled tasks, services
  and accounts by hand. A task or service that appears between two triages goes unnoticed.

The MCP server and the analyst (ADRs 0008 and 0010) can answer questions about evidence only. Asked
"is this server healthy?", they have nothing to read.

ADR 0011 set the pattern this follows: one source, read once, bounded, and shown the same way on
every surface.

## Decision

**WPShield gets one read-only layer of host facts. The collector reads it on a fixed cadence and
stores bounded snapshots in the evidence store. The CLI, the desktop command center, the MCP server
and the analyst all answer from those snapshots. Nothing in this layer changes the host.**

### 1. The facts

| Fact | What it holds | Source | Elevation |
| --- | --- | --- | --- |
| `host_health` | Uptime and last boot. Unexpected restarts over the last 30 days, each with the bugcheck code when there is one. CPU, memory, and free space per fixed volume, with the volume that holds the IIS logs marked. The size of the evidence store | `GetTickCount64`; System log events 41 (Kernel-Power), 6008 (unexpected shutdown) and 1001 (WER `BugCheck`, which carries the code); `GetSystemTimes`, `GlobalMemoryStatusEx`, `DriveInfo`; file sizes of the store and its WAL | None. The System log is readable by default |
| `iis_sites` | Per site: ID, name, state, bindings (protocol, port, host name, loopback or not), pool, pool identity **type** (`ApplicationPoolIdentity`, a specific user, `LocalSystem`, ...) and whether that identity is a local administrator. Log coverage per site from the web sensor (ADR 0011) | The IIS configuration reader that `audit`, `preflight` and the web sensor already use, read-only; `WebEvidenceQueries.Sites()` | Yes. Without it, the fact is `needs-elevation` |
| `iis_posture` | The latest audit summary: each finding's ID, severity and item count, plus the counts behind the gauges, such as pools with administrator rights out of all pools | The audit checks themselves (`AuditRunner`), run read-only; see section 3 | Yes |
| `listening_ports` | Port, protocol, local address (any, a specific address or loopback), process executable, and an exposure verdict | The TCP and UDP listener tables (`LocalListenerInventory`, which already names the owning processes) and the active firewall policy | Process names and some rules need elevation; anything not read is `unknown` |
| `rdp_sessions` | Current sessions (ID, state, user, logon time) and the RDP logons and reconnections of the last 7 days, each with its source address | `WTSEnumerateSessions` for state; LocalSessionManager events 21 and 25 for addresses (as in `OwnConnection`) | No for the event log. Some session details need it |
| `host_inventory` | Three kinds: `accounts`, `services` and `tasks` | See section 1.3 | Yes. Unelevated, tasks are listed as `partial` |
| *outbound* (deferred) | Connections from web worker processes to the internet | Needs its own sensor; see section 1.4 | — |

#### 1.1 The exposure verdict

For each listener, the verdict comes from the **enabled inbound rules of the active firewall
profiles**:

- `open-to-any`: an allow rule matches the port with any remote address;
- `restricted`: allow rules match only some remote addresses;
- `blocked`: a block rule matches, or no allow rule does while the default inbound action is block;
- `local-only`: the listener is bound to loopback;
- `unknown`: the policy could not be read.

The verdict is labelled **"by the Windows Firewall rules"**, and it is never presented as
"reachable from the internet". Other WFP filters and callouts sit in the same path and decide too:
a network filter driver, an endpoint product, a provider's edge firewall. So a process that listens
is not proven reachable, and a rule that allows traffic does not prove that packets arrive.

#### 1.2 Unexpected restarts are events, not only a count

Each unexpected restart is recorded once, as an evidence event of kind `host.unexpected-restart`.
Duplicates are recognized by their System log record ID. The detail holds the time, the source event
and the bugcheck code with its name (`0x133 DPC_WATCHDOG_VIOLATION`). The first start reads the last
30 days, so the history is there immediately. Later starts read only what is new. The 30-day count
on the gauge is a query over these events, and it survives the System log being cleared or
overwritten.

#### 1.3 The inventory, without secrets

Only items that are **not Microsoft's** are listed. For services and tasks, that means the binary is
not Authenticode-signed by Microsoft. Tasks under `\Microsoft\` whose action is a Microsoft-signed
binary are skipped.

- **Accounts:** name, enabled, member of Administrators or of Remote Desktop Users, last logon, age of
  the password, and whether it never expires. The description is not read. The full name is read only
  in memory, for the indicator below, and is never stored, logged or returned.
- **Services:** name, display name, state, start mode, run-as account and the executable's path. The
  executable's signature is reported as `signed by <subject>`, `unsigned` or `not checked`.
- **Tasks:** path and name, state, run-as principal, last and next run, and the action's executable
  path with its signature.

**Arguments are never stored or shown.** A service's or task's arguments can carry a password or a
token, and an encoded command is the attacker's payload. In their place the fact records **flags**,
computed locally and then discarded:

- `has-arguments`;
- `encoded-command` (`-enc`, `-EncodedCommand`);
- `contains-url`;
- `user-writable-path` (the executable or a path argument is under a folder that users or
  `Everyone` can write).

The argument text never reaches the store, a log line or an answer.

**Signature checks are bounded.** `WinVerifyTrust` results are cached by path, size and last-write
time. Each snapshot verifies at most 300 binaries; the rest stay `not checked` until the next one.

**Are attackers trying the accounts' full names?** On the incident host, attackers tried names that
looked like the full names of real local accounts. A list like that does not come from a dictionary.
It comes from the server itself: its logon screen, or the months of the intrusion. So the accounts
snapshot computes one indicator, locally:

1. Read the full names of the local accounts, live, into memory.
2. Compare them with the distinct account names tried in the last 30 days of failed logons in the
   evidence store. The comparison ignores case, accents and repeated spaces.
3. Store only the result in the snapshot: `full_name_targeted` (true or false) and `matches` (how
   many local accounts had their full name tried). Never a name.
4. Discard the full names when the snapshot is written.

The indicator is a count, not a host detail. It is returned by the MCP tools and the analyst without
`mcp.host_details`, and shown on the RDP/SMB attacks panel. If the full names cannot be read, it is
`unknown`, never `false`.

A change between two inventory snapshots is recorded as an event of kind `host.inventory-change`:
an item added, removed, or changed in executable, account or signature. That is the "a task
appeared" signal. It complements the `wpshield.persistence` pack (ADR 0012), which sees the event
when it is logged. The inventory sees the state, including what was created while nothing was
watching.

#### 1.4 Outbound connections, deferred to their own ADR

Malwarebytes saw `php-cgi.exe` connect to the attacker's address on 2026-11-19, after the cleanup.
That is the most valuable host fact of all, and it is **not** in this ADR. A snapshot of the TCP
table every few minutes misses a callback that lasts two seconds. Seeing those reliably needs a
sensor: an ETW session on the kernel network provider, or high-frequency TCP table sampling. Either
one brings its own costs, permissions and bounds. It gets its own ADR. Until then the command center
shows the panel as **"not measured yet"**, so that absence is never read as "nothing goes out".

### 2. Honest about what it could not read

Every fact carries:

- its **read time**;
- a **status**: `ok`, `partial`, `needs-elevation`, `unreadable` or `not-measured`;
- for any status other than `ok`, a **reason** and the **remedy**, as `audit` and `preflight`
  already do.

A snapshot older than three times its cadence is shown as **stale**, with its age. An unreadable
fact is never rendered as an empty one: zero unexpected restarts and "the System log could not be
read" must not look alike.

### 3. Snapshots, cadence and storage

**The collector takes snapshots; readers never trigger a live read.** Polling would be the wrong
design here:

- The desktop refreshes every 5 seconds. Enumerating tasks and verifying signatures at that rate
  would make the monitor the heaviest process on the host.
- A trend needs history: "pools moved, week by week" and "restarts over 30 days" cannot come from
  live reads.
- Every surface shows the same snapshot with the same read time, so the CLI, the desktop and the
  analyst cannot disagree.
- A model can never make WPShield probe the host. The MCP tools and the analyst read stored
  snapshots only.

**Cadence:**

| Fact | Cadence |
| --- | --- |
| `host_health` | every 5 minutes. Unexpected restarts are read at start and every 15 minutes |
| `iis_sites`, `listening_ports`, `rdp_sessions` | every 15 minutes |
| `iis_posture` | at start and every 6 hours |
| `host_inventory` | at start and every 6 hours |

**Where the posture comes from.** The collector runs the audit's checks itself, read-only, on its
cadence. The CLI hands it the audit reader, as it hands it the IIS site list (ADR 0011, as built).
So the "pools moved" gauge moves without the operator remembering to run anything. A manual
`wpshield audit` also records its summary as a posture snapshot.

**This writes to WPShield's own evidence store only, never to the server.** No IIS setting, pool,
permission, service, task or firewall rule is touched, by the collector's posture snapshot or by
`wpshield audit`. The audit's closing line says exactly that: "Nothing on this server was changed. A
summary was recorded in WPShield's evidence store." When the store cannot be opened, the audit still
runs and its closing line says the summary was not recorded.

**Storage: schema 3, additive.** A store written by an earlier build keeps every row, as AGENTS.md
requires since schema 2, and a test opens a literal schema-2 store with the new code:

- `host_snapshots`:
  - columns: fact, kind, taken time, status, reason, and a JSON payload of at most 256 KB;
  - kept: the latest snapshot of every fact, all posture snapshots for 400 days (four a day), and
    other snapshots for 7 days.
- `host_health_hourly`: CPU average and peak, minimum free memory, and minimum free space per
  volume, for 90 days. This is what draws the trends.
- Events `host.unexpected-restart` and `host.inventory-change`, which follow the existing retention
  of `events`.

**Bounds:**

- at most 2,000 items per inventory kind and 500 listeners per snapshot;
- every name and path cleaned and bounded at 256 characters;
- at most 500 `host.inventory-change` events a day per kind; beyond that they are counted, not
  stored, and the overflow is recorded;
- a time budget per snapshot. A fact that exceeds it is stored as `partial`, never left half-written.

**Where it runs first: `evidence collect` only.** Like the web sensor, host facts start in
`evidence collect`, which runs elevated. Running them in the service under `NT SERVICE\WPShield`
needs a permission table per fact and the remedies for each. That comes later, in an amendment, when
the service collector reads the IIS logs too.

### 4. Never changes anything

ADR 0005 and AGENTS.md apply without exception. No fact, verb, tool or panel stops, starts, deletes
or reconfigures a service, task, account, firewall rule, IIS setting or file. Everything that looks
wrong comes with a remedy, which is printed text for a person to carry out by hand. A future action
of any kind would need its own ADR, and a confirmation outside the model (ADR 0008, section 2).

### 5. What leaves the host

Site names, account names, service and task names, executable paths and RDP source addresses are
**host details**. A list of them is a map of the server for whoever reads it. Every tool result goes
to the assistant's model provider (ADR 0008, section 7), so these details need their own gate.

**A new audited setting, `mcp.host_details`** (default `false`, `NextStart`). Why not
`mcp.detailed_records`:

- That setting governs **evidence detail**: single attempts and the account names attackers tried.
  This one governs **the host's own inventory**: what runs, as whom, from where.
- An operator who allows detailed records for one investigation should not silently export the
  server's map along with it.
- ADR 0010 refused "a second definition of what leaves the host" for the same content. This is
  different content, so a separate switch is the honest shape. ADR 0008, section 7 gets a paragraph
  naming it.

**With `mcp.host_details` false**, the tools return:

- counts, statuses, verdicts and gauges ("80 of 81 pools run as an administrator", "3 services with
  an unsigned binary");
- port numbers, protocols and exposure verdicts;
- the executable **file name** of a listening process (`mysqld.exe`), without its path, because an
  exposure verdict means nothing without it;
- restart times and bugcheck codes;
- the `full_name_targeted` indicator and its count of matches, never the names.

Names of sites, accounts, services and tasks, paths, and RDP source addresses are replaced by
`"withheld"`, and the answer says which setting would release them.

**With it true**, they are returned. Every value that names something is returned under `untrusted`
(ADR 0008, section 3). On a compromised host, the attacker chooses task names, service display
names and executable paths.

The CLI and the desktop show everything. They are local surfaces, and nothing they display leaves
the host.

### 6. Surfaces

**CLI:**

```text
wpshield host [health|sites|posture|ports|sessions|inventory <accounts|services|tasks>] [--live] [--json]
```

With no argument it prints a one-screen summary of every fact from the latest snapshots, each with
its age and status. `--live` reads the host directly and writes nothing. It is for when the collector
is not running, and the output says it is a live read.

**MCP tools.** The strict schemas of the analyst (ADR 0010) allow at most 24 optional parameters
across all tools and 16 union-typed ones, and the web tools of ADR 0011 still have to fit. So:

- `host_health`, `iis_sites`, `iis_posture` and `listening_ports` take **no parameters**;
- `rdp_sessions` takes one optional **named** range (`24h` or `7d`);
- `host_inventory` takes one **required** enum, `kind` (`accounts`, `services` or `tasks`). It is one
  tool instead of three, and a required enum costs nothing against the optional budget;
- none takes a path, a name, a command or a query;
- explicit `from`/`to` ranges are not offered. If one is ever needed, the analyst's reduction keeps
  it off, as `ExplicitRangeTools` does today;
- the existing test that pins the optional-parameter budget covers the new tools. It fails the build
  before a request would fail at the provider.

All of them are read-only and non-destructive, so the analyst's guard (`McpAnalystTools.RequireReadOnly`)
accepts them unchanged.

**The desktop command center** is a home screen of panels. Each panel shows its data source's read
time and turns grey when its data is missing or stale. **Grey is never green.**

| Panel | Shows | Source | When there is no data |
| --- | --- | --- | --- |
| WPShield | Collector running, each sensor's coverage (Security log, RDP, IIS logs "N of M sites read"), age of the newest record | Evidence coverage, web sensor sites | "Collector not running since ..." in red; a sensor that is not covering says why |
| RDP/SMB attacks | Attempts per minute against the 7-day hourly median; decisions in force (Monitor); the most active network; **"attackers try your accounts' full names: yes (N)"** | Evidence, `decisions`, the `full_name_targeted` indicator | Gaps drawn as "no data", as in Attacks; the indicator shows `unknown` when the full names could not be read |
| Web | Requests per minute, rule findings, login and xmlrpc POSTs. **`WEB-OBS-001`**: red when above zero; green only when every site was read for the whole range | Web evidence (ADR 0011) | Incomplete coverage turns the `WEB-OBS-001` light grey, never green |
| Server health | Uptime; **unexpected restarts in 30 days, with their bugcheck codes**; CPU, memory and disk, with trends | `host_health`, `host_health_hourly`, restart events | Stale or unreadable snapshot: grey, with age and reason |
| Posture | **Pools moved: N of M**, with a progress bar and its history; PHP mapped at the server level; writable site folders; FTP overlaps; time of the last posture snapshot | `iis_posture` | "No posture snapshot yet" in grey, with the remedy (start the collector elevated, or run `wpshield audit`) |
| Exposure | Each listener open to any address, with its verdict. Red for SMB (139, 445), RPC (135), SQL Server (1433), MySQL (3306, 33060), PostgreSQL (5432), VNC (5900) and WinRM (5985, 5986) when open to any. A port restricted to specific addresses is not red. The remedy shown is to restrict the rule to the addresses that need it, never to hide the port | `listening_ports` | `unknown` verdicts are listed as unknown, never as closed |
| Analyst | Enabled or off; runs and input tokens today against `analyst.daily_runs` and `analyst.daily_input_tokens`; time of the last report | Analyst store (ADR 0010) | Off is shown as off, not as an error |
| Outbound | — | Deferred (section 1.4) | Always "not measured yet: needs its own sensor" |

The window is built **after this ADR is accepted and the host facts layer is merged**, on the layer's
read API. That is the same order as the web view, which waited for its sensor.

## Consequences

- **The questions of the last two months get an answer on one screen:**
  - Did it crash again, and with what code?
  - How many pools are still administrators?
  - What is open to the world?
  - Did a service or a task appear?
- **The analyst can reason about the host**, from stored snapshots and, by default, without the
  host's names leaving it.
- **The collector does more work.** The cadences and the per-snapshot budget keep that bounded, and
  the first week measures it.
- **The store grows by a fixed amount.** Snapshots are pruned, and hourly health stays small.
- **A third-party filter driver can still make an exposure verdict wrong.** That is why the verdict
  names its source.
- **Outbound connections stay invisible** until their ADR is written. The panel says so.

## Alternatives considered

- **Sysmon.** Excellent data, including network connections by process. But it installs a kernel
  driver and a configuration on a production server, and that is the kind of change this host has
  already paid for. It may come back as an optional source in the outbound ADR.
- **WMI for everything.** One API, but slow on a busy host, prone to repository corruption, and the
  same subsystem attackers use for persistence. The native APIs above are faster and narrower. WMI
  stays a fallback, read-only, if one is needed.
- **A monitoring agent** (Zabbix, Wazuh, Prometheus `windows_exporter`). Mature, but it is another
  agent with its own listener and update channel on an exposed server. It does not speak WPShield's
  evidence or its honesty rules, and its gauges would sit in a second console. An export of
  WPShield's own snapshots to such a tool can come later, as a reader.
- **Live reads on every request.** Simpler, but there are no trends, the desktop becomes heavy, the
  surfaces disagree, and a model could make the host be probed. Rejected for the reasons in section
  3.
- **Reusing `mcp.detailed_records`.** Rejected in section 5: it governs different content.

## Decisions on acceptance (2026-11-25)

Pedro Hernández accepted this ADR with these six decisions:

1. **`mcp.host_details`** is a new audited setting, off by default, separate from
   `mcp.detailed_records` (section 5).
2. **Posture:** the collector runs the audit's checks every 6 hours, and a manual `wpshield audit`
   records its summary. Both write to WPShield's own evidence store only, never to the server, and the
   audit's closing line says so (section 3).
3. **The exposure red list stays:** SMB, RPC, SQL Server, MySQL, PostgreSQL, VNC and WinRM when open
   to any. A port restricted to specific addresses is not red. The remedy is to restrict, never to
   hide (section 6).
4. **Cadences and retention as written** (section 3).
5. **Account full names stay out** of the store, the MCP tools and the analyst. A local indicator,
   `full_name_targeted` with `matches`, records whether attackers try them, as a boolean and a count
   only (section 1.3).
6. **Host facts start in `evidence collect` only.** The service follows in an amendment (section 3).

## As built (2026-11-25)

Phase 1 (the host-facts layer, `wpshield host`, the audit's posture summary) differs from the text
above in these points:

- **The Microsoft filter is stricter than section 1.3.** A service or task whose binary is signed by
  Microsoft is still listed when it runs a script host (`cmd.exe`, `powershell.exe`, `pwsh.exe`,
  `mshta.exe`, `wscript.exe`, `cscript.exe`, `rundll32.exe`, `regsvr32.exe`, `certutil.exe`,
  `bitsadmin.exe`, `wmic.exe`, `forfiles.exe`, `curl.exe`) or carries an `encoded-command`,
  `contains-url` or `user-writable-path` flag: `cmd /c powershell -enc ...` is signed by Microsoft
  too. Services hosted in `svchost.exe` are judged by their `ServiceDll`.
- **Payload field names.** The accounts snapshot stores the indicator as `fullNameTargeted` and
  `fullNameMatches` (every payload uses camelCase field names); sections 1.3, 5 and 6 call them
  `full_name_targeted` and `matches`.
- **The attempt window is 14 days with the default retention, not 30.** The indicator compares the
  full names with the attempts of the last 30 days that are still stored in detail, and detailed
  attempts are kept `retention.raw_days` (14 by default). Wherever this ADR says "the last 30 days of
  failed logons", read "the detailed attempts still kept, 30 days at most".
- **Near-complete block lists do not block.** A block rule counts only when its remote addresses are
  `*`, `Any`, `Internet` or a whole-range literal. A block rule with a list that covers almost every
  address is treated as covering some addresses only, so it does not make a listener `blocked`: the
  verdict leans open, as section 1.1 asks when unsure.
- **No MCP tools yet, and `evidence collect` only.** The host-fact tools and the `mcp.host_details`
  gate they honour come in the next phase; the setting exists and is audited, and changes nothing yet.
  The service-hosted collector does not take host facts.
- **Patch level in `host_health`.** It holds, read-only, what Windows reports in three places that can
  disagree: `CurrentBuild`, `UBR` and `DisplayVersion` from
  `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`; the ProductVersion of
  `%SystemRoot%\System32\ntoskrnl.exe` (compared with `UBR` by revision only, since an enablement
  package raises `CurrentBuild` while the kernel file keeps the base build); and, from
  `Microsoft-Windows-WindowsUpdateClient/Operational`, the newest event 19 (install succeeded) whose
  title contains "Cumulative Update" - title cleaned and bounded at 200 characters, with its date and
  the days since - and the count of event 20 (install failed) in the last 30 days. An unreadable log is
  `unknown`, never "none"; "not found" says how far back the log reaches. WPShield has no offline
  source of the latest build, so it never judges a host "outdated".
- **The MCP tools exist (2026-11-26).** `host_health`, `iis_sites`, `iis_posture`, `listening_ports`,
  `rdp_sessions` and `host_inventory` answer from the snapshots through `HostFactsQueries` and honour
  `mcp.host_details`, frozen when the server starts like `mcp.detailed_records`; they take exactly the
  parameters of section 6, so the analyst is offered 24 optional parameters across 20 tools, both
  strict-tool-use limits. As built: `rdp_sessions` defaults to `7d`; restarts count as read only once the
  collector has recorded how far it read the System log (`HostFactsQueries.RestartsReadUntil`), and
  before that the count is `null`, never 0; a reason that is not a code and every stored remedy come back
  as untrusted text; a drive-letter volume name is shown, any other volume name is a path and is
  withheld; a service's or task's account is classified (`local-system`, `local-service`,
  `network-service`, `virtual-account`, `pool-identity`, `named-account`) so the kind shows while the
  name stays behind the gate; and the signer of a signature is always returned, as untrusted text. The
  "no MCP tools yet" bullet above applied to phase 1.

## Revisiting this decision

- After two weeks on the incident host: the collector's CPU and time per snapshot, the store's
  growth, and how often signature checks run out of budget.
- When the outbound sensor's ADR is written: wire its panel and its tool here.
- When the service-hosted collector reads the IIS logs: add host facts to it, with the permission
  table per fact.
- When ADR 0007's dedicated reader group exists: reconsider which facts an unelevated desktop may read.
