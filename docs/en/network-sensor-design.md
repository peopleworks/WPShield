# WPShield.NetworkSensor — Design (English)

WPShield.NetworkSensor is a **separate, optional, Windows-only component** that captures
network metadata on operator-named ports (for example `80` and `443`) so an operator can
see what traffic reaches the host. It is **not** the HTTP gateway, it is **not** in the
request path, and it never modifies IIS.

## Desktop monitor

From the repository root on Windows with the .NET 10 SDK and Desktop Runtime, run:

```powershell
dotnet run --project src/WPShield.Desktop -c Release -- --en
```

Select TCP or UDP in the sidebar, or search by address, exact port, PID, process name or
conventional port name. The cards show each table's observation time, coverage and IPv4/IPv6
counts. The owner column shows the process name and PID, for example `sqlservr · 4120`. Each refresh looks up at most 4,096 distinct PIDs across TCP and UDP. A name appears in the
column and in search only when the process started before that row’s owner-table observation.
If the PID now belongs to a newer process or the timestamps coincide, the row keeps the observed
PID and explains the timing. An unreadable process and a PID skipped at the lookup limit have
separate labels. The tooltip shows the owner observation time. Use **Refresh** for another snapshot or enable
**Every 5 s**. Closing the window stops polling. The view reads local socket tables in memory and
works without Npcap, elevation or an HTTP listener. Use `--es` to open the window in Spanish.

Names that come from Windows (adapters, capture devices, processes) are shown with control and
bidirectional-format characters replaced by `�`, and accented letters kept. A read that fails in an
unexpected way shows a message and leaves the window open.

**On a server without the .NET SDK,** build a self-contained copy on a development machine and carry
the folder across; nothing is installed on the server:

```powershell
dotnet publish src/WPShield.Desktop -c Release -r win-x64 --self-contained true -o artifacts\wpshield-desktop
```

Run `WPShield.Desktop.exe` from that folder in the server's desktop session (Windows Server with the
Desktop Experience). Only **Port traffic** needs Npcap and administrator rights.

### Attacks

Open **Attacks** to see who is failing to log in to this host. The view reads the last 24 hours of
failed logons and then follows new ones live:

- **Security 4625** for every logon type. Remote Desktop with NLA and SMB fail as logon type 3, plain
  Remote Desktop as type 10, IIS basic authentication as type 8.
- **RdpCoreTS 140** (`Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational`). With NLA,
  Windows often writes 4625 without the client address; Remote Desktop's own record carries it. A
  4625 and a 140 for the same attempt, within two seconds, are counted once: the one with the
  address is kept, and when both have it the 4625 is kept because it names the account.

The cards show failed attempts, distinct source addresses, the share of attempts on account names
that do not exist (guessing, rather than a known user mistyping) and the last hour. The timeline
splits each interval into nonexistent accounts and the rest, for 1 hour, 6 hours or 24 hours.
Select a source to slide in its detail: the accounts it tried, its attempts over time, other
addresses attacking from the same /24 (IPv4) or /64 (IPv6) network, and its latest attempts. **Esc**
or **✕** closes it. Search matches an address, a network such as `203.0.113.0/24`, an account or a
label.

**7 d and 30 d** read the WPShield service's evidence store
([ADR 0007](adr/0007-local-evidence-store.md)) instead of the Security log, which on a busy host
rarely reaches back a week. The 7-day timeline has one bar per hour and the 30-day timeline one per
day; both start on a whole hour or UTC day, so the hourly totals add up exactly. The store answers
with counts per source, so the table shows `—` for each row's accounts and logon types; a source's
detail asks the store for its accounts and latest attempts, and adds when WPShield first saw it.
Where the store keeps only hourly aggregates (by default, anything older than 14 days), the detail
says that account names and single attempts are no longer kept for that period, and the account
count is `—`, not 0. Intervals the service did not record are grey, as unread time is in the
shorter ranges. 1 h, 6 h and 24 h still read the Security log directly, and live updates continue
whichever range is shown. The view opens on the `attacks.default_range` setting.

The store exists only once the WPShield service is installed, and opening it needs administrator
rights. When it cannot be opened, **7 d** and **30 d** are disabled and their tooltip says why;
the shorter ranges work as before.

**Labels.** The `labels.addresses` setting names addresses and networks you know: your office, your
own connection, a scanner network you have already reported. A label appears next to a matching
address in the table, in the detail and among the neighbours, in every range. An exact address
wins over a network, and a longer prefix over a shorter one. Labels are set in the
[Settings window](#settings-window) or with
[`wpshield settings`](#attack-history-from-the-command-line). **A label describes an address; it
never allows or blocks one.**

**Decisions.** When the store can be read, the **Decision** column marks each source with the
[decision](#decisions-monitor) in force about it or about its /24 or /64: **would block** or
**protected**. In every range, the short ones included. The cell is empty when nothing is in force,
and `—` when the store could not be read: nobody could look, which is not the same as no decision.
The footer says which: how many decisions are in force and when they were read, that the engine has
never run, or that the service is not recording, in which case nothing is in force. The decisions are
read with each load or **Refresh** while the rows update live, so each mark is checked against its
expiry when it is drawn. A source's detail lists the decisions
about it and its network over the last 30 days, with rule, expiry and the reason the engine wrote.
**Monitor only: nothing is blocked.** The view never says "blocked".

What the view will not do:

- **Show an empty board as a quiet host.** Reading the Security log needs administrator rights.
  Without them the cards show `—`, a banner says the window could not look, and **Reopen as
  administrator** relaunches it elevated on this view. The rest of the monitor keeps running without
  elevation.
- **Show unread time as zero.** A busy host's Security log can cover only hours. Intervals before
  the oldest record still in the log, or before a bound stopped the read (20,000 records or
  10 seconds per log), are drawn as **no data**, and the banner names the time the data starts.
  Enlarging the Security log is a manual server setting.
- **Trust the account names.** The attacker chose them. They are cleaned of control and format
  characters and bounded to 64 characters before they are stored or shown. Labels are cleaned the
  same way.
- **Present aggregates as detail.** A period answered from hourly aggregates says so; the counts
  are exact and the names are gone.
- **Decide or block anything.** It reads and shows. Decisions are made by the service's engine, in
  Monitor, and the view only reads them. Live records are applied once a second and memory holds at
  most 100,000 records, dropping the oldest and moving the "no data" line with them.

### Settings window

Open **Settings** to read and change the evidence store's [settings](#settings) without a JSON file
or a path on the server. The list is the catalog this build of WPShield knows - every setting,
including ones added after this page was written - with its value and whether it is the default.
Select one to see what it does, its current value, who changed it last and when, its default, when
it takes effect, and its history: when, who, the old and new value, and the reason.

Each setting is edited with a control that fits its type: a check box for on and off, a box for a
number or a word, a table of **Address or network** and **Label** for `labels.addresses`, and a list
of entries for a list of addresses. Any other shape is edited as JSON, and **Edit as JSON** switches any
editor to JSON text and back, for a value the table or the list cannot hold. Whether a value is acceptable
is decided by the same check `wpshield settings set` uses, and its answer appears under the editor.
**Save** stays disabled until the value is valid, differs from the current one, and has a
**reason**. **Reset to default** removes the stored value and needs a reason too. Every change is
recorded with your Windows user name and the reason, exactly as the command line records it.

**Saving applies nothing.** Each setting says when it takes effect: at its next use (the next pruning
pass, query or view that reads it), or the next time the process that reads it starts. The window
restarts nothing.

**My current connection** adds a row with the address **this server sees** for your Remote Desktop
session - the address an attack would come from, and the one an allow-list has to name. It is read
from the server's established connections to its Remote Desktop port (the port configured for the
listener, not an assumed 3389). When several people are connected, this session's newest logon or
reconnection record in the `TerminalServices-LocalSessionManager/Operational` log (events 21 and 25)
says which connection is yours, and it is used only if that address is connected now. With exactly one
connection and no such record, that connection is offered and the tooltip says so. Nothing is offered,
and the tooltip says why, in a console session, when the connections cannot be read, when several
people are connected and nothing says which one is you (the tooltip lists them so you can type the
right one), and when your record names an address that is not connected now, as through a Remote
Desktop Gateway. The window reads all this when it opens and on **Refresh**; the tooltip gives the
time.

The address your Remote Desktop client reports about itself is never offered. Microsoft documents that
the client reports it: behind NAT it is your own network's private address, which never matches
anything this server sees. When it differs from the address offered, the tooltip mentions it only to
explain the difference.

What the window will not do:

- **Change anything without elevation.** The store's folder admits only administrators and the
  service. Without elevation the window is read-only, and when it cannot open the store at all it
  shows every value as unknown, never as its default. **Reopen as administrator** relaunches it
  elevated on this view.
- **Create the store.** When the evidence folder or the store file does not exist, the window says
  so and names `wpshield install`; the service creates the store once it runs.
- **Hold the store open, or overwrite a change it has not seen.** It opens the store for writing only
  for one change, while the service keeps writing. If the value was changed elsewhere after the
  window read it (the command line, another window), the save is refused with who changed it;
  **Refresh** shows that change. A save that fails says why and keeps your edit.

### Adapter traffic

Open **Adapter traffic** and select a Windows network adapter. Paired bars show received and sent
bytes per second across the whole adapter. Both use the same vertical scale. Hover over an interval
to see its UTC time and rates. For individual flows or a port-specific capture, use the
[host flow view](#host-flow-view).

The first read establishes a baseline. Every two seconds the window reads the byte counters and
divides their change by the measured elapsed time. A failed read, lower counter, clock discontinuity
or interval longer than five seconds marks a gap in amber. Two equal counter readings measure zero.
**Pause chart** freezes the display while sampling continues. Resume returns to the latest 30
observations. Switching adapters starts a new history. Closing the traffic window ends sampling.

## Attack history from the command line

`wpshield attacks` and `wpshield settings` read the evidence store the WPShield service writes
([ADR 0007](adr/0007-local-evidence-store.md)), at
`%ProgramData%\WPShield\evidence\wpshield-evidence.db` unless `--store` names another. Its folder
admits only administrators and the service, so run them from an elevated prompt. Neither changes
anything on the server except, for `settings set` and `settings reset`, the setting named.

```powershell
wpshield attacks --range 24h
wpshield attacks --range 30d --top 50
wpshield attacks --source 203.0.113.45 --range 7d
wpshield attacks --range 7d --json
```

`wpshield attacks` prints the failed attempts, the distinct source addresses, the share of attempts
on nonexistent accounts and the most tried account, then the top sources (`--top`, 20 by default)
with their network, neighbours in the same /24 or /64, first and last attempt, and label.
`--source` prints one address's history instead: when the store first saw it, the accounts it
tried, its attempts per hour or per day, and its latest attempts. `--range` defaults to the
`attacks.default_range` setting. Every answer says what it is made of:

- **Records:** `detailed`, or `hourly aggregates` - the counts are exact, but account names, logon
  types and single attempts are no longer kept for that period.
- **Coverage:** recorded for the whole range, the gaps with the reason the service wrote down, or
  none. A range nobody recorded is `no data` (exit code 2, `null` in JSON), never zero.
- **Range:** from 24 hours up a range starts on a whole hour (30 days on a whole UTC day), so it is
  never shorter than its name and the hourly totals add up exactly.

```text
Evidence store   C:\ProgramData\WPShield\evidence\wpshield-evidence.db (read-only)
Range            last 24 hours: 2026-11-23 23:00 to 2026-11-24 23:54 UTC
Records          detailed: every attempt and the account it named
Coverage         gaps - these times were not recorded and read as no data, never as zero:
                   2026-11-24 14:54 to 2026-11-24 16:34 UTC  (service-stopped: service not running)

Failed attempts       725  (8 without a source address)
Source addresses      5
Nonexistent accounts  64% of attempts
Most tried account    administrator

Top 5 of 5 source addresses
ADDRESS         ATTEMPTS  NONEXISTENT  ACCOUNTS  NETWORK          NEIGHBOURS  FIRST (UTC)       LAST (UTC)        LABEL
203.0.113.45         420          66%         6  203.0.113.0/24            1  2026-11-24 03:55  2026-11-24 23:54  Scanner network
203.0.113.46         160         100%         6  203.0.113.0/24            1  2026-11-24 03:58  2026-11-24 23:45  Scanner network
198.51.100.23         95           0%         1  198.51.100.0/24           0  2026-11-24 17:54  2026-11-24 23:43
2001:db8:5::17        30         100%         1  2001:db8:5::/64           0  2026-11-24 05:01  2026-11-24 23:17
192.0.2.10            12           0%         1  192.0.2.0/24              0  2026-11-24 20:57  2026-11-24 23:51  My office
```

When the store cannot be opened, the command stops with the reason instead of printing an empty
table: exit code 3 when there is no store (the service is not installed), 1 when this process is not
elevated or access was denied, 2 when another version of WPShield wrote it. Account names and labels
are printed with control and format characters replaced, and escaped in `--json`.

### Settings

```powershell
wpshield settings list
wpshield settings get labels.addresses
wpshield settings set attacks.default_range 7d --reason "a week by default"
wpshield settings set labels.addresses --value-file .\labels.json --reason "name the office"
wpshield settings reset retention.raw_days --reason "back to the default"
wpshield settings history
```

| Setting | Default | Takes effect | What it does |
| --- | --- | --- | --- |
| `retention.raw_days` | `14` | next use | Days of detailed failed logons kept |
| `retention.aggregate_days` | `400` | next use | Days of hourly aggregates and decisions kept |
| `retention.event_days` | `90` | next use | Days of other evidence events kept |
| `retention.max_megabytes` | `2048` | next use | Size the store may reach before detailed rows are pruned |
| `attacks.default_range` | `"24h"` | next use | Range `wpshield attacks` and the desktop's Attacks view open with |
| `labels.addresses` | `{}` | next use | Names for addresses and networks; they never allow or block |
| `mcp.detailed_records` | `false` | next start | Whether a future MCP server may return single attempts; none exists yet |
| `defense.mode` | `"monitor"` | next start | The decision engine's mode; only `monitor` is accepted |
| `defense.allow` | `[]` | next use | Addresses and networks the engine never decides against |
| `defense.include_private` | `false` | next use | Whether private ranges may be decided against |
| `defense.<rule>.*` | see [Decisions](#decisions-monitor) | next use | Each rule's count, window and duration |

`list`, `get` and `history` open the store read-only and fail, rather than print the defaults, when
it cannot be opened. `set` and `reset` need an elevated prompt and a `--reason`. They refuse a key
this version does not know and list the known ones, validate the value, never create the store, and
record the change in the store's settings history with your Windows user name and the reason. `set`
replaces the whole value: to add one label, `get labels.addresses`, edit it, and set all of it back.

**The command applies nothing.** Each setting takes effect at its next use (the next pruning pass,
query or view that reads it) or at the next start of the process that reads it, and the command
prints which.

The desktop's [Settings window](#settings-window) makes the same changes, through the same checks and
the same history, with an editor for each setting instead of a JSON file.

Values are JSON, and a text setting also takes a bare word (`7d`). Windows PowerShell 5.1 drops the
quotes inside an argument on its way to a program, so give an object such as the labels in a file
(64 KB at most):

```json
{ "198.51.100.7": "My office", "203.0.113.0/24": "Scanner network" }
```

## Decisions (Monitor)

The WPShield service runs a decision engine
([ADR 0009](adr/0009-deciding-what-to-block.md), proposed) inside its evidence collector. It turns
failed logons into decisions with a rule, a reason and an expiry, and writes each one to the evidence
store's `decisions` table. **This version runs in Monitor only. Nothing is enforced anywhere:** every
decision is a record of what Block mode would have done. Block mode needs the enforcer of ADR 0006 (in
PR #86), which does not exist yet; `defense.mode` accepts only `monitor` until it does.

**What it sees.** Only live failed logons, after a 4625 and a 140 of the same attempt have been
paired, and only records that arrived after the service started. The catch-up read at start is stored
and never handed to the engine. That includes its last seconds, which go through the pairing buffer
with the live records, so they are marked by channel and record ID rather than by a time cut. The
engine never reads the `decisions` table. Its state lives in memory and ends with the process: a
restart forgets everything, which costs at most one more window of attempts.

**The rules.** Rule IDs are stable and untranslated. Every threshold is a setting:

| Rule | Fires when | Decision | Default | Settings (bounds) |
| --- | --- | --- | --- | --- |
| `HOST-AUTH-001` | One address fails N times within W | would block the address for D | 10 in 10 min, 60 min | `defense.failures.count` (3-100), `.window_minutes` (1-1440), `.block_minutes` (1-10080) |
| `HOST-AUTH-002` | One address tries M account names that do not exist within W | would block the address for D | 4 in 10 min, 6 h | `defense.unknown_accounts.count` (2-50), `.window_minutes`, `.block_minutes` |
| `HOST-AUTH-003` | K different addresses of one /24 or /64 fail within W | would block the network for D | 8 in 10 min, 60 min | `defense.network.count` (2-64), `.window_minutes`, `.block_minutes` |
| `HOST-AUTH-004` | One existing account fails from A different addresses within W | report only | 10 in 10 min | `defense.shared_account.addresses` (2-100), `.window_minutes` |

"Does not exist" means Windows said so (`unknown-account`), and names are compared without case. "Existing"
means a reason Windows gives only for a real account, such as a wrong password, a locked or disabled
account or an expired password. Remote Desktop's ambiguous "wrong user name or password" counts as
neither. A record without a source address counts for nothing.

**Repeat offenders.** A target that triggers again within 7 days of the end of its previous decision
gets twice that decision's duration, up to 7 days, and the reason says so. This memory is in-process
too.

**Never decided against.** The engine checks these when it makes a decision and records a stopped
decision as `protected`, with the reason, until the would-be block would have ended:

- the allow-list `defense.allow`: canonical addresses and networks, none wider than /16 (IPv4) or
  /48 (IPv6), and no loopback, multicast or unspecified address, at most 1,000 entries;
- every address bound on the host itself, and loopback, link-local and unspecified addresses;
- private ranges (RFC 1918, ULA `fc00::/7`, CGNAT `100.64.0.0/10`) unless `defense.include_private`
  is `true`;
- an address holding a Remote Desktop session right now: an established TCP connection to the port
  in `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\PortNumber`, which is
  never assumed to be 3389.

A network decision is stopped when any address in it would be. When the connection table, the port
or the host's addresses cannot be read, the decision is `refused`, not made: "nobody could look" is
not "nobody is connected".

**Bounded.** Per-address, per-network and per-account state each hold at most 100,000 entries and
1,000,000 items inside them, and evict the least recently seen. At most 10,000 decisions are in force.
Past that a new one is `refused` and the refusal is recorded. While a decision is in force the
engine ignores its target's attempts, as an enforced block would have dropped them, so there is one
record per decision and not one per attempt. A refused target is reconsidered after one window.

**What it writes.** Every record carries the rule, the target (an address, or a /24 or /64), mode
`monitor`, the reason with the counts that fired it, the channel whose record completed the rule,
and the expiry. Actions:

| Action | Meaning |
| --- | --- |
| `would-block` | A rule fired; the target would be blocked until the expiry |
| `protected` | A rule fired on a target the engine never decides against; the expiry is when that block would have ended |
| `refused` | A rule fired and the engine could not check what it must, or 10,000 decisions were in force |
| `report` | `HOST-AUTH-004` fired. Never blocks. The target is the address that completed the pattern, and the account is not named, because the MCP server returns targets and reasons whatever `mcp.detailed_records` says |
| `expire` | A `would-block` ended, at its expiry (checked every minute) or when the service stopped |

Log lines carry counts and rule IDs only, never an address or an account. A failure inside the engine
is logged with its type, and collection continues. The attempts are stored either way.

**In force.** A decision counts as in force when it is the newest record about its target, is
unexpired, was made since the engine last started, and the collector is still recording. A decision
never outlives the process that made it, and a crash writes no `expire`. The CLI, the desktop and any
later Protection panel all use this one definition (`EvidenceQueries.ActiveDecisions`).

### `wpshield decisions`

```powershell
wpshield decisions
wpshield decisions --range 7d --target 203.0.113.45
wpshield decisions --active
wpshield decisions --active --json
```

It is read-only and opens the store exactly as `wpshield attacks` does, with the same exit codes
(3 no store, 1 not elevated or access denied, 2 another schema or nothing recorded) and the same
cleaning of stored text. Without `--active` it lists the decisions of a range (`--range`, 24 hours by
default; at most 200, newest first), with a count per action and the collector's coverage, because
the engine decides only while the collector runs. A range nobody recorded is `no data`, never "no
decisions". `--target` takes an address, which shows its own decisions and its /24's or /64's, or a
network exactly as a decision names it. `--active` shows what is in force now, and when nothing can
be, it says why: the engine never ran, or the service is not recording.

```text
Evidence store   C:\ProgramData\WPShield\evidence\wpshield-evidence.db (read-only)
At               2026-11-24 12:00 UTC
Mode             monitor - nothing is blocked; these are what Block mode would be enforcing now
Engine           started 2026-11-24 09:00 UTC; only decisions made since then can be in force
Collector        recording (coverage reaches 2026-11-24 12:00 UTC)

In force now     2  (would-block 1, protected 1)

TARGET          ACTION       RULE           SINCE (UTC)       UNTIL (UTC)       REASON
203.0.113.0/24  would-block  HOST-AUTH-003  2026-11-24 11:30  2026-11-24 12:30  8 different addresses of this network failed in 3 minutes (threshold 8 in 10 minutes)
198.51.100.7    protected    HOST-AUTH-001  2026-11-24 11:20  2026-11-24 12:20  10 failed logons in 2 minutes (threshold 10 in 10 minutes); protected: on the allow-list (198.51.100.7)
```

The MCP `decisions` tool reads the same table and calls it an audit trail, not the current state.

**Thresholds will be wrong at first.** That is what Monitor is for. After a week on a real host,
compare the `would-block` and `protected` records with what you expected, adjust the `defense.*`
settings with `wpshield settings set`, and they apply at the next evaluation. Known gap: a botnet
that sends one attempt per address triggers no per-address rule, and `HOST-AUTH-003` catches it only
when its addresses share a /24 or /64.

## Local listener inventory

Use this local command to see TCP listeners and bound UDP endpoints before choosing ports for a
traffic capture. It reads the Windows socket tables once and works independently of Npcap.

```powershell
wpshield network-monitor --listeners
wpshield network-monitor --listeners --ports 443,1433,3389 --json
wpshield network-monitor --listeners --protocol tcp --local-address 127.0.0.1 --ports 443 --owners
```

Omitting `--ports` includes all local ports. The filter accepts 1–64 port numbers. Each protocol
has a separate UTC observation time, read status and list of distinct local addresses and ports.
Bindings are labelled `loopback`, `wildcard` (all local addresses of that family) or `specific`.
IPv6 addresses retain any scope ID. The output contains local addresses and is intended for the operator.

Use `--protocol tcp` or `--protocol udp` to read one table. Use `--local-address` to match the
exact bound IPv4 or IPv6 address, including a numeric IPv6 scope such as `fe80::1%2`. To find
wildcard bindings, query `0.0.0.0` or `::` explicitly. A search for `127.0.0.1` shows only sockets
bound to that address. The filters apply together before the row limit and PID lookup. Within each
table, displayed rows sort by port, family, numeric address and scope ID. JSON records requested
filters in `Protocol` and `LocalAddress`, including when the result is empty.

A `read` table can be empty. A `limited` table contains up to 4,096 distinct matching endpoints
and carries the reason `row-limit`. An `unavailable` table carries `access-denied` or `query-failed`.
Exit code 0 means all selected tables were read completely, 2 means partial results, and 1 means
every selected table was unavailable or the arguments were invalid.

To check a change, repeat the command with the same filter and compare protocol, address and port
for each table marked `read` in both snapshots. TCP and UDP are read in sequence. A socket can
appear or disappear between reads. External reachability, service ownership, site and login
outcome all require independent evidence.

### Offline port hints

```powershell
wpshield network-monitor --listeners --ports 443,1433,3389 --port-hints --json
```

Add `--port-hints` to look up conventional names for the observed protocol and local port in a
catalog shipped with the CLI. For example, TCP 1433 returns `ms-sql-s` and TCP 3389 returns
`ms-wbt-server`. The JSON field `PortHintCatalog` identifies the WPShield catalog version.
Each endpoint's `PortHints` array contains the matching registry names, including aliases.
An empty array (shown as `unknown` in the console) means this catalog has no entry for the pair.

Version `wpshield-iana-v1` covers 20 selected port numbers for web, database, remote access, mail,
FTP, SIP and VPN services. The lookup runs locally without DNS or registry requests. A listening
process can use any available port. To investigate the actual process, combine the option with
`--owners` and check the timestamped PID separately. [IANA service and port registry](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)

### Observed owner PID

```powershell
wpshield network-monitor --listeners --ports 443,1433,3389 --owners --json
```

For each protocol and IP family with retained endpoints, the CLI reads a second local Windows
table. It matches the full local address (including IPv6 scope) and port. Each endpoint gains
an `Owner` object with `ObservedAtUtc`, `ProcessId` and `Reason`. A unique nonzero PID is the
process identifier Windows reported at that second observation. The socket can change hands
between reads. Windows can also reuse a PID after a process exits. A historical PID cannot
identify a running process, Windows service, IIS site or login without further evidence.
[Windows TCP table](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable) · [Windows UDP table](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedudptable)

`ProcessId` is null if the endpoint disappeared (`not-observed`), the rows disagree
(`ambiguous`) or Windows supplied PID zero (`pid-unavailable`). A failed owner table
marks affected endpoints with `access-denied`, `query-failed`, `invalid-table` or `table-limit`.
Each native table read has a 1 MiB buffer ceiling and at most three attempts. A failed owner
table makes the result partial (exit 2) while preserving the listener rows. A successful table
can legitimately contain unresolved endpoints. Omitting `--owners` skips the extra reads and
the `Owner` field.

## Host flow view

To find the capture interface, run the local inventory first.

```powershell
wpshield network-monitor --list-interfaces
wpshield network-monitor --list-interfaces --json
```

Copy the Npcap device ID from the first column into `--interfaces` when starting a flow capture.
The ID remains usable after a Windows adapter rename. A unique friendly name or description also works.
The inventory reports whether Npcap sees local IPv4 or IPv6 addresses. An adapter with neither
cannot determine flow direction. The inventory reads device metadata without opening the adapter.
Capture permissions and link support are checked when capture starts. Successful enumeration with
zero devices returns `[]` in JSON. An enumeration error exits with code 1 and writes to stderr.
If the selected ID disappears, list the interfaces again and choose the intended source explicitly.

Run the CLI locally with administrator privileges and Npcap installed. Use the name of one
Windows adapter and the actual service ports on that host. These examples use common ports.

```powershell
wpshield network-monitor --flows --interfaces "Ethernet" --ports 443,1433,3389
wpshield network-monitor --flows --interfaces "Ethernet" --all-ports --json
```

Every two seconds the console shows up to 40 most recently active flows, with local and remote
endpoints, protocol, last activity in UTC, and observed IP bytes received and sent (including IP and
transport headers and retransmissions). Both directions share one row. An observed opening TCP SYN
identifies the local or remote initiator. UDP and TCP first seen midstream show `unknown`. A port
filter can match either endpoint. Service identity, site attribution and authentication outcomes
require separate evidence. Ctrl+C stops the capture and prints a final snapshot.

JSON includes every retained flow. The table holds at most 4,096 flows and expires entries after 60 seconds of inactivity. The display
includes the active count, packets skipped during decoding or direction assignment, packets dropped
at table capacity and the driver's reported drop counter (null in JSON when unavailable). A zero
driver counter cannot establish complete coverage. [Npcap capture statistics](https://npcap.com/guide/wpcap/pcap_stats.html)

The capture requests at most 160 bytes per frame and retains only flow metadata. TCP/UDP over
IPv4 and basic IPv6 are supported. VLAN encapsulation, IP fragments and IPv6 extension headers are
outside this version's coverage. Both-local and neither-local traffic cannot be assigned a remote
endpoint. Filters can exclude frames before software counters see them. Only addresses assigned to
the selected adapter at startup are used for direction. Output is local and includes IP addresses.

### Source status

Every flow snapshot identifies the adapter (`Interface`), the UTC snapshot time (`Timestamp`) and
the selected TCP/UDP ports (`CapturePorts`, an empty array for all ports). During capture,
`CaptureStatus` is `running`. The final snapshot reports `stopped` for an operator stop or
`interrupted` for an unexpected driver stop, including with zero flows and with history disabled.
A failure before capture starts reports a command error. In JSON mode diagnostics go to stderr.

For RDP and SQL, `WindowStart` and `WindowEnd` bound the event query in UTC. RDP names the
Security channel and selected local TCP port. SQL names the Application channel and instance
provider. Each query has its own `AuditStatus`. A completed empty query returns `read` and
provides no login evidence. For `unavailable`, `UnavailableReason` is `access-denied` or
`query-failed`; for a readable or limited query the reason is null. Older JSON may omit these
fields. Window timestamps describe the period queried. They cannot establish whether the
server was configured to record every login.

### Selected audit reference

In the Windows desktop monitor, choose **Audit references → Open snapshot** and open one saved
WPShield JSON object. Use the arrow keys to select a row. The preview shows the exact JSON that
**Copy** or **Ctrl+C** places on the clipboard. RDP and SQL rows identify the Windows event by
channel, provider, UTC timestamp and record ID. IIS rows identify the W3C input prefix by SHA-256
and byte length, with the physical line and any paired challenge line.

Coverage is the status recorded in the file. Older snapshots can have unknown coverage. An
empty list describes the contents of that snapshot. The desktop accepts up to 8 MiB and 1,024
references per snapshot with a five-second read budget. A duplicate ID within one source,
an invalid reference or an exceeded limit clears the list and disables copying.

Save a single JSON snapshot locally. Use the Windows event **record ID** shown for the chosen
row. The source selects the channel even if RDP and SQL have records with the same number.

```powershell
wpshield network-monitor --sql-instance MSSQLSERVER --json | Set-Content -Encoding UTF8 .\sql.json
wpshield audit-reference --snapshot .\sql.json --source sql --record-id 431
wpshield audit-reference --snapshot .\flow-snapshot.json --source rdp --record-id 125
```

Replace the example IDs with IDs present in the snapshot. For a flow monitor JSON Lines file,
save the single original JSON line for the observation of interest in UTF-8. The selector accepts
one object up to 8 MiB. It reads saved fields offline. The reference contains only channel,
provider, UTC timestamp and record ID. SQL flow attribution remains unknown. Verify the reference
against the original Windows event log on the same server.

Exit 0 prints one JSON reference. Exit 3 means the requested ID was absent from that source in
this snapshot, including when its coverage was partial. Invalid input, a missing source section,
duplicate matches or a read error return 1. Diagnostics go to stderr and failed selections leave
stdout empty. [IIS file and line references](iis-login-evidence.md#selected-line-reference)

### Traffic history

```powershell
wpshield network-monitor --flows --interfaces "Ethernet" --ports 443,1433,3389 --history --json
```

The optional history shows observed IP bytes per second for each direction on the selected adapter
and ports. Counting happens after decoding and direction checks, before flow admission, expiry or
tuple reuse. A full flow table can omit an endpoint row while its observed bytes still count.
Each snapshot closes one interval. A monotonic clock measures its duration and UTC labels its
boundaries. The first and final intervals can be short. The console shows five intervals and JSON
includes up to 30 under `History` (under `Traffic.History` when an audit is selected).
Snapshots overlap in history; use each interval once when comparing them.

| Coverage | Meaning |
| --- | --- |
| `observed` | The driver counter was available at both boundaries and the reader detected no gap. Rates describe the selected, decodable traffic. |
| `unknown` | The driver counter was unavailable at a boundary. Rates still measure observed bytes. A zero is insufficient to establish an idle network. |
| `gap` | Packets were skipped, the driver counter rose or reset, capture stopped unexpectedly, sampling exceeded five seconds, or the UTC and monotonic clocks disagreed. Rates are null. Counts and `GapReasons` remain available. |

Open **Port traffic** and type 1–64 comma-separated numbers in **TCP/UDP ports** (for example,
`443,1433,3389`). Alternatively, choose an entry in **Port list** and click **Add port**. Repeat to
combine ports, or edit the text to remove one. The list includes conventional HTTP, HTTPS, SQL Server
and RDP ports and ports from the latest local listener inventory. Observed ports are labelled.
You can prepare the selection in a normal session. To capture, open WPShield as administrator on
a Windows host with Npcap, enter the selection in that session, choose an adapter and click
**Start capture**. A TCP or UDP packet matches when either endpoint uses a selected port. Each row
plots incoming and outgoing IP bytes per second on a shared scale, newest interval first. Hover
over a row for its UTC dates, observed byte counts and any gap reason codes. A gap displays a dash
for each rate. Unknown coverage still shows the measured rates.

**Pause chart** holds the displayed intervals while capture continues. Uncheck it to see the
latest 30 intervals. **Stop** shows the final snapshot and releases the adapter. Closing this
window also stops its capture. Capture data stays in memory. Live validation on Windows Server
with Npcap remains pending. For whole-interface counters without Npcap, open [Adapter traffic](#adapter-traffic).

### Remote Desktop logon evidence

On the monitored server, specify its configured local Remote Desktop TCP port. The account running
the command needs read access to the Windows Security log. Whether Windows records successes and
failures depends on the host's existing Audit Logon policy.

```powershell
wpshield network-monitor --flows --interfaces "Ethernet" --ports 443,1433,3389 --rdp-port 3389
```

For each snapshot WPShield reads up to 256 recent RemoteInteractive (type 10) events from the past
60 seconds, newest first. A match requires the same client IP and source port, a recorded time
between the first and last packet observed for that flow, and a unique candidate on the selected
adapter and local TCP port with an observed incoming SYN. Windows records a successful logon in
event 4624 and a failed attempt in 4625. Each match includes its UTC time and Security record ID
for lookup in Event Viewer. [Event 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624) · [Event 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)

- `success`, `failure` and `mixed` summarize the matching audit records in this snapshot.
  `unknown` covers missing source ports, midstream captures, ambiguous flows and absent evidence.
  Failures recorded under other logon types are outside this view.
- `AuditStatus` is `read` when the query completes, `limited` when it reaches its record or polling
  budget, and `unavailable` when Windows denies access or the query fails. Traffic remains visible.
- With `--json`, each line contains `Traffic` and `RdpAudit`. A record may reappear in successive
  snapshots. Use its Security record ID to count it once within the same log. Output contains
  endpoint addresses but omits account names and event messages. A match concerns a logon on the
  host. The audit record omits the destination endpoint, so uniqueness applies only to the captured
  flows. Site attribution and activity inside a desktop session require other evidence.

To validate on a Windows Server test host with Npcap, start the command before an authorized
Remote Desktop sign-in. In Event Viewer, open **Windows Logs → Security** and compare the record
ID, UTC time, source IP and source port with the displayed flow. Record whether the audit read
completed and whether capture drops occurred. If Windows omits the source port, the expected
result is `unknown`. That run exercises missing evidence and leaves a positive match unverified.

### SQL Server login evidence

Read one minute of existing **Windows Logs → Application** events for one local Database Engine
instance. The standalone command needs permission to read Application and runs independently of
Npcap and SQL credentials. Use `MSSQLSERVER` for the default instance. For a named instance, copy
the suffix of its `MSSQL$<name>` source from Event Viewer, preserving spelling and case.

```powershell
wpshield network-monitor --sql-instance MSSQLSERVER --json
wpshield network-monitor --flows --interfaces "Ethernet" --ports 1433,3389 --rdp-port 3389 --sql-instance Example
```

Events 18453, 18454 and 18455 indicate a successful login. Event 18456 records a failure.
Availability depends on the server's auditing and logging configuration. The reader selects the
instance provider and event metadata only. Each row gives the event ID, Application record ID,
UTC time and outcome. The result applies to the instance. `FlowAttribution` stays `unknown`
even if a single TCP flow used its usual port. Usernames, event messages and SQL statements are
excluded. [SQL Server event IDs](https://learn.microsoft.com/en-us/sql/relational-databases/errors-events/database-engine-events-and-errors-18000-to-18999) · [Windows Application providers](https://learn.microsoft.com/en-us/sql/relational-databases/performance/view-the-windows-application-log-windows-10)

The newest 256 matching records fit in a snapshot, subject to a 500 ms polling budget.
`ObservedOutcome` summarizes only the returned records as `success`, `failure`, `mixed` or
`unknown`. A completed query with zero matches leaves the outcome unknown, including for an
absent provider. Standalone exit codes are 0 for `read`, 2 for `limited` and 1 for
`unavailable` or invalid arguments. With `--flows --json` the same fields appear under
`SqlAudit` alongside `Traffic` and optional `RdpAudit`. Overlapping windows can repeat a record.
For live validation compare the channel, provider, record ID and UTC time against a known login
in Event Viewer on a test server with existing audits. The command leaves auditing untouched.

## Why it must be separate

| Concern | WPShield.Gateway (M1/M2) | WPShield.NetworkSensor (proposed) |
|---|---|---|
| Position | Inline reverse proxy, loopback only | Passive capture, separate process |
| Privileges | Normal user, loopback listener | Administrator, Npcap driver |
| Modifies IIS | No | No |
| Sees request bodies | Only bounded multipart samples | Never |
| Sees query strings | Never logged | Never logged |
| Default exposure | Loopback `127.0.0.1:10000` | None until operator enables it |

Mixing a packet capture driver into the HTTP gateway would break the loopback-only invariant,
require kernel privileges inside the request path, and tempt the implementation to inspect
full bodies — all prohibited by AGENTS.md and THREAT_MODEL.md.

## HTTP metadata mode responsibilities

1. **Capture only metadata.** Source/destination IP, source/destination port, HTTP method,
   request path (query string stripped), response status code, body size, timestamp, network
   interface name.
2. **Filter by operator-named ports only.** A BPF filter restricts capture to the ports listed
   in configuration (default: none — the sensor captures nothing until configured).
3. **Never capture full bodies, credentials, cookies, authorization headers, nonces, tokens,
   or complete query strings.** This is structural, not a threshold that can be lowered later.
4. **Emit events in the gateway's log envelope** (`timestamp`, `level`, `category`, `message`,
   `state`) so a forensic report and a gateway log correlate on the same field names.
5. **Fail closed.** If Npcap is missing, elevation is absent, or the configuration is invalid,
   the sensor refuses to start and writes a clear blocker message.

## What it does NOT do

- Does not bind to ports 80/443 or change IIS bindings.
- Does not modify URL Rewrite rules, ARR, application pools, or any IIS setting.
- Does not install Npcap silently; the operator installs it explicitly.
- Does not run in promiscuous mode unless the operator explicitly opts in.
- Does not inspect, buffer, or store request/response bodies.
- Does not block traffic. It observes and reports only.
- Does not replace IIS logs, Microsoft Defender, or a WAF.

## Configuration (`appsettings.NetworkSensor.json` or `WPSHIELD_NETWORKSENSOR_*`)

```json
{
  "NetworkSensor": {
    "Enabled": false,
    "Interfaces": [ "Ethernet", "vEthernet (WSL)" ],
    "Ports": [ 80, 443 ],
    "PromiscuousMode": false,
    "MaxEventsPerSecond": 1000,
    "OutputPath": "C:\\WPShield\\Logs\\network.ndjson",
    "Rotation": {
      "MaxFileSizeBytes": 104857600,
      "RetentionDays": 30
    }
  }
}
```

- `Enabled` defaults to `false`. The sensor captures nothing until explicitly enabled.
- `Interfaces`, when present, limits capture to those adapter names. When empty, all adapters
  matching the port filter are used.
- `Ports` is mandatory when enabled. Empty list = capture nothing.
- `PromiscuousMode` defaults to `false`. True is an explicit operator choice, logged as a blocker-level event.
- `MaxEventsPerSecond` bounds the emission rate so the sensor cannot become a noise amplifier.
- `OutputPath` is a file the sensor writes; it is the only write the component makes.

## Event model (JSON Lines, gateway envelope)

Every emitted line is one JSON object:

```json
{
  "timestamp": "2026-10-20T14:32:07.1234567Z",
  "level": "Information",
  "category": "WPShield.NetworkSensor",
  "message": "HTTP request observed",
  "state": "observed",
  "requestId": "ns-1a2b3c4d-...",
  "interface": "Ethernet",
  "srcIp": "192.0.2.10",
  "dstIp": "192.0.2.1",
  "srcPort": 51422,
  "dstPort": 443,
  "method": "POST",
  "path": "/wp-admin/admin-ajax.php",
  "statusCode": 200,
  "bodySizeBytes": 12450,
  "tls": true
}
```

Privacy-safe fields only. `path` is the request path **without** the query string. No
`Authorization`, `Cookie`, `Set-Cookie`, body content, or full query string ever appears.

## Interfaces (C#)

These contracts live in `WPShield.NetworkSensor` and reference only `WPShield.Abstractions`
for shared types where appropriate.

```csharp
namespace WPShield.NetworkSensor;

public sealed class NetworkSensorConfiguration
{
    public bool Enabled { get; init; }
    public IReadOnlyList<string> Interfaces { get; init; } = [];
    public IReadOnlyList<int> Ports { get; init; } = [];
    public bool PromiscuousMode { get; init; }
    public int MaxEventsPerSecond { get; init; } = 1000;
    public string OutputPath { get; init; } = string.Empty;
    public RotationConfiguration Rotation { get; init; } = new();
}

public sealed class RotationConfiguration
{
    public long MaxFileSizeBytes { get; init; } = 100_000_000;
    public int RetentionDays { get; init; } = 30;
}

public sealed record NetworkEvent
{
    public required DateTimeOffset Timestamp { get; init; }
    public required string Level { get; init; }
    public required string Category { get; init; }
    public required string Message { get; init; }
    public required string State { get; init; }
    public required string RequestId { get; init; }
    public required string InterfaceName { get; init; }
    public required string SourceIp { get; init; }
    public required string DestinationIp { get; init; }
    public required int SourcePort { get; init; }
    public required int DestinationPort { get; init; }
    public required string HttpMethod { get; init; }
    public required string Path { get; init; } // query string stripped
    public required int StatusCode { get; init; }
    public required long BodySizeBytes { get; init; }
    public required bool Tls { get; init; }
}

public interface INetworkSensor : IAsyncDisposable
{
    Task StartAsync(CancellationToken cancellationToken);
    Task StopAsync(CancellationToken cancellationToken);
    bool IsRunning { get; }
}

public interface INetworkEventSink
{
    Task WriteAsync(NetworkEvent @event, CancellationToken cancellationToken);
}
```

## Capture flow

```
Operator enables NetworkSensor
        │
        ▼
Validate configuration (ports non-empty, Npcap present, elevated)
        │
        ▼
Build BPF filter: "tcp port 80 or tcp port 443"
        │
        ▼
Open live capture on selected interfaces (non-promiscuous by default)
        │
        ▼
For each packet:
  ├─ Parse Ethernet/IP/TCP
  ├─ If destination port not in configured list → skip
  ├─ Attempt lightweight HTTP parse (method, path, status, size)
  ├─ Strip query string from path
  ├─ Emit NetworkEvent to sink (JSON Lines)
  └─ Enforce MaxEventsPerSecond token bucket
        │
        ▼
Rotate output file when size limit reached; purge files older than RetentionDays
```

## Security requirements

- **Npcap is an external dependency.** The sensor references it but never downloads or installs it.
- **Elevation required.** The process must run as Administrator. Missing elevation is a startup blocker, not a degraded mode.
- **No privileged service account changes.** The sensor does not create Windows services, change ACLs, or modify IIS.
- **Events are write-once appends.** Rotation replaces files but never edits existing content.
- **No default capture.** `Enabled: false` and empty `Ports` means zero packets are observed.

## Integration with milestones

| Milestone | Relationship |
|---|---|
| M4 Observability | NetworkSensor events feed the same structured event stream; rotation/retention patterns align. |
| M5 Dashboard | Loopback-only dashboard view of NetworkSensor events; Windows authentication before any remote use. |
| M7 Controlled activation | If WPShield is eventually placed in front of IIS via ARR (M7), the gateway already sees HTTP traffic; NetworkSensor becomes complementary network-layer visibility, not redundant. |

## Out of scope for this design

- Packet injection or blocking.
- Decryption of TLS payloads (only TLS handshake metadata: `tls: true`).
- Intrusion prevention signatures.
- Integration with WordPress internals (database, `wp_options`, etc.).

## Next steps

1. Add `src/WPShield.NetworkSensor/` project targeting `net10.0-windows`.
2. Add SharpPcap + PacketDotNet to `Directory.Packages.props`.
3. Implement configuration binding and validation.
4. Implement BPF filter construction and live capture loop.
5. Implement JSON Lines event sink with rotation.
6. Add unit tests for configuration validation, path stripping, and event serialization.
7. Add integration test using a synthetic local HTTP server and loopback capture (requires Npcap in CI leg).
8. Write `docs/es/diseno-sensor-red.md` mirroring this document.
