# Host facts

[Español](../es/datos-del-host.md) · [Documentation index](../README.md) ·
[ADR 0013](adr/0013-host-facts-and-the-command-center.md)

WPShield's evidence answers "who is attacking this server". Host facts answer "how is this server doing":
its health and unexpected restarts, its IIS sites and posture, what listens on the network and what the
firewall rules admit, who has a session, and which non-Microsoft accounts, services and tasks it runs.

Host facts are **read-only**. No fact, verb or snapshot stops, starts, deletes or reconfigures anything on
the server. Every remedy is text for a person to carry out by hand.

## Where the facts come from

`wpshield evidence collect` takes the snapshots, elevated, and stores them in the evidence store (schema 3).
`wpshield host` reads them. A model never makes WPShield probe the host: the MCP tools of the next phase read
stored snapshots only.

| Fact | What it holds | Read from | Cadence | Needs elevation |
| --- | --- | --- | --- | --- |
| `host_health` | Uptime, CPU, memory, free space per fixed volume (the IIS log volume marked), store size | `GetTickCount64`, `GetSystemTimes`, `GlobalMemoryStatusEx`, `DriveInfo` | 5 minutes | No |
| Patch level (in `host_health`) | `CurrentBuild`, `UBR` and `DisplayVersion`; the kernel file's version; the newest successful cumulative update with its date and the days since; failed installs in 30 days | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`, `ntoskrnl.exe` ProductVersion, `WindowsUpdateClient/Operational` events 19 and 20 | 5 minutes | No |
| Unexpected restarts | Each crash once, with its bugcheck code (`0x133 DPC_WATCHDOG_VIOLATION`) | System log 41, 6008 and 1001, grouped per crash | At start and every 15 minutes | No |
| `iis_sites` | ID, name, state, bindings, pool and pool identity **type** | The read-only IIS reader `wpshield audit` uses | 15 minutes | Yes |
| `iis_posture` | The audit's finding IDs, severities and counts, and "pools as an administrator: N of M" | The audit's own checks, read-only | At start and every 6 hours, and after every manual `wpshield audit` | Yes |
| `listening_ports` | Protocol, port, binding, owning executable, exposure verdict | The TCP and UDP listener tables and the firewall policy (COM, read-only) | 15 minutes | For process names and some rules |
| `rdp_sessions` | Current sessions; RDP logons and reconnections of 7 days with their source address | `WTSEnumerateSessions`; LocalSessionManager 21 and 25 | 15 minutes | No |
| `host_inventory` accounts | Name, enabled, Administrators and Remote Desktop Users membership, last logon, password age | `NetUserEnum`, `NetLocalGroupGetMembers` | At start and every 6 hours | Yes |
| `host_inventory` services | Non-Microsoft Win32 services: state, start mode, run-as account, executable, signature, flags | The services registry key and the service control manager | At start and every 6 hours | Yes |
| `host_inventory` tasks | Non-Microsoft scheduled tasks: path, state, principal, last and next run, executable, signature, flags | The Task Scheduler (COM, read-only) | At start and every 6 hours | Yes |

Outbound connections from web worker processes (`w3wp.exe`, `php-cgi.exe`) are **not measured yet**: a
snapshot misses a two-second callback. They get their own ADR and sensor.

### Patch level: facts, never a verdict

The registry's build, the kernel file's version and the Windows Update log can disagree: a crash dump
can show an older kernel than the updates the update history lists. `wpshield host health` shows all
three side by side, says when the kernel file's revision differs from the registry's `UBR`, and counts
the days since the last successful cumulative update. An unreadable update log reads `unknown`, never
"none"; "not found in the Windows Update log" says how far back the log reaches. WPShield has no
offline source of the latest build, so it never calls a host outdated.

## Honest about what it could not read

Every snapshot carries its read time and a status: `ok`, `partial`, `needs-elevation`, `unreadable` or
`not-measured`. Anything other than `ok` names its reason and the remedy. A snapshot older than three times
its cadence is shown as **stale**. A fact never read says "no snapshot yet". Zero restarts and "the System log
could not be read" never look alike.

## Exposure, by the Windows Firewall rules

Each listener gets a verdict from the enabled inbound rules of the profiles in force: `open-to-any`,
`restricted`, `blocked`, `local-only` (bound to loopback) or `unknown` (the policy could not be read). The
verdict is always labelled **"by the Windows Firewall rules"** and never presented as "reachable": other
network filters, an endpoint product or a provider's edge firewall decide too.

When unsure, the verdict leans open: a rule scoped to a program whose path could not be read is taken to
apply, and a remote-address list is "restricted" unless it is `*` or `Internet`.

**Red:** SMB (139, 445), RPC (135), SQL Server (1433), MySQL (3306, 33060), PostgreSQL (5432), VNC (5900)
and WinRM (5985, 5986) when open to any address. Restricted to the addresses that need them, they are not
red. The remedy is to restrict the rule by hand, never to hide the finding.

## The inventory never stores secrets

- **Arguments are never stored or shown.** A service's or task's arguments can carry a password or a
  token, and an encoded command is the attacker's payload. They are reduced to flags and dropped:
  `has-arguments`, `encoded-command`, `contains-url`, `user-writable-path`.
- **Non-Microsoft only.** A service or task whose binary is signed by Microsoft is left out, **unless** it
  runs a script host (`cmd.exe`, `powershell.exe`, `mshta.exe`, `rundll32.exe`, ...) or carries an
  `encoded-command`, `contains-url` or `user-writable-path` flag: `cmd /c powershell -enc ...` is signed by
  Microsoft too. Services hosted in `svchost.exe` are judged by their `ServiceDll`.
- **Signatures are bounded.** Embedded and catalog Authenticode signatures are checked with
  `WinVerifyTrust`, without revocation checks, cached by path, size and write time, at most 300 per
  snapshot. The rest read `not-checked` until the next snapshot.
- **Passwords and descriptions are never read.** Account full names are read into memory for one
  comparison and dropped (below).
- **Changes are events.** An item added, removed or changed (executable, account or signature) between two
  snapshots is recorded as `host.inventory-change`, at most 500 a day per kind; beyond that they are counted.

### Do attackers know your account names?

At every accounts snapshot the collector compares the account names attempted in failed logons - the
attempts of the last 30 days still stored in detail, which is 14 days with the default
`retention.raw_days` - with the **full names** of the local accounts, in memory, ignoring case, accents
and spacing. It stores only whether any matched and how many:
"attackers try a real account's full name: YES (2)". The full names are never stored, logged or shown. A
match means the names leaked from this server, through its login screen or an intrusion.

## Commands

```text
wpshield host                                  every fact with its age and status
wpshield host health                           uptime, restarts with bugcheck codes, CPU, memory, volumes
wpshield host sites | posture | ports | sessions
wpshield host inventory accounts|services|tasks
wpshield host ... --json                       one JSON document
wpshield host ... --live                       read now, write nothing (run it elevated)
```

`wpshield audit` also records its summary - finding IDs, severities and counts, never names - as a posture
snapshot in WPShield's own evidence store. That is a write to WPShield, not to the server, and the audit
says so in its last line. An incomplete run (not elevated, IIS unreadable) is not recorded.

## Store

Schema 3 adds `host_snapshots` (bounded JSON, at most 256 KB per snapshot) and `host_health_hourly`.
Restarts and inventory changes are rows of `events`. Retention: the newest snapshot of every fact is always
kept, posture snapshots for 400 days, other snapshots for 7 days, hourly health for 90 days.

The migration is additive and one-way: once a schema-3 build opens a store, older builds refuse it. Update
the CLI and the desktop together, and run `wpshield evidence collect` once before opening the desktop.

## What leaves the host

Nothing yet: the MCP tools for host facts come in the next phase. They honour the new audited setting
`mcp.host_details` (off by default): with it off they return counts, statuses, verdicts, port numbers,
executable file names, restart times and bugcheck codes, and `withheld` for names, paths and addresses.
