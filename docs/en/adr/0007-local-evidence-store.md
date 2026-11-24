# ADR 0007 — A local evidence store, and who may read it

- **Status:** Proposed
- **Deciders:** Pedro Hernández (maintainer)
- **Affects:** `AGENTS.md`, `WPShield.Service`, the desktop monitor, the CLI, `wpshield uninstall`,
  and a future `wpshield mcp` server

## Context

WPShield remembers nothing. The desktop's **Attacks** view re-reads the Windows Security log every
time it opens and keeps what it sees live only until the window closes. On the production host that
started this project, the Security log covered about a week under brute-force volume, so a week is
also the longest history anyone can see. During the incident, a scheduled task that deleted IIS logs
older than 30 days removed the evidence of how the webshells arrived. Evidence that lives only in a
log someone else rotates is evidence WPShield does not have.

Three features now need memory:

1. **History beyond the Windows logs**: 30 or 90 days of attacks, when an address was first seen,
   whether it came back.
2. **The decision engine** (ADR 0006): escalating a block for an address that returns needs to know
   it returned, and every block decision needs an audit trail of what was decided and why.
3. **Asking questions**: the maintainer wants to ask an assistant, through the Model Context Protocol,
   "who attacked RDP last night?" or "why was this address blocked?". That needs a store to answer
   from, and rules for what may leave the host in an answer.

## Decision

**WPShield keeps a local SQLite database of security evidence, written by the WPShield service and
read by the desktop, the CLI and a future MCP server.** It is history. It is never the source of an
enforcement decision at startup.

### 1. One writer, the service

The WPShield service is the only writer. It runs whether or not anyone has a window open, starts
with Windows, and records continuously; a desktop that wrote would leave gaps whenever it was
closed. The desktop, the CLI and an MCP server open the database **read-only**.

The service runs as `NT SERVICE\WPShield`. Reading the Security log needs that account in the
built-in **Event Log Readers** group (`S-1-5-32-573`). That is a server setting: `wpshield preflight`
reports it as a blocker with the command to run, and nothing adds the account on its own.

### 2. Where it lives and who may open it

`%ProgramData%\WPShield\evidence\wpshield-evidence.db`, in WAL mode. The folder's permissions are
**replaced, not added to** (the rule for every WPShield directory): `SYSTEM` and `Administrators`
full control, `NT SERVICE\WPShield` modify, nobody else. Granted by SID. Reading the evidence
therefore needs an elevated process, the same requirement as reading the Security log directly; a
web application pool, or code running in one, cannot open it.

### 3. What it stores

| Table | Content | Kept |
| --- | --- | --- |
| `auth_failures` | One row per failed logon: UTC time, channel and record ID (unique together), source address and port, account name, reason code, logon type | 14 days, at most 5,000,000 rows |
| `hourly_sources` | Per hour, per source address, per service: attempts, attempts on nonexistent accounts, distinct accounts | 400 days |
| `decisions` | Every "would block", block, expiry, unblock and allow-list change: time, address or range, rule ID, mode, the evidence that asked, expiry | 400 days |
| `coverage` | For each source and interval: read, limited, unavailable, or service not running | as long as the data it describes |
| `collector_state` | Last record ID read per channel | — |

Later sources (the gateway's HTTP evidence, IIS logs, SQL Server, FTP) add tables under the same
rules, each in its own change.

**Never stored:** request bodies, query strings, cookies, authorization headers, nonces, tokens,
passwords, file contents. The same list the gateway's log already refuses. Account names, user
agents and paths are attacker-chosen text: cleaned of control and format characters and bounded
before they are written, exactly as they are before they are shown.

### 4. Bounded, and gaps are recorded

Every table has a row bound and an age bound, and the file has a size bound (2 GB by default). When
a bound is reached, the oldest raw rows go first and the aggregates stay. Each pruning and each
period the service was not running is written to `coverage`, so every view can draw **no data**
where nothing was recorded. A quiet period and an unrecorded period must never look alike.

### 5. History, never the source of a block

When the service starts, it may catch up the store from the Windows logs (by record ID, so nothing
is stored twice). It **does not** feed that history to the decision engine, and it **never restores
blocks** from `decisions`. ADR 0006's guarantee - a block lives exactly as long as the process -
holds because enforcement starts from an empty block set and from evidence that arrives after the
process started. A database that resurrected blocks would turn every past mistake into a permanent
one.

### 6. Readers ask questions; they do not act

The desktop, the CLI (`wpshield attacks ...`) and a future `wpshield mcp` server read through one
query library with fixed, parameterised queries and bounded results (row limits, time ranges). No
reader accepts free SQL.

**The MCP server** gets its own ADR before it exists. This one fixes the constraints it inherits:

- **stdio only at first.** The assistant starts `wpshield mcp` as a local process; there is no
  network listener, which keeps the loopback-only rule for management interfaces. Reaching the store
  from another machine is a separate decision with authentication.
- **Read-only.** Tools answer questions (top sources, an address's history, coverage, decisions). No
  tool blocks, unblocks or changes configuration until an ADR defines how a human confirms the
  action outside the model.
- **Attacker text is data, never instructions.** Account names, paths and user agents reach the
  model inside structured fields marked as untrusted. An attacker who logs in as `ignore previous
  instructions` must not be able to steer an assistant that reads the result. This is the main
  reason the first version has no action tools.
- **What leaves the host is the operator's choice.** An answer travels to the assistant's model
  provider. Results are aggregated by default; raw records are returned only when asked for, and the
  documentation says so.

### 7. Uninstall keeps it

`wpshield uninstall` keeps the evidence store unless told otherwise, like the logs: an uninstall
during an incident is the worst moment to delete the record of what happened.

## Consequences

- **A new dependency:** `Microsoft.Data.Sqlite` (MIT) and its native SQLite bundle (SQLitePCLRaw,
  Apache 2.0). Both permit redistribution in WPShield's MIT release; `NOTICE.md` lists them.
- **The store's project stays portable.** Schema, retention and queries live in a library with no
  Windows dependency, so the Linux CI leg tests them; only the collector that reads the event log is
  Windows-only.
- **Disk writes on the server.** Bounded by section 4, under a folder no other account can read.
- **A new manual step:** adding `NT SERVICE\WPShield` to Event Log Readers.
- **The desktop's Attacks view** gains 7-day and 30-day ranges from the store, and keeps reading the
  Security log directly when the service is not installed.

## Alternatives considered

- **More JSON Lines files.** The gateway already writes them, and they stay. But every question
  ("first seen", "came back", "top sources over 30 days") would re-read and re-aggregate every file,
  and an MCP server would need a query engine anyway.
- **The SQL Server, MySQL or PostgreSQL already on the host.** They belong to the hosted
  applications. A security tool's evidence should not depend on, or be readable through, the
  databases an attacker is trying to reach.
- **LiteDB or another embedded document store.** Workable, but SQLite is the format every tool can
  open, which matters when evidence has to be inspected by hand during an incident.
- **The desktop as the writer.** Simpler, and it records only while a window is open.

## Revisiting this decision

- If a reader needs access without elevation, add a dedicated local group rather than widening the
  folder's permissions.
- If remote MCP access is wanted, it is a new ADR: authentication, transport, and what an answer may
  contain when it leaves the host over a network.
