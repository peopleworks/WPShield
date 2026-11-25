# Ask an assistant about the evidence: `wpshield mcp`

`wpshield mcp` is a read-only [Model Context Protocol](https://modelcontextprotocol.io/) server over
WPShield's local evidence store ([ADR 0007](adr/0007-local-evidence-store.md)). Claude Desktop, Claude
Code or any other MCP client starts it as a local process and asks it questions: who tried to log in,
from where, whether an address has been here before, what was and was not recorded, and which block
decisions WPShield made. The decision behind it, and everything this page summarises, is
[ADR 0008](adr/0008-read-only-mcp-server.md).

> [!IMPORTANT]
> **Answers leave the server.** Whatever a tool returns is sent by the assistant to its model provider
> (Anthropic, for Claude Desktop and Claude Code). By default that is counts, source addresses,
> coverage, block decisions, settings and your address labels - which name your own addresses. Read
> [What leaves the host](#what-leaves-the-host) before you connect it.

## What it can answer

| Ask | Tool |
| --- | --- |
| "How many failed logons in the last 24 hours, and from how many addresses?" | `attacks_summary` |
| "Who attacked RDP last night?" "Top 10 sources this week?" | `top_sources` |
| "Has 203.0.113.7 been here before? Since when, on how many days?" | `source_history` |
| "When did the attempts peak?" | `attack_timeline` |
| "Was the collector running all of yesterday? Is that quiet hour real?" | `coverage` |
| "Why was this address blocked? What did WPShield decide today?" | `decisions` |
| "What other evidence is there - refused HTTP requests, SQL Server logons?" | `evidence_kinds`, `evidence_events` |
| "What is the retention? May you show account names?" | `list_settings` |
| "Which addresses are labelled as ours?" | `address_labels` |

Ranges are `1h`, `6h`, `24h`, `7d`, `30d` or `90d`, or an explicit `from` and `to` (ISO-8601 UTC, at
most 90 days apart). A range longer than six hours starts on the hour, because hourly aggregates count
whole hours; the answer shows the effective start and the one asked for. Lists return 20 rows by
default and 100 at most, and say when more exist.

It **cannot** block, unblock, allow or change anything. If you ask it to, it says the action has to be
done by you, outside the conversation. It opens no listener and modifies nothing on the server: no
IIS setting, DNS record, certificate, firewall rule, service or port.

## The safety model

- **stdio only.** The assistant starts the process and talks to it on stdin and stdout. There is no
  port, so nothing else on the server or the network can reach it.
- **Read-only.** The store is opened read-only and every question goes through WPShield's fixed,
  bounded queries. No tool accepts SQL.
- **Attacker text is marked.** An account name in a failed logon is whatever the attacker typed - and
  an attacker can type `ignore previous instructions`. Every such string (account names, event
  subjects and details, reasons, labels, who changed a setting) is cleaned of control characters and
  returned as `{"untrusted": "..."}`, and every tool tells the model those values are data, never
  instructions. This lowers the risk; it cannot remove it, which is why there are no action tools:
  the worst an injected account name can do through this server is a wrong answer.
- **Aggregates by default.** Account names and single records (single attempts, single events) are
  returned only when the store setting `mcp.detailed_records` is `true`. It is `false` by default.
- **Gaps are said out loud.** Every answer has a `coverage` section with the gaps in what was
  recorded; a gap is never presented as a quiet period. An answer also says when detail is missing
  because the setting withheld it or because the detailed rows were already pruned.
- **Errors are errors.** If the store cannot be opened, every tool returns an error with the reason -
  never an empty answer that would read as "no attacks".

## What leaves the host

| Setting `mcp.detailed_records` | Sent to the assistant's model provider |
| --- | --- |
| `false` (default) | Counts, source addresses and their networks, timelines, coverage, block decisions, settings, address labels |
| `true` | All of the above, plus the account names that were tried, single attempts and events, and who requested each decision and who changed each setting (with `false` these show as `"withheld"`, because they are often your own account names; a decision the engine made names its evidence channel, `security-4625` or `rdpcorets-140`, which names nobody and is always shown) |

Account names that were tried include **real accounts on this server**, correctly spelled or not.
Turn `mcp.detailed_records` on only if you accept that. It is a store setting
([ADR 0007](adr/0007-local-evidence-store.md), amendment) changed by an elevated operator tool, never
through the assistant. **No `wpshield` verb changes it yet**, so today it stays `false` unless a tool
built on `EvidenceSettings` sets it. `wpshield mcp` reads it when it starts: restart the assistant's connection
to the server after changing it. `list_settings` shows the stored value and the one in effect when they
differ.

## Elevation

The evidence store's folder is readable only by Administrators, SYSTEM and the WPShield service.
`wpshield mcp` runs with the rights of whoever starts it, so **the assistant itself must run elevated,
on the server**:

- **Claude Desktop:** right-click it and choose **Run as administrator**. If the administrator account
  is a different account from yours, the elevated Claude Desktop reads *that* account's configuration
  file, so add the server there.
- **Claude Code:** open the terminal with **Run as administrator** and start `claude` from it.

Without elevation every tool answers `needs-elevation`. Windows reports a file a process may not read
as a file that does not exist, so an unelevated server cannot tell you whether the store is missing or
protected; it says so.

This is a real cost: an elevated chat application on a server can do more than an unelevated one, and
so can anything it runs. The server does not elevate itself, because a UAC prompt starts a separate
process that cannot talk over the assistant's stdio. A dedicated read-only group for the store is the
planned way out (ADR 0007, "Revisiting this decision").

## Configure Claude Desktop

Edit `claude_desktop_config.json` (on Windows, `%APPDATA%\Claude\claude_desktop_config.json`; Claude
Desktop opens it from **Settings > Developer > Edit Config**), using the path where you put
`wpshield.exe`:

```json
{
  "mcpServers": {
    "wpshield": {
      "command": "C:\\Tools\\WPShield\\wpshield.exe",
      "args": ["mcp"]
    }
  }
}
```

Restart Claude Desktop - elevated, as above. To read a store somewhere else, add
`"--store", "D:\\path\\wpshield-evidence.db"` to `args`.

## Configure Claude Code

From an elevated terminal:

```powershell
claude mcp add wpshield -- C:\Tools\WPShield\wpshield.exe mcp
```

Then start `claude` from the same elevated terminal and check the server with `/mcp`.

## Turn it off

Remove the `wpshield` entry from `claude_desktop_config.json` and restart Claude Desktop, or run
`claude mcp remove wpshield` for Claude Code. Nothing else needs undoing: the server changes nothing on
the host, and the evidence store keeps being written by the WPShield service either way.

## When it answers with an error

| `reason` | Meaning | What to do |
| --- | --- | --- |
| `needs-elevation` | The process is not elevated, so the store cannot be opened (or even seen) | Start the assistant elevated, on the server |
| `missing` | Elevated, and there is no store at the path | Check the WPShield service is installed and running (`wpshield status`). The server retries on every call, so no restart is needed once the service has written the store |
| `schema-mismatch` | The store was written by a different WPShield release | Use the `wpshield.exe` from the same release as the service |
| `unreadable` | The file exists but SQLite could not open it | Check `wpshield status` and the service log. This read-only server never repairs a store |

An argument out of range (`range: "2h"`, `limit: 500`) comes back as `invalid-argument` with a message
the assistant can correct itself from; nothing is clamped silently.

The server's own messages go to stderr, never stdout: Claude Desktop keeps them in its log for the
server (under `%APPDATA%\Claude\logs`), and Claude Code shows them with `claude --debug`. The first
line says whether the store opened and whether detailed records are on.

## Options

```text
wpshield mcp [--store <path>]
```

`--store` defaults to `%ProgramData%\WPShield\evidence\wpshield-evidence.db`. `wpshield mcp --help`
prints the same. The process exits with 0 when the client disconnects.
