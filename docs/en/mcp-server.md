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
> coverage, block decisions, settings and your address labels - which name your own addresses - and
> the host facts without their names: restarts, patch level, ports and verdicts, counts. Read
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
| "What did the IIS logs show today? Did a PHP file answer that should not have? Which sites' logs were not read?" | `web_summary` |
| "Who probed the sites this week? Who hammered `wp-login.php`?" | `web_top_sources` |
| "What were the newest web findings on site 4?" "What did 203.0.113.7 request?" | `web_findings` |
| "Tell me everything about 203.0.113.7: logons, web, decisions, allow-list." | `address_report` |
| "How is the server? How many unexpected restarts this month, with which bugcheck code? When was the last cumulative update?" | `host_health` |
| "Which sites run in a pool with administrator rights? Which binding answers every host name?" | `iis_sites` |
| "How many pools still run as an administrator? Is PHP mapped for the whole server?" | `iis_posture` |
| "Which ports are open to any address by the firewall rules? Is SMB or MySQL exposed?" | `listening_ports` |
| "Who is logged on? Who connected over RDP this week, from how many addresses?" | `rdp_sessions` |
| "Which accounts are administrators? Do attackers try a real account's full name? Which unsigned services or tasks run here?" | `host_inventory` |

Ranges are `1h`, `6h`, `24h`, `7d`, `30d` or `90d`, or an explicit `from` and `to` (ISO-8601 UTC, at
most 90 days apart). A range longer than six hours starts on the hour, because hourly aggregates count
whole hours; the answer shows the effective start and the one asked for. Lists return 20 rows by
default and 100 at most, and say when more exist.

The web tools and `address_report` take the named ranges `wpshield web` takes - `1h` to `30d` - and
no explicit `from` and `to`. They read the IIS log evidence of
[ADR 0011](adr/0011-http-evidence-from-iis-logs.md) through the same read API as `wpshield web` and
the desktop: coverage first, with every site the sensor knows and why a site's log was not read;
requests counted over whole hours; rule findings and the observations `WEB-OBS-001` (a `.php` file
that answered 2xx and is not a WordPress entry point), `-002` and `-003` (POSTs to `wp-login.php` and
`xmlrpc.php`). Web evidence is evidence only: nothing is decided or blocked from it. A site is named by
its ID, the number of its `W3SVC` log folder; `web_summary` lists the IDs the sensor knows.

`address_report` answers one address from every source in one call: its failed logons, the decisions
about it or its /24 or /64 and the one in force now, its web counts and newest findings, its label, and
whether the allow-list or a private range keeps the decision engine from deciding against it.

The host tools - `host_health`, `iis_sites`, `iis_posture`, `listening_ports`, `rdp_sessions` and
`host_inventory` - answer what the server *is*, from the host facts of
[ADR 0013](adr/0013-host-facts-and-the-command-center.md). They read the snapshots the WPShield
collector takes on its cadence and never read the host themselves, so nothing an assistant asks makes
WPShield probe the server. Every answer starts with the snapshot it read: its read time, its age,
whether it is stale (older than three times its cadence) and its status, with the reason and the remedy
when it is not `ok`. A remedy, and a reason that is not a fixed code, can name a path or a site, so they
follow `mcp.host_details`: without it only the reason code is returned and the remedy reads
``withheld (mcp.host_details); run `wpshield host` on the server to see it``. A fact the collector has not read yet is `no-snapshot-yet` and its values are
`null`: unknown, never none. Four of them take no argument; `rdp_sessions` takes `24h` or `7d` (default
`7d`, all the snapshot holds) and `host_inventory` takes a required `kind`: `accounts`, `services` or
`tasks`. None takes a path, a name or a command. Exposure verdicts are "by the Windows Firewall rules"
and never "reachable"; the patch level is what Windows reports, never a verdict of "outdated"; and the
inventory never holds a command line's arguments, only flags for what they contained.

It **cannot** block, unblock, allow or change anything. If you ask it to, it says the action has to be
done by you, outside the conversation. It opens no listener and modifies nothing on the server: no
IIS setting, DNS record, certificate, firewall rule, service or port.

## The safety model

- **stdio only.** The assistant starts the process and talks to it on stdin and stdout. There is no
  port, so nothing else on the server or the network can reach it.
- **Read-only.** The store is opened read-only and every question goes through WPShield's fixed,
  bounded queries. No tool accepts SQL.
- **Attacker text is marked.** An account name in a failed logon is whatever the attacker typed - and
  an attacker can type `ignore previous instructions`. Every such string (account names, request
  paths and user agents, event subjects and details, reasons, labels, site names, who changed a
  setting) is cleaned of control characters and
  returned as `{"untrusted": "..."}`, and every tool tells the model those values are data, never
  instructions. This lowers the risk; it cannot remove it, which is why there are no action tools:
  the worst an injected account name can do through this server is a wrong answer.
- **Aggregates by default.** Account names and single records (single attempts, single events) are
  returned only when the store setting `mcp.detailed_records` is `true`. It is `false` by default. The
  same setting holds back IIS site names, the request paths and user agents of web findings, and site
  remedies: without it a web answer carries site IDs, counts and rule and observation IDs.
- **The server's own map has its own switch.** The host tools withhold the names of sites, pools,
  accounts, services and tasks, host names, paths, local addresses and RDP source addresses unless the
  store setting `mcp.host_details` is `true`. It is `false` by default, and it is separate from
  `mcp.detailed_records` on purpose: allowing evidence detail for one investigation must not export the
  server's inventory with it. With it on, every such value comes back as `{"untrusted": "..."}`, because
  on a compromised host an attacker names the tasks and services.
- **Gaps are said out loud.** Every answer has a `coverage` section with the gaps in what was
  recorded; a gap is never presented as a quiet period. An answer also says when detail is missing
  because the setting withheld it or because the detailed rows were already pruned.
- **Errors are errors.** If the store cannot be opened, every tool returns an error with the reason -
  never an empty answer that would read as "no attacks".

## What leaves the host

| Setting `mcp.detailed_records` | Sent to the assistant's model provider |
| --- | --- |
| `false` (default) | Counts, source addresses and their networks, timelines, coverage, block decisions, settings, address labels; for web evidence, site IDs, rule and observation IDs, methods and statuses |
| `true` | All of the above, plus the account names that were tried, single attempts and events, and who requested each decision and who changed each setting (with `false` these show as `"withheld"`, because they are often your own account names; a decision the engine made names its evidence channel, `security-4625` or `rdpcorets-140`, which names nobody and is always shown); and for web evidence, IIS site names, the normalized request paths and user agents of findings, and the remedy for a site whose log was not read (it can name a folder on the server) |

| Setting `mcp.host_details` | Sent by the host tools ([ADR 0013](adr/0013-host-facts-and-the-command-center.md)) |
| --- | --- |
| `false` (default) | Counts, statuses with their reason codes, read times and stale flags; uptime, CPU, memory and disk; the patch level and the last cumulative update's title; unexpected restarts with their times and bugcheck codes; posture finding IDs and counts; port numbers, protocols, exposure verdicts and the listening program's file name; numbers of sessions, logons, users and source addresses; account flags and the full-name indicator (yes or no and a count, never a name); for services and tasks, the kind of account they run as, the executable's file name, the signature and the flags. Every name, path and RDP source address reads `"withheld"`, and so does the remedy of a fact that could not be read, and any reason that is not a fixed code |
| `true` | All of the above, plus site, pool, account, service and task names, binding host names, executable paths, specific local addresses, the source address of each RDP logon, and the remedies and free-text reasons of facts that could not be read - each as `{"untrusted": "..."}` |

Account names that were tried include **real accounts on this server**, correctly spelled or not.
Turn `mcp.detailed_records` on only if you accept that, and `mcp.host_details` only if you accept that
the assistant's provider receives a map of the server. Both are store settings
([ADR 0007](adr/0007-local-evidence-store.md), amendment) changed by an elevated operator tool, never
through the assistant: `wpshield settings set mcp.host_details true --reason <text>` from an elevated
prompt, or the desktop's **Settings** window. `wpshield mcp` reads both when it starts: restart the
assistant's connection to the server after changing one. `list_settings` shows the stored value and the
one in effect when they differ.

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
line says whether the store opened and whether detailed records and host details are on.

## Options

```text
wpshield mcp [--store <path>]
```

`--store` defaults to `%ProgramData%\WPShield\evidence\wpshield-evidence.db`. `wpshield mcp --help`
prints the same. The process exits with 0 when the client disconnects.
