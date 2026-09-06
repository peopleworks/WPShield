# Triage tool

`scripts/Invoke-WPShieldTriage.ps1` examines WordPress sites on a Windows and IIS host and reports
what is on disk that should not be, when each artifact was last used, and **which of it WPShield
would actually refuse a request to.**

It reads. It never deletes, quarantines, renames, moves or repairs anything, and it never executes a
file it finds.

## Where this came from

WPShield's rules used to come from a threat model. This tool, and the `WP-PATH-*` rules it reports
against, come from an incident: a real WordPress site on IIS running six webshells, whose IIS logs
still held the exploitation traffic in full. The triage was done by hand, over a couple of hours,
with ad-hoc PowerShell. This script is that work, generalised — because the next person to find a
strange file on a Windows WordPress host should not have to reinvent it.

The most useful thing that came out of that afternoon was not a list of shells. It was the sentence
*"every request that reached one of these carried no body, so WPShield could not have seen any of
it."* That measurement is what produced [request path inspection](m2-5-request-path-inspection.md),
and it is why this tool reports gateway coverage rather than only listing files.

## Running it

```powershell
# First, on a host you do not know: what would be examined?
.\scripts\Invoke-WPShieldTriage.ps1 -DiscoverOnly

# Then the run itself.
.\scripts\Invoke-WPShieldTriage.ps1 -OutputPath .\triage.jsonl
```

> **Running it from `cmd.exe`.** A `.ps1` is not executable from the command prompt: typing its name
> there opens it in an editor or reports an unrecognized command, depending on the file association.
> Call the interpreter explicitly, from an **elevated** prompt:
>
> ```
> powershell -NoProfile -ExecutionPolicy Bypass -File C:\temp\Invoke-WPShieldTriage.ps1 -OutputPath C:\temp\triage.jsonl
> ```

Run it as an administrator. An unprivileged shell cannot read the IIS configuration, cannot read the
IIS logs, and cannot see every file in the web root; the tool says so and continues rather than
failing, but the report is then incomplete in ways it cannot fully describe.

With no `-SitePath`, the tool asks IIS for its sites and looks for WordPress at the root of each and
one directory below it. Nothing about the host is assumed or hard-coded.

| Parameter | What it is for |
| --- | --- |
| `-SitePath` | One or more WordPress roots. Skips discovery. |
| `-IisLogPath` | IIS log root. Defaults to `C:\inetpub\logs\LogFiles`. Pass `''` to skip log correlation. |
| `-OutputPath` | Where the JSON Lines report goes. |
| `-RecentDays` | How far back the timestamp checks and the log scan reach. Default 30. |
| `-MaximumFileBytes` | Bytes read per PHP file, split between its head and its tail. Default 65536. |
| `-MaximumFilesScanned` | Bound on files examined per site. Default 200000. |
| `-MaximumLogBytes` | Bound on IIS log bytes read. Default 1 GiB. |
| `-MaximumFindings` | Bound on findings emitted. Default 5000. |
| `-DiscoverOnly` | List the sites and exit. |

Every bound has a default, and the report says when one was reached rather than stopping quietly. A
forensic tool that silently truncates is worse than one that refuses to start.

## What it checks

| ID | What it reports |
| --- | --- |
| `TRIAGE-001` | An executable file inside `wp-content/uploads`, `upgrade` or `updraft`. Those directories are data. |
| `TRIAGE-002` | An executable file inside a directory that exists to be served verbatim — `dist`, `static`, `node_modules`, `img` and the rest of the asset list. |
| `TRIAGE-003` | A `web.config` below the site root. On IIS a `web.config` can add a handler mapping, so writing one decides what the server executes. |
| `TRIAGE-004` | A file name Windows accepts but does not store literally: a trailing dot or space, an alternate data stream suffix, a control character. |
| `TRIAGE-005` | PHP that can execute code chosen at runtime, where either a request reaches that code or it is obfuscated. |
| `TRIAGE-006` | A hidden file whose name is a Unix timestamp — a dropper marker, and the shape that started the incident above. |
| `TRIAGE-007` | An executable file created *after* the content it holds was written. One is a backup tool; hundreds across a plugin tree is a mass-rewriter working through the site. |
| `TRIAGE-008` | The requests the IIS logs remember reaching a flagged artifact: how many, when they started and stopped, from which addresses, with which methods and status codes. |
| `TRIAGE-009` | Installed plugins and themes, with versions. |
| `TRIAGE-010` | **Host.** A scheduled task registered recently, or one whose action runs an interpreter. |
| `TRIAGE-011` | **Host.** A local account whose password was set recently, and who is in the Administrators group. |
| `TRIAGE-012` | **Host.** A Windows service whose binary lives in a temporary, user or web directory. |
| `TRIAGE-013` | **Host.** Autorun keys. |
| `TRIAGE-014` | **Host.** Executable content written recently into a staging directory such as `C:\Windows\Temp`. |
| `TRIAGE-015` | **Host.** Microsoft Defender's own record of threats on this machine. |

### Why `TRIAGE-005` is not just a list of function names

Because a list of function names produces a report nobody reads. WordPress core calls
`base64_decode`. Half the plugin ecosystem calls it. A check that fires on it reports several
hundred files on a healthy site, and the operator learns to ignore the tool.

So markers are grouped by what they *mean* — a way to run code chosen at runtime, request-controlled
input that can reach it, and the habits of someone hiding what a file does — and a file is reported
only when those combine into something a legitimate file has no reason to be: a sink a request can
reach, a sink wrapped in a decoder, or obfuscation dense enough that the author was concealing rather
than compressing.

The lookbehind in each pattern matters more than it looks: without it, `$database->exec(...)` —
ordinary PDO, present in a great many legitimate files — matches the `exec` sink, and that single
false positive would be the largest source of noise in the whole check.

### Why `TRIAGE-009` ships no vulnerability database

Because a list of CVEs baked into a script is out of date the day it is written, and an operator who
trusts a stale one is worse off than one who looks the version up. The tool reports names and
versions and says where to check them. In the incident this came from, one line — the slider plugin's
version — was what identified the entry point.


## The host checks, and why they are separate

Everything else in this tool looks inside a WordPress site. That is the right scope for a tool named
after WordPress, and it is the wrong scope for the question an operator actually has, which is *"am
I still compromised?"*

A webshell is a foothold, not the whole of it. In the incident this tool comes from, the intruder
had moved on to writing into `C:\Windows\Temp` — outside the web root, outside every other check
here, and untouched by stopping the site. **Stopping IIS closes the door they came in by and does
nothing about a scheduled task, a service, an autorun key or an account.**

```powershell
.\scripts\Invoke-WPShieldTriage.ps1 -IncludeHost -OutputPath .\triage.jsonl
```

`-IncludeHost` is opt-in because it answers a different question from the rest of the script and
needs elevation to answer it properly. **The summary always says whether it ran**, because a section
that is silently absent reads exactly like a section that found nothing — the same principle the
preflight applies to an unreadable IIS configuration.

Still read-only. Nothing is disabled, deleted or repaired.

Group membership is resolved from the well-known SID rather than the name `Administrators`, because
the group is `Administradores` on a Spanish Windows and a check written against the English name
finds nothing there — and reports that absence in the reassuring direction.

## The gateway verdict

This is the part worth having. Every file finding carries the verdict WPShield's request-path rules
would return for an HTTP request to that file, computed with the same directory lists, the same
extension lists, the same summed scoring and the same two thresholds the gateway uses.

| Verdict | Meaning |
| --- | --- |
| `blocked` | The gateway refuses the request outright. |
| `observed` | It scores and is recorded, but forwarded. Below the block threshold. |
| `not-covered` | **The file is executable and no request-path rule fires.** The gateway forwards a request that reaches code. A real gap. |
| `not-applicable` | Requests to this file are not how it does harm, so a rule family that decides about executable requests has nothing to say about it. |

The summary ends with a count of each, and prints the `not-covered` paths in full:

```
Would WPShield refuse a request to the executable artifacts above?
  blocked outright: 11
  scored but forwarded: 0
  not covered by any request-path rule: 1

WPShield would forward a request to each of these. Gateway coverage is not containment:
  ...\wp-content\plugins\exampleslider\wp\import1.php
```

`not-applicable` exists so that `not-covered` keeps meaning something. An uploaded `web.config` is
remote code execution on IIS, but not because anybody requests it — IIS reads it on its own and
applies the handler mappings it declares. Counting it as a gap in the request-path rules would
inflate the one number a reader is meant to act on, with a case no request-path rule could ever
close. What covers a `web.config` is the [upload rule set](m2-upload-rules.md), at the moment the
file arrives.

**A tool that only listed what its own product catches would be an advertisement.** The number above
is printed because it is sometimes not zero, and on the incident that produced this tool it was not.

## What the report contains, and what it deliberately does not

Findings are written as JSON Lines in the **same envelope the gateway's own log uses** —
`timestamp`, `level`, `category`, `message`, `state` — with timestamps in the same format. A triage
report and a gateway log can be read by one parser, sorted together as text, and correlated on the
same field names.

```json
{"timestamp":"2026-09-06T20:22:17.9506873+00:00","level":"Warning","category":"WPShield.Triage",
 "message":"A PHP file can execute code chosen at runtime, and either a request reaches that code or it is obfuscated.",
 "state":{"ruleId":"TRIAGE-005","requestPath":"/wp-content/plugins/example/wp/import1.php",
          "executionSinks":["eval"],"requestInputs":["post"],"obfuscation":["base64_decode"],
          "gatewayVerdict":"not-covered","gatewayScore":0,"gatewayRuleIds":[],
          "sha256":"2B17DF...","sizeBytes":88}}
```

**No file contents. Not one byte.** A triage report is written to be attached to a support thread or
a public issue, and a report that reproduces the payload distributes the webshell to everyone who
reads it. Marker names, sizes, hashes and timestamps identify a file without republishing it. To read
a file, open it yourself, in an editor, on a machine that will not run it.

**Nothing outside ASCII.** Every string is escaped into the printable ASCII range, so a file name
recovered from a host somebody else has been writing to cannot carry a control character or an ANSI
escape sequence into a terminal, a log viewer, or a browser rendering an issue. This is the same
reasoning the gateway applies to rule evidence, applied to a report that will travel further.

One thing the report *does* carry is client IP addresses, in `TRIAGE-008`. They are the point of that
check — they are what an operator blocks and what an abuse report needs — but they are also the one
field in the report that is somebody's personal data, so it is worth a moment's thought before
pasting a report into a public issue.

## What it does not do

- **It does not tell you a site is clean.** It reads what is on disk today. An intruder who cleaned
  up leaves a disk that looks like a healthy one, and the tool will say so. A clean run is the
  absence of evidence.
- **It does not enumerate alternate data streams.** `TRIAGE-004` reports a stream suffix in a *name*,
  but the tool does not ask each file whether it carries hidden streams: that is one extra system
  call per file across a tree with tens of thousands of them. A file hiding a payload in a stream is
  not reported.
- **It does not read the database.** Injected content in `wp_posts` or `wp_options`, and the
  administrator account an attacker adds, are invisible to it.
- **It does not decide anything.** Findings are a starting point. Read each file yourself.
- **It does not clean up.** By design, and permanently. Deleting a webshell before understanding how
  it arrived removes the evidence and leaves the way in.

On that last point, the advice from the incident this came from still stands: for a compromise of any
age, on a host running other applications, **rebuild rather than disinfect.** Shells that have been
present for years, on a machine you cannot fully inventory, cannot be proven gone.

## How the tool is kept honest

`scripts/Test-WPShieldScripts.ps1` runs in CI on every push and pull request, and enforces five
things. Each exists because of a defect that actually happened.

**Every script parses**, under PowerShell 7 *and* under Windows PowerShell 5.1 — which is what a
Windows Server host has without anything being installed on it. PowerShell 7 accepting a script is
not evidence that 5.1 will.

**Every script is pure ASCII.** Windows PowerShell 5.1 reads a `.ps1` without a byte order mark as
ANSI, so a UTF-8 em dash arrives as two characters, one of which is a typographic quote that
PowerShell treats as a string delimiter. Quote parity then breaks silently and the parser reports an
error a hundred lines further down, in code that is correct. This exact defect shipped a triage
script that would not run.

**The triage tool has no write path but its own report.** Its AST is walked for every write-capable
cmdlet and .NET member, every `[System.IO.File]::Open` is required to ask for read access only, and
exactly one `StreamWriter` is permitted. Say plainly what this is worth: it is an *inventory*, not a
proof. The gateway's equivalent guarantee — that no request body can reach the disk — is proved, by
scanning the assembly's type references for any file API at all. Nothing that strong exists for a
script, because PowerShell can call a cmdlet whose name it computes at runtime. So the check also
bans the two constructs that would make the inventory meaningless: invocation through a variable, and
`Invoke-Expression`. With those gone the inventory is complete for anything a reader can see, which
is the honest version of the claim.

**The rule vocabulary has not drifted.** The tool carries its own copies of the gateway's extension
and directory lists, because it must run on a server with no .NET runtime and no build of WPShield on
it. Copies drift, and a drifted copy does not fail loudly — it quietly reports coverage the gateway
does not have, which is worse than reporting nothing. So the lists are compared, entry by entry,
against the C# sources, and the deliberate exclusions from the asset list are checked to still be
excluded.

**The tool runs, end to end, and reaches the right verdicts.** A fixture reproducing the incident's
directory structure is built, scanned, and asserted: the artifacts in covered directories come back
`blocked`, the one in the plugin's own PHP directory comes back `not-covered`, and a generated
stylesheet served from PHP stays silent. This is the most important check in the file, because it is
the only one that fails when the script does not run at all — which is how both defects found while
writing it presented.

## See also

- [Request path inspection](m2-5-request-path-inspection.md) — the gateway rules this reports against.
- [Upload rules](m2-upload-rules.md) — what covers a file at the moment it arrives.
- [Threat model](../../THREAT_MODEL.md)
