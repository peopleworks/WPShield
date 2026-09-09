# ADR 0003 — Operator tooling moves to a .NET CLI

- **Status:** Accepted
- **Deciders:** WPShield maintainers
- **Affects:** every script under `scripts/` except the triage tool, and the shape of every future
  operator-facing feature

## Context

WPShield is a .NET project whose operator surface is PowerShell. Measured on the day this was
written:

| | Lines |
| --- | --- |
| C# under `src/` | 9,831 |
| PowerShell under `scripts/` | **5,561** |

**Thirty-six per cent of the project is PowerShell**, and 1,264 of those lines are
`Test-WPShieldScripts.ps1` — a hand-built test harness that exists to supply what `dotnet test`
supplies for free: parse checking, encoding checking, a structural guard against writes, and a
comparison that the scripts have not drifted from the code they mirror.

That was a reasonable first choice. A Windows Server has PowerShell 5.1 on it and nothing else
guaranteed, an incident does not wait for a build, and a single ASCII file can be copied to a server
by any route, including a chat window. Every one of those reasons was real.

Three days of running the scripts against a live server hosting sixty-six sites is what changed the
balance.

## What it actually cost

Of ten defects found in those three days, **three cannot exist in C#**:

| Defect | Why C# forecloses it |
| --- | --- |
| `@('config', $name, 'obj=', $account, 'password=', '')` — Windows PowerShell 5.1 **drops** the empty argument, so `sc.exe` rejected the command line and the install threw at step 4 of 6, leaving the gateway running as `LocalSystem` with unrestricted directories | `ProcessStartInfo.ArgumentList` is a typed collection; an empty element is an empty argument |
| `-replace '\\', '\\\\'` emitted **four** backslashes, because a .NET replacement string does not treat backslash as an escape. The printed configuration could not be pasted | A string is a string |
| `$LASTEXITCODE` from a native call leaked out of the test harness, which printed `All 71 checks passed` and then failed the build with it | The exit code is what you return |

They share one property, and it is the one that matters: **no test saw any of them, because there is
no compiler.** All three were found by an operator on a production server.

### The argument that settles it

`Test-WPShieldScripts.ps1` documents its own fourth section like this:

> The triage tool reports whether WPShield would refuse a request to each artifact it finds. It
> answers that from its **own copies** of the gateway's extension and directory lists, because it has
> to run on a server with no .NET runtime and no build of WPShield on it. **Copies drift.** A drifted
> copy does not fail loudly — it quietly reports coverage the gateway does not have, which is worse
> than reporting nothing.

An entire category of test exists to watch a copy for drift. In C# there is no copy: the tool
references `WPShield.Rules.WordPress` and the whole category disappears.

### The part that is not about defects

An operator running this at eleven at night has to know seven file names and each one's parameters.
There is no `--help` that lists what the tool can do. For a .NET product that is the wrong front
door, and it is the reason this ADR exists at all: the request came from the operator, not from the
maintainers.

## Options

### Option A — Leave it in PowerShell, keep hardening the harness

The harness now runs under both PowerShell 7 and Windows PowerShell 5.1 in CI and exercises the real
`sc.exe` grammar. That closes the three defects above and nothing else. Every future script starts
from zero type safety again, the drift check stays, and the front door stays seven file names wide.

### Option B — Move everything, including the triage tool

Deletes 5,561 lines of PowerShell and the drift check with them. It also deletes the property the
triage tool was built for: on the evening the compromise was found, it was pasted into an RDP window
on a server that had no WPShield installed and was not trusted enough to install one. A binary is a
different trust proposition on a box you already suspect.

### Option C — Move everything except the triage tool

`install`, `uninstall`, `preflight`, `publish` and the IIS step that does not exist yet become verbs
of one `wpshield.exe`. `Invoke-WPShieldTriage.ps1` stays as it is: one ASCII file, no dependencies,
copyable by any route.

## Decision

**Option C.**

The dividing line is **when the tool runs**, not what it does:

| | Runs when | Form |
| --- | --- | --- |
| `triage` | Before anything is installed, on a host that may be compromised, urgently | **PowerShell**, unchanged |
| `preflight` | Before installing, deliberately | `wpshield.exe` |
| `install`, `uninstall` | Elevated, changing the machine | `wpshield.exe`, shipped inside the artifact it installs |
| `publish` | On a build machine that has the SDK | `wpshield.exe` |
| `enable` (the IIS step) | Against live traffic | `wpshield.exe`, and it is written here first |

### `System.CommandLine`, and it is stable now

`System.CommandLine 2.0.12` is a released first-party package rather than the long-running preview.
It supplies `--help`, typed and validated options, subcommands and exit codes — the things this
project has been hand-rolling in every script.

### A separate assembly, and that is forced rather than chosen

The CLI cannot live in `WPShield.Gateway`. `MultipartInspectionReaderTests.GatewayAssembly_ReferencesNoTypeThatCanWriteToDisk`
scans that assembly's type references for `File`, `FileStream`, `Directory` and `StreamWriter`, and
an installer copies files for a living. Putting the CLI there would force the disk-freedom guard to
be relaxed, and **a guarantee relaxed once is a guarantee that erodes** — the same reasoning that
already put `WPShield.Logging` in its own assembly.

So: `src/WPShield.Cli`, producing `wpshield.exe`.

## Consequences

### Everything the scripts learned has to survive the move

The scripts are not merely long; they are long because each one carries a defect that already
happened. None of that may be lost in translation, and this is the list the migration is checked
against:

- The installer **refuses** to install inside a directory IIS serves, before it creates, copies or
  registers anything.
- It **writes** the log path it hardened into the configuration the gateway reads, because hardening
  a directory nothing writes to hardens nothing.
- It names the service by a constant, never by a literal, so it can never be pointed at another
  service on a host running sixty-six applications.
- It changes **nothing** in IIS as a side effect.
- The closing notes must not instruct an operator to do what the tool just did.
- `preflight` reports both states of everything it checks, because the absence of a finding is not a
  finding.
- Every destructive verb supports a dry run, and the dry run does not require elevation.

### `--dry-run`, not `-WhatIf`

`SupportsShouldProcess` is a PowerShell idiom. The behaviour it provides — preview without change —
is not, and it is required on every verb that changes the machine. It is spelled `--dry-run`.

### The artifact carries two self-contained applications

`wpshield.exe` and `WPShield.Gateway.exe` publish into one directory. Their runtime files are
identical, so the directory holds one copy of each and the archive does not double. This is asserted
by the publish verb rather than assumed.

### CI keeps running the PowerShell suite

Until the last script is gone, `Test-WPShieldScripts.ps1` keeps running under both PowerShell 7 and
Windows PowerShell 5.1. When only the triage tool remains, most of the harness goes with the scripts
it was watching — and the drift check goes first, because the tool it watches will be the only one
left that still needs it.

### This does not change what the gateway does

No rule, no threshold, no traffic path and no default changes. This ADR is about the surface an
operator touches, and a migration that quietly altered behaviour would be the worst possible way to
run it.

## What this ADR does not decide

- **Whether the triage tool eventually moves too.** Once WPShield is installed on a host, the .NET
  runtime is already there and `wpshield triage` would work. The cold-start case is a server where
  WPShield is not installed yet — a new client, or an incident. Keeping two implementations would
  reintroduce exactly the drift this ADR removes, so if the triage tool ever moves, the PowerShell
  one is deleted rather than kept alongside.
- **Whether the IIS step is automated at all.** `AGENTS.md` says never modify IIS automatically. The
  `enable` verb is where that constraint gets revisited, in its own decision, and this ADR only says
  where such a verb would live.

## Revisiting this decision

Revisit if the CLI ever needs to run somewhere PowerShell can and it cannot — a host with no way to
receive a binary, or an environment where an unsigned executable is refused but a script is not.
That is the one condition under which Option C was the wrong split.
