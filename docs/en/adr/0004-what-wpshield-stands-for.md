# ADR 0004 — What WPShield stands for, and what it does not cover yet

- **Status:** Accepted
- **Deciders:** WPShield maintainers
- **Affects:** the name, the README, the site, and where a rule that is not about WordPress goes

## Context

The name was chosen in the first week, for a project that inspected WordPress uploads behind IIS. It
has been regretted since roughly the second, in the operator's own words:

> Qué pena que sólo le llame WPShield, debí llamarle IISShield o algo más, porque los ataques van a
> todos los sites aunque no sean WordPress.

The project has since stopped being what the name describes. **This is not a case of a name aging;
it is a case of the thing behind the name being re-engineered.**

| | Original design | Today |
| --- | --- | --- |
| Operator surface | 5,561 lines of PowerShell | `wpshield.exe`, verbs, `/?`, typed arguments |
| Inspection scope | The site | The site **and the host** — scheduled tasks, services, accounts, autoruns, Defender history |
| Brute force | Not addressed | [ADR 0002](0002-host-level-brute-force-defence.md), and rate limiting built |
| Traffic path | [ADR 0001](0001-production-traffic-path.md), IIS in front | Also a verified HTTP.SYS direct-binding option |
| How anything is known to work | By reading the script | Asserted: step order, permissions, mode discipline |

Of that list, **only the rule engine is about WordPress.** The CLI, the preflight, the installer, the
host triage, the rate limiter and the logging are about Windows and IIS.

### The measurement that makes this urgent

The server this project was built against runs **sixty-six IIS sites. Its own preflight detects two
of them as WordPress.** The other sixty-four are .NET applications — an e-invoicing API, an ERP
client portal, a BI server, a relay, an automation host, and fifty more.

WPShield today speaks to two of sixty-six and turns its back on the rest. The attacks do not: a scan
for `.env`, for `web.config`, for an exposed admin path, for a backup file left in a web root, goes
to every one of them.

## The proposal

Keep the letters and change what they stand for. **WPShield = Windows Power Shield.**

It costs nothing measurable: the repository keeps its URL, the namespaces keep their prefix, every
existing link keeps working, published artifacts keep their name, and an installed service keeps its
identity. What changes is what the name claims.

## Options

### Option A — Rename to something explicit

`IISShield`, `WinShield`, or similar. Buys clarity at the price of every namespace, every document
link, the published site, the artifact names, the service name in every existing install, and the
`NT SERVICE\WPShield` account an operator has already granted permissions to.

That is a large, entirely cosmetic migration for a project that has real work outstanding, and it
would be the second migration in a week for the same operator.

### Option B — Keep the name meaning "WordPress Shield" and stay WordPress-only

Honest about the rules and dishonest about everything else. The preflight, the installer, the host
triage and the rate limiter are not WordPress features and never were, and a name that describes only
the rule engine describes about a fifth of the code.

It also forecloses the direction the measurement points at, on a host where the name would be
protecting two sites out of sixty-six.

### Option C — Keep the letters, change what they stand for, and write down the debt

**WPShield = Windows Power Shield**, adopted now as a statement of direction, with the gap between
the name and the code recorded here with named exit conditions.

## Decision

**Option C**, with one condition that is not negotiable.

**The name states a direction. The README and the site must state what is covered today**, above the
fold, in the first screen a reader sees — not in a footnote and not implied by an architecture
diagram.

That condition is the whole point of this ADR, and it comes from three days of finding the same
defect in different clothes:

- an installer that reported hardening a directory the gateway never wrote to
- a preflight that reported checking a rule family it could not match
- a gateway that reported itself healthy while writing no evidence at all

Each was a tool claiming a state it had not achieved. **A name that claims Windows-wide protection
while shipping only WordPress rules is the same defect, in the largest possible font.** Adopting it
without writing this down would be the version of that mistake this project would deserve least.

## What makes the name true

Three exit conditions. Until all three are met, this ADR stays the thing that keeps the promise
visible.

1. **A second rule package that is not about WordPress, shipped and enabled by default.** The
   architecture already anticipates it: `WPShield.Abstractions` and `WPShield.Core` are free of
   ASP.NET Core, YARP, IIS and Windows dependencies — a Linux CI leg builds and tests exactly those
   three projects, which is what keeps that claim falsifiable. `WPShield.Rules.WordPress` is a
   package, not the engine.

2. **The README and the site say what is covered today.** A reader must be able to learn, without
   scrolling, that the rules today are WordPress rules and the host tooling is not.

3. **The rule identifier scheme has room for it.** Today every identifier is `WP-*`, `FILE-*` or
   `MULTIPART-*`. `WP-` means WordPress and must keep meaning that; a family that is not about
   WordPress needs its own prefix rather than being filed under one that lies about it.

## Consequences

### `WPShield.Rules.WordPress` keeps its name

It is a WordPress rule package and the name is exactly right. Nothing about this ADR renames it —
the point is that it becomes *one of* the rule packages rather than *the* rule package.

### The irony is worth naming out loud

"Power Shield" reads adjacent to PowerShell, and [ADR 0003](0003-operator-tooling-in-dotnet.md) has
just deleted 2,668 lines of it. That is a joke the project has earned rather than a problem, but if a
reader ever takes the name to mean "a shield written in PowerShell", the README has failed at exit
condition 2 and that is where to fix it.

### This does not license scope creep

The name pointing at Windows does not mean every Windows problem belongs here.
[ADR 0002](0002-host-level-brute-force-defence.md) already decided that firewall-level blocking lives
in a sibling project and not in this one, and that decision stands. This ADR widens what the rules
may be about; it does not widen what the gateway does.

### Nothing about the code changes today

No rule, no threshold, no traffic path, no default and no namespace. A name change that quietly
altered behaviour would be the worst possible way to run one.

## What this ADR does not decide

- **What the second rule package covers.** The obvious candidate is the .NET-on-IIS surface that
  sixty-four of those sixty-six sites present, and there is measured evidence available for it, but
  choosing its rules is its own decision made against real logs rather than a threat model. This
  project has learned that difference expensively.
- **Whether the repository is ever renamed.** Option A stays available if the letters ever become
  more confusing than they are worth.

## Revisiting this decision

Revisit if exit condition 1 is still unmet when the project reaches its first release. Shipping a
1.0 called *Windows Power Shield* that only knows WordPress would turn a statement of direction into
a claim, and this ADR exists precisely to keep that from happening quietly.
