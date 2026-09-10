# ADR 0004 — What WPShield stands for, and what it does not cover yet

- **Status:** Accepted
- **Deciders:** WPShield maintainers
- **Affects:** the name, the README, the site, and where a rule that is not about WordPress goes
- **Corrected:** 2026-09-09 — see below. The decision stands; one of its factual premises did not.

## Correction — 2026-09-09

**The Context section below overstates how much of the rule set is about WordPress, and this ADR was
accepted with that error in it.** It is corrected here rather than quietly, because the error is the
same class of defect the ADR was written about.

### How it happened

The inventory behind the original claim was one command:

```
grep -rhoE '"(WP|FILE|MULTIPART)-[A-Z]+-[0-9]+"'
```

It searched for the three prefixes the author already expected and found exactly those three.
**The measurement encoded its own conclusion.** That is the same shape as the preflight that
reported checking a rule family it could not match — which this ADR cites, four sections down, as
part of the evidence for its own decision.

### What is actually shipped, read rule by rule

| | Rules | Would they report anything on a site that is not WordPress? |
| --- | --- | --- |
| WordPress-coupled | `WP-PATH-001` | **No.** It matches the directory pairs `wp-content/uploads`, `wp-content/upgrade` and `wp-content/updraft` by name. |
| WordPress-aware | `WP-UPLOAD-001`, `WP-UPLOAD-002`, `IIS-UPLOAD-001`, `IIS-CONFIG-001`, `FILE-NAME-001` | **Yes.** They decide on the NTFS view of the name. The `sanitize_file_name()` view is a *second* view that only ever adds findings, and it lives in `WPShield.Abstractions`, not in the WordPress package. |
| Nothing about WordPress in them at all | `WP-PATH-002`, `IIS-PATH-001`, `PHP-CONTENT-001`, `PHP-CONTENT-002`, `FILE-TYPE-001` | **Yes.** `PHP-CONTENT-001` is `<?php` or `<?=` in the sample and nothing else. |

`WP-PATH-002` is the sharpest case. Its directory list is `dist`, `build`, `_next`, `out`,
`node_modules`, `bower_components`, `static`, `fonts`, `webfonts`, `img` and `images` — not one
WordPress directory, and `_next` is Next.js. It carries a `WP-` prefix that exit condition 3 below
forbids, and it was already shipping on the day that condition was written.

### What survives the correction

The gap is real and the decision stands, but it is a different gap than the one recorded. It is not
that the rules only know WordPress. It is three things:

- **Packaging.** Eleven rules in one assembly named `WPShield.Rules.WordPress`, five of which
  contain no WordPress at all. The Linux CI leg already builds and tests that package with no
  Windows dependency, which is evidence of the same thing from the other direction.
- **Coverage.** Nothing in `src/` outside the CLI mentions `.env`, `.git`, `.bak` or `.sql`. The
  scan that reaches all sixty-six sites still meets no rule. **That claim was true and stays true**,
  and it is the part that mattered.
- **Labelling.** One shipped identifier already lies about what it is.

The exit conditions have been restated against those three. The Context section keeps its original
wording with the error marked, because an ADR that edits its mistakes away is not a record.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="../../assets/estate-dark.svg">
  <img alt="Sixty-six sites on one Windows Server: two are WordPress, sixty-four are .NET applications. A scan sends the same seven requests to every one of them. Four — GET /.env, GET /.git/config, GET /db-backup.sql and GET /admin — meet no rule at all. Three are answered: GET /dist/shell.php by WP-PATH-002, an upload of invoice.php.jpg by WP-UPLOAD-001 and 002, and an upload of web.config by IIS-CONFIG-001. Eleven rules read uploads and request paths, ten of them fire on a site that has never run WordPress, and none of them reads a dotfile, a stray backup or an exposed admin path. The gap is coverage and packaging, not the rules being WordPress-only." src="../../assets/estate-light.svg">
</picture>

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

Of that list, ~~**only the rule engine is about WordPress.**~~ The CLI, the preflight, the installer,
the host triage, the rate limiter and the logging are about Windows and IIS.

> **The struck sentence is wrong.** Of the eleven shipped rules, one is WordPress-coupled, five are
> WordPress-aware, and five contain no WordPress at all. See the correction at the top of this file.
> The rest of the paragraph, and the measurement below, are unaffected.

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

*(After the correction above, this option is weaker still: it would not be honest about the rules
either. Ten of the eleven fire on a site that has never run WordPress.)*

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

*Restated on 2026-09-09. The originals were written against the false premise corrected at the top
of this file; conditions 1 and 2 asked for something the code had partly done already, and condition
3 asked for something a shipped rule was already violating.*

1. **The rules that are not about WordPress are packaged where they belong, and the .NET surface is
   covered.** Two halves, and the first is not "write a second package" — it is *split the one that
   exists*. `WPShield.Rules.Windows` takes the five rules that contain no WordPress; the WordPress
   package keeps `WP-PATH-001` and the five that consult the `sanitize_file_name()` view. The second
   half is the part that is genuinely missing: **no rule anywhere reads `.env`, `.git`, a stray
   `.bak` or `.sql`, or an exposed admin path**, which is the whole of what a scan sends at the
   sixty-four sites. The architecture already permits both: `WPShield.Abstractions` and
   `WPShield.Core` are free of ASP.NET Core, YARP, IIS and Windows dependencies, and a Linux CI leg
   builds and tests those two plus the rules package, which is what keeps that claim falsifiable.

2. **The README and the site say what is covered today.** A reader must be able to learn, without
   scrolling, which surface the rules reach — WordPress uploads, and the Windows, IIS, PHP and
   filename surface underneath them — and which one they do not reach at all: the .NET application
   surface those sixty-four sites present.

3. **The rule identifier scheme has room for it, and no identifier lies.** `WP-` means WordPress and
   must keep meaning that; a family that is not about WordPress needs its own prefix rather than
   being filed under one that lies about it. **`WP-PATH-002` breaks this today** — its directory list
   is build output and package trees, and its prefix says WordPress. Renaming a published identifier
   is a breaking change to every stored finding and every operator's saved query, so it is its own
   decision rather than a side effect of this one; it is named here so it cannot be forgotten.

## Consequences

### `WPShield.Rules.WordPress` keeps its name, for a worse reason than first written

~~It is a WordPress rule package and the name is exactly right.~~ **Corrected 2026-09-09.** The name
is not right: five of the eleven rules inside it contain no WordPress. It keeps the name anyway,
because renaming an assembly and splitting one are different jobs and only the second one is worth
doing — exit condition 1 asks for the split, and after it the remaining package will deserve the
name it already has.

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

- **Which rules cover the .NET surface.** Exit condition 1 says that surface must be covered. It does
  not say by what. The candidates are obvious enough to be dangerous — `.env`, `.git`, backups, admin
  paths — and picking them from a threat model is how a rule set ends up scoring things nobody sends.
  They get chosen against this server's real logs, and that is its own decision.
- **What `WP-PATH-002` is renamed to, and when.** A published rule identifier appears in stored
  findings and in whatever an operator has built on top of them. Changing one is a breaking change
  and needs its own ADR, a deprecation path, or both.
- **Whether the repository is ever renamed.** Option A stays available if the letters ever become
  more confusing than they are worth.

## Revisiting this decision

Revisit if exit condition 1 is still unmet when the project reaches its first release. Shipping a
1.0 called *Windows Power Shield* that only knows WordPress would turn a statement of direction into
a claim, and this ADR exists precisely to keep that from happening quietly.
