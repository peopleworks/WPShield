# ADR 0005 — Putting WPShield in the path, and whether a tool may do it

- **Status:** Accepted
- **Deciders:** WPShield maintainers
- **Affects:** `AGENTS.md`, the deployment, and a possible `enable` / `disable` verb

## Context

Every other step of a deployment is now one command. The last one is not: putting WPShield into the
traffic path takes **three changes in IIS and the site's own application**, in an order where getting
it wrong takes a live site down.

They were done by hand, on a live sixty-six-site server, and it went wrong exactly as the ordering
implies:

| Step | What it is | What happens if it is missing or out of order |
| --- | --- | --- |
| **a** | `HTTP_X_FORWARDED_PROTO` added to the site's allowed server variables | A rule that sets a variable not on this list returns **HTTP 500 for the whole site** |
| **b** | The WPShield rewrite rule, ordered above any catch-all, carrying its `serverVariables` block | Below a catch-all, either the rule never runs or it runs against the already-rewritten URL. **Both look like a working site.** |
| **c** | `wp-config.php` translating the header into `$_SERVER['HTTPS']` | WordPress sees plain HTTP behind an HTTPS site and every page redirects to HTTPS forever: **`ERR_TOO_MANY_REDIRECTS`** |

The operator did **b** and not **a** or **c**, because the preflight printed **b** and warned about
the redirect loop without naming what prevents it. That is a tooling defect and it is fixed: the
preflight now prints all three. But fixing the instructions does not fix everything the instructions
ask a person to do at eleven at night: type XML into a production `web.config`, get the rule order
right by dragging it in a list, and remember which of five changes is the one that is server-wide.

### The invariant this collides with

`AGENTS.md` says:

> Never modify IIS, certificates, DNS, firewall rules, or Windows services automatically.

**As written, that rule is already not true.** `wpshield install` creates a Windows service,
configures its identity, sets its recovery actions and rewrites two directories' ACLs. It has always
done that, deliberately, and the script harness enforced a narrower rule alongside it: a
service-mutating call must name the service by a constant, never by a literal, so the installer can
never be pointed at one of the sixty-five other applications on the host.

So the invariant's real content was never the list. It was: **never change infrastructure the
operator did not name, and never as a side effect of asking a different question.** The literal text
is a proxy for that, and the proxy has drifted from the thing it stands for.

Pretending otherwise is worse than amending it on purpose. This ADR amends it on purpose.

## The five changes, by blast radius

"Automate IIS or do not" is the wrong question. These are five different changes with five different
consequences.

| | Change | Scope | Reversible by |
| --- | --- | --- | --- |
| 1 | Private loopback binding on the site | One site | Removing the binding |
| 2 | Allowed server variable | One site | Removing the entry |
| 3 | The rewrite rule | One site | **Disabling the rule** |
| 4 | `wp-config.php` translation | One application's **source code** | Restoring the file |
| 5 | ARR `preserveHostHeader` | **The whole server** — every ARR proxy on the machine | Turning it back, and re-testing everything else |

Number 5 is the one `PRE-017` exists to warn about. Number 4 is not IIS at all; it is a customer's
application source, which can have any structure and may be under source control the tool cannot see.

## Options

### Option A — Nothing changes; keep improving the printed instructions

Defensible now in a way it was not last week, because the printed instructions are finally complete.
It leaves the operator transcribing XML into a production file, ordering a rule by hand, and holding
the difference between a per-site change and a server-wide one in their head.

It also leaves the rollback manual. When a site does break, somebody has to notice, decide which of
three changes did it, and undo the right one under pressure.

### Option B — A verb that applies all five

Fastest, and wrong. It would edit a customer's PHP source, flip a server-wide switch affecting
sixty-five unrelated applications, and do it all behind one command.

### Option C — A verb that applies only the per-site, reversible IIS changes, refuses the rest, and verifies

`wpshield enable --site <name>` applies **2 and 3**. It refuses 5 outright and prints it. It refuses
to run at all until 4 is already in place, and prints exactly what to add. 1 is applied only when the
site has no loopback binding yet.

And — this is the part that makes it safer than a person doing it — **it requests the site
immediately after applying, and reverts automatically if the site stopped working.**

## Decision

**Option C.**

### The argument that decides it

A person types a rewrite rule into `web.config`, saves it, and the site is now either fine or a 500.
Finding out requires them to check, notice, diagnose which of three changes did it, and undo the
right one. That is a manual verification loop with a human in the slowest part of it.

A verb applies the same change, requests the site, reads the status code, and has reverted before the
operator has finished reading the output. **Automation here is not a convenience; it closes the
window between breaking a site and un-breaking it.** That window was hours on the deployment this ADR
is written from — the rule went live, produced `ERR_TOO_MANY_REDIRECTS`, and stayed live while the
cause was diagnosed.

That is the whole case. Not "typing is tedious" — *the rollback is too slow when a human owns it.*

### What the verb refuses, and why each refusal stays

- **`preserveHostHeader`.** Server-wide, no per-site override, and it changes the `Host` header every
  ARR proxy on the machine sends downstream. `PRE-017` names the other applications it would affect.
  A tool must not make that change on behalf of an operator who asked about one site.
- **`wp-config.php`.** It is the customer's application source, not infrastructure. The verb reads it
  to confirm the translation is present and **refuses to proceed without it** — which enforces the
  ordering across the boundary without the tool ever writing PHP. This also means the verb cannot
  create the redirect loop it exists to prevent.
- **More than one site per invocation.** `--site` is required and takes exactly one name. No `--all`.
  The reason the IIS steps were manual was that they need a person looking at the site; one site at a
  time is what preserves that, and it is the property the invariant was really protecting.
- **A gateway that is not listening.** Enabling the rule while nothing answers on the loopback port
  takes the site down instantly. The verb checks the health endpoint first.

### The safety properties, which are the deliverable

1. **`--dry-run` prints the exact plan**, per site, in order, including the rollback command — and
   does not require elevation.
2. **`web.config` is backed up** before it is touched, to a path the output names.
3. **Applied in order**, and a failure at any step reverts the steps already applied.
4. **Verified by a request** to the site through its public binding after applying. A 5xx, or a
   redirect chain that does not terminate, is a failure.
5. **Automatic revert on failed verification**, before the command returns.
6. **`wpshield disable --site <name>`** exists and is documented first, because it is the rollback and
   an operator looks for it when things are already going wrong. It sets `enabled="false"` on the
   rule rather than deleting it, so re-enabling is one command and the rule's ordering is preserved.

### The amendment to `AGENTS.md`

The line becomes, in substance:

> Never change infrastructure the operator did not name, and never as a side effect of asking a
> different question. A verb may change IIS only for a single site named on the command line, only
> for changes that are individually reversible, and only when it verifies the result and reverts on
> failure. Server-wide settings, certificates, DNS, firewall rules, and any service other than
> WPShield stay manual.

That says what the old line meant. It also says what the installer has been doing all along, which
the old line did not.

## Consequences

### The structural guard has to move, not disappear

`Test-WPShieldScripts.ps1` banned every IIS-writing cmdlet in every script. Those scripts are gone,
and the ban has to be re-expressed in the CLI's tests: **only the `enable` and `disable` verbs may
reach IIS-writing APIs, and only through one narrow seam.** The equivalent of "names no service by a
literal" is "names no site the operator did not pass on the command line" — asserted, not documented.

### The verification request is a new capability, and it deserves a bound

The verb makes an HTTP request to the site it just changed. That is the only outbound request
anything in this project makes. It goes to the hostname the operator named, follows a bounded number
of redirects, times out quickly, and logs the status code and nothing else — no body, no headers
beyond the status line, following the same rule as everything else that writes evidence here.

### This does not make the deployment one command

Even with `enable`, `preserveHostHeader` and `wp-config.php` remain manual, and the operator still
reads the Monitor log for days before moving a site to `Block`. The deployment goes from **three
manual changes and a manual rollback** to **one manual change, one prerequisite the tool checks, and
an automatic rollback.** That is the honest size of the improvement.

## What this ADR does not decide

- **Whether `enable` ever handles `preserveHostHeader`.** On a single-application server the trade is
  different, and a future ADR could revisit it with a refusal that only lifts when the host has one
  ARR proxy. Not now, and not on a host with sixty-six sites.
- **The verification request's exact success criteria.** "Not 5xx and not a redirect loop" is the
  shape; the specific rules belong with the implementation and with a real site to try them against.

## Revisiting this decision

Revisit if the automatic revert ever fails to restore a site. The entire case for this verb rests on
the revert being faster and more reliable than a person; if that turns out not to hold, Option A was
right and the printed instructions are as far as this should go.
