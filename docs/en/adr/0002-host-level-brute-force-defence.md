# ADR 0002 — Where brute-force defence belongs

- **Status:** Proposed
- **Deciders:** WPShield maintainers
- **Affects:** M3 (rate limiting and automated behaviour), and a possible sibling project

## Context

Two WordPress sites on one Windows Server host recorded **40,779 requests to `wp-login.php` in
thirty days**, from more than sixty distinct addresses, at roughly 1,360 attempts per day. The same
host exposes RDP to the internet. Neither number is unusual for a Windows server with a public
address; both are unaddressed today.

WPShield sees HTTP and nothing else. Credential attacks against RDP, FTP, SMTP and SQL are invisible
to it, and they are attacks against the same host, often from the same addresses.

The obvious model is [RDPGuard](https://rdpguard.com/) and, before it, `fail2ban`: watch logs for
failed authentication, and add the source address to the firewall. The question this ADR answers is
not *whether* that capability is worth having — the numbers above settle that — but **where it
belongs**, because the answer collides with an invariant this project already committed to.

## The collision

`AGENTS.md` states, without qualification:

> Never modify IIS, certificates, DNS, **firewall rules**, or Windows services automatically.

A brute-force blocker's entire purpose is to modify firewall rules automatically. The two safety
contracts are not merely different, they are inverses. There is no wording that satisfies both
inside one product: either the invariant acquires an exception large enough to swallow it, or the
capability is crippled into a tool that recommends blocks and never applies them.

That invariant is not decoration. WPShield is deployed onto shared hosts — the one measured above
runs sixty-five IIS sites belonging to unrelated applications — and "this security tool changed a
machine-wide setting on its own" is the failure mode the rule exists to prevent.

## Options

### Option A — Build it into WPShield

Add rate limiting that blocks at the firewall, under M3.

**For.** One process, one configuration, one log. WPShield already resolves the true client address
behind the proxy, so the hardest part of attribution is solved.

**Against.** It requires deleting or gutting the firewall invariant, which is load-bearing for
deployment onto shared hosts. It also does not reach RDP, FTP, SMTP or SQL — WPShield is an HTTP
proxy and those protocols never pass through it — so it would solve half the problem while paying
the whole architectural price.

### Option B — A separate project, sharing the evidence format

A host-level daemon that watches Windows authentication events and manages firewall rules, with its
own safety contract. WPShield keeps its invariant untouched.

**For.** Each product's contract matches its job. The daemon covers every protocol on the host, not
just HTTP. WPShield stays deployable on a shared server without a firewall-modifying component
attached to it.

**Against.** Two things to install, two things to operate. Some duplicated machinery.

### Option C — Do nothing; rely on RDPGuard

It exists, it works, and it costs about forty dollars.

**For.** No engineering.

**Against.** It is closed source. A component that rewrites the firewall of a production server on
its own evidence is precisely the category where the source matters most, and where an operator
should be able to read what triggers a block. It also produces evidence in its own format, which is
one more thing to correlate by hand during an incident.

## Decision

**Option B, with the HTTP half staying inside WPShield.**

The split is by *signal source*, not by protocol convenience:

| Attack | Handled by | Why |
| --- | --- | --- |
| HTTP credential attacks (`wp-login.php`, XML-RPC, REST) | **WPShield, M3** | It is already inline and already resolves the real client address. |
| RDP, FTP, SMTP, SQL, SMB | **The sibling project** | Those never traverse an HTTP proxy. |

WPShield's M3 rate limiting **refuses requests**; it does not touch the firewall. The invariant
survives intact. When the sibling project exists, WPShield can emit an observation that it chooses
to act on — but the decision to change a machine-wide setting stays in the component whose stated
job that is.

### Why inline beats log-watching for the HTTP half

RDPGuard and its relatives tail IIS log files. That is late and lossy: IIS buffers log writes, so a
reaction arrives minutes after the traffic, and the tool sees only the fields the site was
configured to log. WPShield sees every request as it happens, with the client address already
resolved through `Gateway:TrustedProxies`.

Reimplementing HTTP brute-force detection by reading IIS logs, in a project that already has an
inline view of the same requests, would be strictly worse at more cost.

### For the sibling project: subscribe to events, do not read files

Windows already pushes authentication failures as events — `4625` in the Security log covers RDP,
SMB and local logon; the service-specific logs cover the rest. An event subscription delivers them
at the moment they occur. Tailing `.evtx` or text logs is polling, and it inherits every latency and
parsing fragility that makes the log-watching model weak.

## Consequences

### Lockout is the design problem, not log parsing

This is the part to get right before anything else is written.

A tool that blocks addresses will eventually block the wrong one, and on a remote server the
consequence is that the administrator cannot get back in — the RDP session they would use to fix it
is the thing that was blocked. There is no recovery path except the hosting provider's console, and
that is the good case.

Three mechanisms, all required, all designed before the first block is implemented:

1. **A persistent allow-list, applied before any rule is written**, seeded with the address of the
   session performing the installation. An operator who installs over RDP has already told the tool
   which address must never be blocked.
2. **A dead-man's switch.** A scheduled task, independent of the daemon, that removes every block
   rule if the daemon has not checked in for a configured interval. A bug that locks everyone out
   then heals itself without a console. *(This project's own triage tool would flag that scheduled
   task as persistence. It would be right to: the mechanism is genuinely indistinguishable from the
   thing it resembles, and the answer is that the operator installed it knowingly.)*
3. **Monitor mode as the default**, exactly as WPShield does it. The tool reports who it *would*
   have blocked and blocks nobody until an operator changes that. A week of Monitor on a real host
   is what turns a plausible threshold into a defensible one.

### Do not create one firewall rule per address

Windows Firewall degrades measurably with thousands of rules, and rule evaluation is on the packet
path. The design is a small fixed set of rules — single digits — each holding a large address list,
updated in place. This also makes removal cheap, which matters because most blocks should expire.

### Attacker-controlled text must not reach a rule name

A failed logon record contains a username the attacker chose. Anything derived from it that reaches
a firewall rule name, a log line or a dashboard is attacker-controlled text in a privileged context.
The same rule WPShield already applies to inspection evidence applies here: report normalized
values, never raw ones.

### Shared evidence format

The sibling project emits findings in the same JSON Lines envelope the gateway log, the triage tool
and the preflight already use: `timestamp`, `level`, `category`, `message`, `state`. One parser for
the whole toolchain, and an incident timeline that sorts as text without reformatting anything.

### Naming

WPShield is named for WordPress, and the rules that matter most on this platform are not about
WordPress at all — `IIS-PATH-001`, the IIS executable extension list, `web.config` as remote code
execution, NTFS alternate data streams. The sibling project is where the host-level ambition
belongs, and naming it for the platform rather than the application keeps WPShield honest about its
own scope.

## What this ADR does not decide

- Whether the sibling project gets built at all, or when. It records what the decision would be.
- Its language or runtime.
- Whether WPShield's M3 blocks by refusing requests only, or also emits an observation for the
  sibling to act on. The first is required; the second is a later integration.

## Revisiting this decision

Fold the capability into WPShield only if the firewall invariant is removed deliberately, in its own
change, with the shared-host deployment story rewritten to match. That is a large decision and it
should never happen as a side effect of adding a feature.
