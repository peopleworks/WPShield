# ADR 0009 — Deciding what to block

- **Status:** Accepted on 2026-11-25, with the as-built amendment below
- **Deciders:** Pedro Hernández (maintainer)
- **Affects:** `WPShield.Evidence`, the evidence collector, the settings catalog, `wpshield`, the
  desktop's Attacks view and a future Protection panel, the MCP `decisions` tool

## Context

ADR 0006 settled *that* WPShield blocks host-wide and *how* the kernel drops traffic. ADR 0007 gave
WPShield a store with a `decisions` table nobody fills yet. What neither decides is **which address
deserves a block, for how long, and which addresses never do**. That is the part a user sees first:
RdpGuard's main window is a count of blocked addresses, and a Protection panel for WPShield would be
the same. It is also the part most likely to hurt the operator: the incident host's legitimate
administrators connect from dynamic addresses behind mobile carriers, and a rule that blocks one of
those locks out the person who would fix it.

The evidence available is failed Windows logons (Security 4625 and RdpCoreTS 140), paired so one
attempt counts once. Its source address was confirmed by a TCP handshake, so it is evidence a sender
cannot forge (ADR 0006, section 5). The incident showed four patterns: single addresses with
thousands of attempts, one /24 network sending from two dozen addresses, names that do not exist
tried in bulk, and a botnet that sent one request per address.

## Decision

**A decision engine turns live failed logons into decisions with a rule, a reason and an expiry. It
starts in Monitor: every decision is recorded as "would block" and nothing is enforced.** Block mode
becomes selectable only when the ADR 0006 enforcer exists and its validation has passed.

### 1. Live evidence only

The engine sees records that arrive after the process started, after pairing. It is never fed
history read at start, and it never rebuilds state from the `decisions` table (ADR 0007, section 5).
A restart forgets everything, which costs at most one more window of attempts before a decision is
made again; that is the price of a block that can never outlive the process that made it.

### 2. Rules

Stable, untranslated IDs. Each rule's thresholds are settings (section 6).

| Rule | Fires when | Decision | Default |
| --- | --- | --- | --- |
| `HOST-AUTH-001` | One address fails N times within W minutes | would block the address for D | 10 in 10 min, 60 min |
| `HOST-AUTH-002` | One address tries M account names that **do not exist** within W | would block the address for D | 4 in 10 min, 6 h |
| `HOST-AUTH-003` | K different addresses of one /24 (IPv4) or /64 (IPv6) fail within W | would block the network for D | 8 in 10 min, 60 min |
| `HOST-AUTH-004` | One **existing** account fails from A different addresses within W | report only, no block | 10 in 10 min |

`HOST-AUTH-002` is faster than `001` on purpose: a colleague who mistypes a password names a real
account; guessing names is what attackers do. `HOST-AUTH-004` reports instead of blocking because
the attack it detects is spread across addresses that 001 and 003 handle as they accumulate, and
blocking every address that ever touched one account would block shared networks wholesale.

RdpGuard's defaults are 3 failures in 24 hours and a 24-hour block. WPShield starts less aggressive
on wrong passwords and more aggressive on guessed names, and the first week on a real host in Monitor
is what tunes it.

### 3. Repeat offenders

An address that triggers again within 7 days of a previous decision gets twice the previous
duration, up to 7 days. The memory of previous decisions is in-process (section 1).

### 4. Addresses the engine never decides against

Checked when a decision is made and again when it would be enforced:

- the **allow-list** (`defense.allow`: canonical addresses and networks, none wider than /16 or /48);
- every address **bound on the host itself**, loopback, link-local and unspecified addresses - sites
  on a shared host call the host's own public address;
- **private ranges** (RFC 1918, ULA, CGNAT 100.64/10) unless `defense.include_private` is true;
- an address that **holds a Remote Desktop session** at that moment (the lockout guard of ADR 0006).
  If the connection table cannot be read, the decision is refused, not made: "nobody could look" is
  not "nobody is connected".

A decision the list stopped is recorded as `protected`, with the reason, so the operator can see what
would have happened to an address they trust.

### 5. Bounded

Per-address, per-network and per-account state each hold at most 100,000 entries and evict the
least recently seen. At most 10,000 decisions are active; past that, new ones are refused and the
refusal is recorded. Expiry is recorded too (`expire`), so the audit trail says when a block ended.

### 6. Settings

New catalog entries, validated and audited like every setting (ADR 0007's amendment):
`defense.mode` (only `monitor` is accepted until the enforcer exists; `NextStart`),
`defense.allow`, `defense.include_private`, and per rule its count, window and duration. Changing a
threshold applies at the next evaluation (`NextUse`) and says so.

### 7. Visible

Every decision goes to the store's `decisions` table with its rule, target, reason (the counts that
triggered it), the evidence channel that asked, mode and expiry. The CLI gains a view of active and
recent decisions, the desktop's Attacks view shows "would block" per address, the MCP `decisions` tool
already reads the table, and the future Protection panel counts them.

## Consequences

- **Thresholds will be wrong at first.** Monitor exists so that is measured, not suffered.
- **Shared addresses** (carrier NAT, an office behind one address) are the main false-positive risk.
  The allow-list, the private-range default, the guessing rule's focus on nonexistent names and the
  lockout guard are the four answers; the `protected` records show where they fired.
- **The one-request-per-address botnet is not stopped** by any per-address rule. The benchmark must
  show it as a known gap.

## Alternatives considered

- **RdpGuard's defaults.** Too aggressive for administrators behind carrier NAT, and they treat a
  mistyped password the same as a guessed name.
- **Reputation feeds or shared block lists.** A different evidence grade (somebody else's
  observation); a later decision.
- **Persisting decisions and restoring them at start.** Rejected by ADR 0006 and ADR 0007: it turns
  every past mistake into a permanent one.

## Revisiting this decision

- After one week of Monitor on the incident host: compare `would block` and `protected` records with
  what the operator expected, and adjust defaults in a dated amendment.
- When the enforcer of ADR 0006 passes its validation: allow `defense.mode = block`, in its own change.

## Amendment - as built (2026-11-25)

The engine shipped in Monitor with these departures from the text above. Each one closes a gap the
text left open; none widens what the engine may decide against.

- **A repeat is measured from the end of the previous decision**, not its start. Measured from the
  start, an address released after a 7-day decision and re-offending at once would fall back to 60
  minutes.
- **While a decision is in force, the target's failures are ignored**, exactly as an enforced block
  would have dropped them. One record per decision, not one per attempt.
- **A protected target is not reconsidered for the rule's duration, and a refused one for one window.**
  A fact that stays unreadable produces one `refused` record per window.
- **An unreadable list of the host's own addresses also refuses a decision**, like an unreadable
  Remote Desktop table.
- **`HOST-AUTH-004` names no account.** Its target is the address that completed the pattern. The MCP
  `decisions` tool returns targets and reasons whatever `mcp.detailed_records` says, so an account
  name in a reason would leave the host through a door that is otherwise closed.
- **A second bound:** 1,000,000 items inside each map, besides 100,000 entries, because an entry count
  alone does not bound memory. The count settings top out at 100, 50, 64 and 100.
- **A clean stop ends every decision on the record** (`expire`), because that is when an enforced
  block would end. "In force" means made since the engine's start in this process, unexpired, and
  only while the collector is recording.
- **Known edge:** when the catch-up read holds a 4625 and its paired 140 arrives live, the engine sees
  that single attempt.

The settings, the action vocabulary and `wpshield decisions` are documented in
[the network sensor design](../network-sensor-design.md).
