# ADR 0006 — Network-layer blocking inside WPShield

- **Status:** Proposed
- **Deciders:** WPShield maintainers
- **Supersedes:** the network half of [ADR 0002](0002-host-level-brute-force-defence.md)'s decision
  (RDP, FTP, SMTP, SQL and SMB "belong to the sibling project"). ADR 0002's HTTP half stands.
- **Affects:** `AGENTS.md`, `ROADMAP.md` (M2.7, M2.8 and the opening statement),
  `.github/instructions/docs.instructions.md`, and `wpshield network-filter`

## Context

ADR 0002 kept address blocking out of WPShield because the only way it knew to block an address was
to write Windows Firewall rules, and a firewall rule written by a tool is exactly what a shared host
cannot afford: it persists when the tool dies, it survives a reboot, and when it is wrong it locks the
administrator out of the session they would use to fix it. ADR 0002 also said how to undo that
decision: deliberately, in its own change, never as a side effect of adding a feature.

That side effect happened. On 2026-10-20 `WPShield.NetworkFilter` landed on `main` with M2.7 and M2.8
ticked in the roadmap and ADR 0002 untouched. Read against the WinDivert 2.2 API it could not block
anything, and it would have been dangerous if it had:

- It opened its handle with `WINDIVERT_FLAG_SNIFF`, which **copies** packets. "Dropping" a copy does
  nothing; the original was already on its way.
- Its `WinDivertRecv` and `WinDivertSend` declarations did not match the API (the real ones take a
  `UINT*` length and an 80-byte `WINDIVERT_ADDRESS*`), and it reinjected every packet with a length of
  65,536 bytes.
- Its default filter, `tcp.Inbound`, is not a WinDivert field, so `WinDivertOpen` fails with error 87
  before anything else happens. That accident is the only reason it was harmless.
- Its rate rule counted **packets** and blocked above 120 a minute, which one WordPress page load
  exceeds. With no allow-list in the filter, it would have blocked the visitors of every site on the
  host, and the administrator's own RDP session with them.
- Its parser read port numbers little-endian.

Meanwhile the evidence for wanting the capability got stronger. Four weeks of Malwarebytes Web Access
Control on the production host recorded **6,150 blocked inbound connections from 344 addresses**,
**17% of them to non-HTTP services**: PostgreSQL, MySQL, SQL Server, SMB, WinRM, FTP, VNC and mail.
WPShield's gateway never sees that traffic. And the commercial alternative is not free of risk either:
the same host crashed repeatedly with `DPC_WATCHDOG_VIOLATION` traced to `mwac.sys`, a kernel
component inspecting every inbound connection. The operator wants a network-layer blocker he can read,
that cannot take the host down.

## Decision

**WPShield may drop inbound packets from addresses on its own block list**, under all of the
following. Each one is enforced in code and covered by tests; none is advice.

### 1. Benign traffic never passes through WPShield

Enforcement uses WinDivert handles opened with **`WINDIVERT_FLAG_DROP`**, whose filter matches only
the addresses on the block list. The driver drops those packets in the kernel. Nothing else matches,
so nothing else is diverted, and **there is no reinjection anywhere in the code**: no `WinDivertSend`
declaration exists to call.

Observation uses a separate handle opened with **`WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY`**
and the filter `inbound and !loopback and tcp.Syn and !tcp.Ack`: new inbound TCP connection attempts,
nothing else. It receives copies. A slow, stopped or crashed observer loses copies, never traffic.

This is the property the 2026-10-20 design lacked, and the reason it could not be made safe by fixing
its bugs: a divert-and-reinject filter puts every packet of every site through a user-mode process,
and a hung process is then a host outage.

### 2. Blocks live exactly as long as the process

No firewall rule, no registry value, no file. A block is a filter on a kernel handle owned by the
WPShield process. When the process exits, crashes, is stopped, or the machine reboots, the handle
closes and every block is gone.

That is ADR 0002's **dead-man's switch**, obtained from handle lifetime rather than from a scheduled
task that removes rules. It is stronger, because there is nothing left behind to remove, and it does
not install anything the triage tool would rightly flag as persistence.

**The residual risk, stated:** a process that *hangs* without exiting keeps its current blocks until
it is killed, and cannot expire dynamic entries while hung. Those blocks can only ever cover addresses
that are not on the allow-list (section 3).

### 3. The allow-list comes before any block

ADR 0002's first mechanism, applied twice:

- An allow-listed address can never enter the block set. A single address on the allow-list is
  refused; a range that contains an allow-listed address is refused.
- The filter builder excludes allow-listed addresses again when it writes the DROP filters, so a
  defect in one layer is not enough.

And the lockout guard: **Block mode refuses to start** when the allow-list is empty, and when any
established TCP connection to the host's RDP port comes from an address that is not on the
allow-list. The port is read from the registry (`RDP-Tcp\PortNumber`), never assumed to be 3389. An
operator who starts Block mode over RDP has to name the address they are connected from, and the tool
names it for them when they have not.

The start-time check is not enough on its own, because an administrator can reconnect from a new
address mid-run. So the guard runs again for every new dynamic block: an address that holds a
connection to the RDP port at that moment is refused, and when the connections cannot be read the
block is refused too, because "nobody could look" is not "nobody is there".

### 4. Monitor is the default

**Monitor never opens a DROP handle.** It is not a flag checked before each drop; the enforcer is not
constructed. Monitor logs who *would* have been blocked and why, which is how a week on a real host
turns a plausible threshold into a defensible one. Block is the explicit `--mode Block`.

### 5. Evidence grade decides who may add a block

A blocked address is blocked for **every site on the host**, which is why the source of a block
matters more here than in the gateway.

| Source | Spoofable? | May add a block in Block mode |
| --- | --- | --- |
| Operator-named address or range (`--block`) | No | Yes |
| Security log: repeated failed logons (`WP-SEC-001`, `WP-SEC-002`) | No: the logon failed after a completed TCP handshake | Yes, with a TTL |
| Connection attempts per minute (`WP-NET-002`) | **Yes**: a SYN's source address is whatever the sender wrote | Only with `--syn-rules-may-block` |
| Distinct ports per minute (`WP-NET-003`) | **Yes** | Only with `--syn-rules-may-block` |

`--syn-rules-may-block` is documented for what it is: it lets anyone who can send forged SYNs get any
non-allow-listed address blocked for the TTL, a search engine's crawler included.

### 6. Blocks expire and the set is bounded

Dynamic blocks expire after a TTL (default 60 minutes; a repeat finding extends it). Operator-named
blocks last for the life of the process. The set holds at most 1,000 entries by default; when it is
full, new dynamic blocks are refused and logged, and an operator entry is never evicted to make room.

### 7. WPShield never loads a kernel driver as a side effect

Every handle is opened with **`WINDIVERT_FLAG_NO_INSTALL`**. If the driver is not loaded, the command
says so and stops. Loading it is an operator action named on the command line (`--install-driver`),
because the WinDivert driver is a service other than WPShield and `AGENTS.md` keeps those manual
unless the operator names the change.

What WinDivert then does is read from its source (`dll/windivert.c`), not assumed: it registers a
demand-start kernel driver service named `WinDivert`, starts it, and **marks it for deletion at
once**. The registration does not survive `sc stop WinDivert` or a reboot, so nothing stays
installed on the host. The price is that `--install-driver` is needed again on the first run after
every reboot, and a future boot-time service will have to pass it knowingly.

WinDivert is **not bundled**. It is LGPLv3, signed by its author, and the operator downloads 2.2.2
from the upstream release. `WinDivert.dll` is loaded from the WPShield assembly directory only, never
from `PATH` or the working directory: the process runs elevated, and a DLL search that reaches a
writable directory is a privilege escalation.

### 8. Self-test before Block

Before the first DROP handle opens, every generated filter is compiled with
`WinDivertHelperCompileFilter` and evaluated with `WinDivertHelperEvalFilter` against synthetic
packets: an address on the block list must match; an allow-listed address and an unrelated one must
not; the first and last address of every range must match and the addresses just outside it must
not. **Block mode refuses to start if any check fails.** `--check` runs the same test without
elevation and without the driver, because both helpers are plain user-mode functions in
`WinDivert.dll`.

This is how ranges can ship although the WinDivert documentation does not spell out how address
comparison orders: the real library is asked, on the machine that will run it, before it is trusted.

### 9. Everything is bounded

A DROP filter holds at most 200 of the 256 objects WinDivert allows (`WINDIVERT_FILTER_MAXLEN`); a
larger block set is split across handles. The observer's per-source state is capped and evicts the
least recently seen source, because a flood of SYNs with random forged sources must not grow a
dictionary without limit. Findings are logged once per source and threshold, not once per packet.

## What changes in the invariants

- `AGENTS.md`'s rule that infrastructure the operator did not name is never changed **stands**. The
  network filter writes no Windows Firewall rule and leaves nothing behind; the driver installation is
  named.
- `ROADMAP.md`'s opening statement and `docs.instructions.md` said no milestone modifies firewall
  rules automatically. They now say what is true: WPShield never writes Windows Firewall rules, and
  its network filter drops packets only from its own block list, only in Block mode, only while it
  runs. Redefining "firewall rule" quietly to make the old sentence still sound true is the evasion
  ADR 0002 warned about, so the sentence changes instead.
- ADR 0002's HTTP split stands: credential attacks against `wp-login.php` and XML-RPC belong to the
  gateway's M3, inline, where the real client address is already resolved.

## Consequences

- **WinDivert's kernel code is on the packet path for the traffic its filters match.** It is a
  third-party, signed driver; WPShield ships no kernel code. Filter evaluation per packet is bounded
  by 256 objects per handle. DROP handles exist only while there are blocks; the observer filter is
  four tests.
- **Network blocks are host-wide.** The gateway's per-site isolation does not extend to them, which
  is why section 5 exists. A block event names `WP-NET-001`, the block list, and records the finding
  that asked for it in `requested_by`, so the log says both what was done and why.
- **Not yet validated against the driver.** Everything above is built against the documented 2.2.2
  API and tested through a fake driver. The first run against a real driver is the operator's, on a
  development machine first, never on the production host first.

## Alternatives considered

- **Windows Firewall rules through the NetSecurity API.** They persist across crashes and reboots,
  which is the lockout failure mode ADR 0002 described, and they are the thing `AGENTS.md` keeps
  manual.
- **The sibling project ADR 0002 proposed.** Still a valid shape. Its reason to exist was that
  blocking meant persistent firewall changes; handle-scoped drops remove that reason, and the
  operator wants one tool.
- **Divert and reinject (the 2026-10-20 design).** Rejected in section 1.

## Revisiting this decision

- If the self-test or the first real run shows WinDivert does not order address ranges as expected,
  ranges are removed and only exact addresses ship.
- If this ADR is rejected, `network-filter` is reduced to Monitor (the observer) and the DROP path is
  deleted, not left behind a flag.
