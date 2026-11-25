# ADR 0006 — Network-layer blocking inside WPShield

- **Status:** Accepted on 2026-11-24. Block mode uses Windows Filtering Platform (WFP).
  This implementation stays in research preview pending the disposable-VM validation below.

- **Deciders:** Pedro Hernández (maintainer)
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

**WPShield may block inbound traffic from addresses on its own block list**, under all of the
following. Each one is enforced in code and covered by tests; none is advice.

### 1. Benign traffic never passes through WPShield

The kernel authorizes inbound traffic using one `FWP_ACTION_BLOCK` filter per accepted
address or prefix, at `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4` or `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6`.
Each filter belongs to the WPShield sublayer and uses `FWPM_CONDITION_IP_REMOTE_ADDRESS`.
The IPv4 value contains an address and mask in host order. The IPv6 value is a
`FWP_V6_ADDR_AND_MASK`. WPShield passes policy to WFP. Traffic stays in the Windows network stack.

### 2. Blocks live exactly as long as the process

No firewall rule, no registry value, no file. A block is a WFP object owned by the dynamic session. When the process exits, crashes, is stopped, or the machine reboots, the session
ends and every block is gone.

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
- The filter builder excludes allow-listed addresses again when it builds the WFP filters, so a
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

Monitor opens no WFP session and reports proposed blocks. Block is explicit with `--mode Block`.

### 5. Evidence grade decides who may add a block

Blocks apply across the host. Operator-named addresses and ranges may be blocked for the session.
An automated block request requires a trusted log source and a remote address confirmed by a
completed TCP handshake. Dynamic blocks carry a TTL.

The Security log adapter accepts failed logons (4625, types 3 and 10) with a Block finding from
`WP-SEC-001` or `WP-SEC-002`. The standalone command enforces operator entries. RdpCoreTS 140,
SQL Server 18456, FTP 530 and gateway-observed WordPress login and XML-RPC are eligible sources
only where the TCP address is established. A separate ADR is required to connect the ADR 0009
decision engine. The SYN observer and its two rules have been removed.

### 6. Blocks expire and the set is bounded

Dynamic blocks expire after a TTL (default 60 minutes; a repeat finding extends it). Operator-named
blocks last for the life of the process. The set holds at most 1,000 entries by default; when it is
full, new dynamic blocks are refused and logged, and an operator entry is never evicted to make room.

### 7. Enforcement uses the Windows network stack

`FwpmEngineOpen0` opens a session with `FWPM_SESSION_FLAG_DYNAMIC`. `FwpmSubLayerAdd0` adds the
WPShield sublayer (`93a54814-5f1d-44f3-b2ba-f4df18dfe12f`) and `FwpmFilterAdd0` adds the filters.
Both objects are dynamic. Filter flags omit persistence and boot-time enforcement. Every import of
`fwpuclnt.dll` uses `DefaultDllImportSearchPaths(System32)`. The Base Filtering Engine ships with
Windows and there is no separate driver installation.
[Dynamic session lifetime](https://learn.microsoft.com/windows/win32/api/fwpmtypes/ns-fwpmtypes-fwpm_session0)

### 8. Self-test before Block

Before enforcing an operator or log-derived block, the process opens a dynamic session and adds a
filter for an RFC 5737 address outside the allow-list. The same path checks that the block set and
the filter builder both exclude an allow-listed entry. It reads the probe back by enumeration,
validates its layer, sublayer, action and address, then deletes it. If any step fails, Block refuses
to start and closes the session. `wpshield network-filter --check` runs this native test and reports
the result for the current Windows identity.

### 9. Everything is bounded

The block set defaults to 1,000 and is capped at 10,000. Up to 1,000 allow-list entries are accepted.
WFP uses one filter per selected prefix. Enumeration reads up to 16,384 filters in batches of 64 and
refuses to pass if it cannot find the probe within that budget. Updates are committed in transactions.
A failed update closes the session so a failed deletion cannot leave expired filters in force.

## Consequences

- The Windows Firewall console and `Get-NetFirewallRule` do not show the dynamic filters.
  Use `netsh wfp show filters`.
- WPShield does not write Windows Firewall rules or change IIS, DNS, certificates or services.
  ADR 0002's HTTP split stands. WordPress credential abuse remains part of the gateway's M3 work.
- `WP-NET-001` identifies enforcement events, and `requested_by` identifies the source.
- Persistent Windows Firewall rules and a packet divert-and-reinject process were rejected in favor
  of dynamic kernel filters.

## Amendment (2026-11-24) and VM acceptance

The amendment adopted WFP in place of WinDivert. WFP keeps the process-lifetime guarantee using
Windows' Base Filtering Engine and removes the additional driver and packet observer. The
[VM validation guide](../network-filter-vm-validation.md) carries the six acceptance checks. Keep
the PR in draft until they pass on a disposable Windows Server VM.

1. Exercise ordinary firewall allow arbitration and record the outcome of **Override block rules**.
2. Kill the process and verify every WPShield filter disappears within one second.
3. Verify an established allow-listed RDP session survives a block on another address.
4. Measure addition time, BFE memory and connection latency with 10,000 filters.
5. Verify third-party endpoint protection remains stable and its own blocks remain effective.
6. Test both an elevated Administrator and `NT SERVICE\WPShield`. If the service token lacks
   access, the administrator-started enforcer is the current path. Any change to WFP access
   descriptors is a manual server setting and requires a separate decision.

## Revisiting this decision

If a firewall policy can override a WPShield block, record the limitation and make Block report it.
If tested CIDRs do not match their promised boundaries, restrict enforcement to exact addresses.
