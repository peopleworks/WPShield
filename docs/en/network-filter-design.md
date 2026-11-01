# WPShield.NetworkFilter — Design (English)

`wpshield network-filter` watches new inbound TCP connections and, in **Block** mode, drops packets
from the addresses on its block list. **Normal traffic never passes through WPShield**: the observer
receives copies, and blocks are WinDivert filters the driver applies in the kernel. Stopping the
command lifts every block at once. The decision behind it is
[ADR 0006](adr/0006-network-layer-blocking.md); this page is how it works and how to run it.

> **Status: built against the documented WinDivert 2.2.2 API and tested through a fake driver. It
> has not yet run against a real driver.** Run it on a development machine first, using the test plan
> at the end of this page, never on a production host first.

## Why it exists

Four weeks of Malwarebytes Web Access Control on a production host recorded 6,150 blocked inbound
connections from 344 addresses, 17% of them to services the gateway never sees: PostgreSQL, MySQL,
SQL Server, SMB, WinRM, FTP, VNC and mail. The same host crashed repeatedly with
`DPC_WATCHDOG_VIOLATION` in `mwac.sys`, a kernel component inspecting every inbound connection. The
network filter is the open, readable alternative, built so that it cannot take the host down.

## How it is built

```text
inbound packet
  │
  ├─ DROP handles (priority 1000) ── filter: inbound and !loopback and (ip.SrcAddr == … or …)
  │     matches → dropped in the kernel. Nothing is received, nothing is reinjected.
  │
  ├─ observer handle (priority 0, SNIFF | RECV_ONLY) ── filter: inbound and !loopback and tcp.Syn and !tcp.Ack
  │     receives a COPY of each new connection attempt → WP-NET-002, WP-NET-003 → findings
  │
  └─ the original packet continues to IIS, SQL Server, … untouched
```

| Part | Responsibility |
| --- | --- |
| `NetworkFilterService` | Start-up order and refusals, the observer thread, block requests, five-second maintenance. |
| `BlockSet` | The only place a block is created. Applies the allow-list, the TTL and the ceiling. |
| `DivertFilterBuilder` | Writes the filters from parsed addresses only; splits large sets across handles. |
| `NetworkEnforcer` | Owns the DROP handles; updates make-before-break. Exists only in Block mode. |
| `NetworkFilterSelfTest` | Compiles and evaluates every filter with the real library before Block mode starts. |
| `LockoutGuard` | Refuses Block mode when the operator's RDP session would be at risk. |
| `WinDivertDriver` | P/Invoke to `WinDivert.dll`, transcribed from `windivert.h`. No `WinDivertSend`. |

## Safety properties

Each one is enforced in code and covered by a test.

- **Monitor is the default and never opens a DROP handle.** It logs `would-block` for every block it
  would have made.
- **No reinjection exists.** `WinDivertSend` is not declared, and a test asserts it never will be.
- **Blocks live exactly as long as the process.** No Windows Firewall rule, no registry value, no file.
  A stop, a crash or a reboot closes the handles and lifts every block.
- **The allow-list is applied twice**, when a block is added and again when the filters are written.
  A block range containing an allow-listed address is refused.
- **Block mode refuses to start** with an empty allow-list, when an address connected to the RDP port
  (read from `RDP-Tcp\PortNumber`) is not on the allow-list, or when the self-test fails. While it
  runs, a new dynamic block is refused for any address holding an RDP connection at that moment, and
  refused too when the connections cannot be read.
- **SYN evidence does not block by default.** `WP-NET-002` and `WP-NET-003` see connection attempts,
  whose source anyone can forge; they block only with `--syn-rules-may-block`.
- **The driver is never loaded as a side effect.** Handles are opened with
  `WINDIVERT_FLAG_NO_INSTALL`; `--install-driver` is the explicit exception, and what it leaves behind
  does not survive a reboot (see *Prerequisites*).
- **`WinDivert.dll` is loaded from the WPShield directory only**, never from `PATH` or the working
  directory.
- **Everything is bounded**: 200 filter objects per handle (WinDivert's limit is 256), 1,000 blocks by
  default and 10,000 at most, 50,000 tracked sources with least-recently-seen eviction, one log line
  per source and threshold rather than per packet.

## Rules

| ID | Signal | Score | Default effect |
| --- | --- | --- | --- |
| `WP-NET-001` | Address on the block list. `blocked` and `expired` events carry it, with the finding that asked in `requested_by` | 100 | Dropped (Block mode) |
| `WP-NET-002` | New connection attempts per source per minute (default threshold 60) | 60 at the threshold, 80 at 2×, 100 at 4× | Observed; blocks only with `--syn-rules-may-block` |
| `WP-NET-003` | Distinct destination ports per source per minute (default threshold 20) | 60 at the threshold, 80 at 2×, 100 at 3× | Observed; blocks only with `--syn-rules-may-block` |

Expected false positives: `WP-NET-002` at a busy shared NAT address, a crawler, or an uptime monitor;
`WP-NET-003` at a vulnerability scanner the operator runs on purpose. Allow-list those.

## Prerequisites

1. **WinDivert 2.2.2**, downloaded by the operator from the official release
   (`github.com/basil00/WinDivert/releases`, `WinDivert-2.2.2-A.zip`). Copy `WinDivert.dll` and
   `WinDivert64.sys` from its `x64` folder into the WPShield program directory, next to
   `wpshield.exe`. WPShield does not bundle or download them; WinDivert is LGPLv3.

   Check the files before copying them. `WinDivert.dll` is unsigned, and `WinDivert64.sys` carries an
   EV signature that Sectigo issued to `成都密思听科技有限公司` (Sichuan, CN), not to WinDivert's
   author; the driver's own metadata reads `Copyright © Basil 2011-2022`. Every copy of the official
   release carries that same driver, so what matters is that yours is the same file.
   `Get-FileHash <file> -Algorithm SHA256` must print exactly:

   | File | SHA-256 |
   | --- | --- |
   | `WinDivert-2.2.2-A.zip` (405,137 bytes) | `63CB41763BB4B20F600B6DE04E991A9C2BE73279E317D4D82F237B150C5F3F15` |
   | `x64\WinDivert.dll` | `C1E060EE19444A259B2162F8AF0F3FE8C4428A1C6F694DCE20DE194AC8D7D9A2` |
   | `x64\WinDivert64.sys` | `8DA085332782708D8767BCACE5327A6EC7283C17CFB85E40B03CD2323A90DDC2` |

   These are from the official release, downloaded on 2026-11-01; the driver's value also matches an
   independent public scanner's record of the same file. Some antivirus products flag WinDivert as a
   hacking tool, because cheats and malware use it too; expect that before copying it to a host.
2. **Administrator elevation**, except for `--check`.
3. **The driver loaded.** A run with `--install-driver` lets WinDivert register and start its
   `WinDivert` kernel driver service. WinDivert marks that service for deletion the moment it starts
   (read from its source, `dll/windivert.c`), so it is gone after `sc stop WinDivert` or a reboot and
   nothing stays installed. The same reason means `--install-driver` is needed again on the first run
   after every reboot.

## Running it

```powershell
# 1. No elevation, no driver: does the real library evaluate WPShield's filters as intended?
wpshield network-filter --check --allow 203.0.113.50 --block 198.51.100.0/24

# 2. Monitor: drops nothing, reports who would be blocked. Leave it running for days.
wpshield network-filter --allow 203.0.113.50 --output C:\ProgramData\WPShield\logs\network-filter.jsonl

# 3. Block: drops the named addresses for as long as it runs.
wpshield network-filter --mode Block --allow 203.0.113.50 --block 198.51.100.0/24 `
    --output C:\ProgramData\WPShield\logs\network-filter.jsonl
```

`--allow` and `--block` take comma-separated lists and may be given once each; a repeated option is
refused rather than silently keeping only the last value. A block may not be wider than `/16` (IPv4)
or `/48` (IPv6) and may not name loopback, link-local, multicast, broadcast or unspecified
addresses. An address written with host bits set (`198.51.100.7/24`) is refused, and the error names
the network it would have meant.

Events go to the console and, with `--output`, to a JSON Lines file in the gateway's envelope
(`timestamp`, `level`, `category: WPShield.NetworkFilter`, `message`, `state`). The `state.action`
vocabulary is fixed: `started`, `stopped`, `self-test-failed`, `observed`, `would-block`,
`not-blocked-spoofable-evidence`, `blocked`, `expired`, `refused-allow-listed`,
`refused-block-set-full`, `refused-unblockable-address`, `refused-rdp-client`,
`enforcement-updated`, `enforcement-failed`, `observer-failed`.

## Rollback and bypass

Stop the command (Ctrl+C, or end the process). Every block is lifted at that moment, because blocks
are handles and the handles close with the process. There is nothing else to undo. To unload the
driver as well, run `sc stop WinDivert` once no process holds a WinDivert handle; the service was
already marked for deletion, so stopping it removes it. A reboot does the same.

## What it does not do

- Touch the Windows Firewall, IIS, DNS, certificates, or any service other than the WinDivert driver
  the operator loads with `--install-driver`.
- Persist a block, or restore blocks after a restart.
- Inspect payloads, decrypt TLS, or look at UDP, ICMP or outbound traffic.
- Act on the Security log yet. `WPShield.Integration` can turn a Security-log finding into a block
  request, but it is not wired to the command: the Security-log reader replays the whole log on
  start and holds it in memory, which would block every address that ever failed a logon. It will be
  wired once the reader subscribes to new events only.

## First run on a development machine

1. Copy the WinDivert 2.2.2 x64 files next to `wpshield.exe`. Run `--check` unelevated. Every line must
   read `PASS`. **Done on 2026-11-01 on a development machine: 28 of 28 checks passed** against the
   official x64 `WinDivert.dll`, with no elevation and no driver. Steps 2 to 5 have not been run.

   `RealWinDivertSelfTest` runs the same check from the test suite when `WinDivert.dll` sits in
   `tests/WPShield.NetworkFilter.Tests/bin/Release/net10.0-windows/` (the test project targets
   `net10.0-windows`, not `net10.0`). Without the file it returns early and reports *passed*, so a pass
   in CI says nothing about the library.
2. Elevated: `wpshield network-filter --install-driver --allow <your address>` (Monitor). From another
   machine, connect to a few ports on this one. `observed` lines must appear; nothing is dropped.
3. Elevated: `--mode Block --allow <your address> --block <a second machine's address>`. From the
   second machine, a connection must now time out; from your own, it must work.
4. End the process from Task Manager, not with Ctrl+C. From the second machine, the connection must
   work again immediately: that is the dead-man's switch.
5. Only then consider the production host, in Monitor mode, for at least a week.
