# WPShield.Integration — Design (English)

`WPShield.Integration` connects `WPShield.SecurityMonitor` to `WPShield.NetworkFilter`. It holds one
type, `NetworkFilterBlockListSink`, an `ISecurityEventSink` that turns a Security-log finding with a
Block action into a block request on the network filter.

> **Status: not wired to any command yet.** See *Why it is not wired* below.

## What it does

```text
Security log 4625 ─► SecurityEventMonitor ─► WP-SEC-001 / WP-SEC-002 finding (Block)
                                                │
                                                ▼
                               NetworkFilterBlockListSink.Publish
                                                │  address from the event's IpAddress field
                                                ▼
                 NetworkFilterService.RequestBlock(address, rule, EvidenceGrade.Authenticated)
```

The sink decides nothing. Whether a request becomes a block is decided by
`NetworkFilterService.RequestBlock`, the one place blocks are created ([ADR 0006](adr/0006-network-layer-blocking.md)):

- Monitor mode logs `would-block` and blocks nothing.
- An allow-listed address is refused, whatever the finding says.
- Loopback, unspecified and other unblockable addresses (`127.0.0.1`, `::1`, `-`) are refused.
- Security-log evidence is graded `Authenticated`: the logon failed after a completed TCP handshake,
  so the address answered packets and was not forged. That is why it may add a block in Block mode
  without `--syn-rules-may-block`. The block carries the dynamic TTL (default 60 minutes).

## Why it is not wired

`SecurityEventMonitor` reads the Security log with an `EventLogReader` that starts at the oldest event
and collects everything into a list on the first scan. On a host with a 2 GB Security log that is
an unbounded read into memory, and every address that ever failed enough logons in a five-minute
window would be blocked at start-up. ADR 0002 already said how the Security log should be consumed:
subscribe to new events (`EventLogWatcher` with `readExistingEvents: false`), do not read the file.
The sink is wired to `network-filter` once the reader does that.

Two further limits of the monitor matter to anyone wiring it:

- `WP-SEC-001` counts only `LogonType 10`. With Network Level Authentication, which is the default
  for RDP, failed RDP logons are recorded as `LogonType 3`. `WP-SEC-002`, which counts every 4625 per
  address, is the rule that sees them.
- The monitor's own `AllowList` is an exact string match. The network filter's allow-list is the
  authority; the sink does not rely on the monitor's.

## Security requirements

- The address is read from the event's `IpAddress` field and parsed; nothing an attacker typed (the
  user name, the workstation name) reaches a filter, a log line or an error.
- The sink never blocks directly and holds no state of its own.
