# WPShield.NetworkFilter — Design (English)

WPShield.NetworkFilter is a **Windows-only, user-mode packet filter** that inspects inbound
TCP/UDP traffic ahead of IIS and WordPress. It is built on **WinDivert**, so a signed system
driver handles packet capture and reinjection while **all filtering decisions run in this
process**. It never runs in kernel, never acquires a kernel spinlock, and enforces a strict
per-packet inspection budget so a slow rule can never stall the network stack.

## Why it exists

A production WordPress host on Windows Server was observed crashing repeatedly with
**`0x00000133` — DPC_WATCHDOG_VIOLATION**. A kernel memory dump (`MEMORY.DMP`) analyzed with
WinDbg/kd showed the `mwac.sys` driver (Malwarebytes Web Access Control) blocked on an
in-stack queued spinlock while inspecting inbound connections in DPC context, consuming
501 clock ticks against a 500-tick watchdog limit. The server force-rebooted four times in
October 2026.

WPShield.NetworkFilter is the project's answer to that failure mode: network-layer
protection under the project's control, with tunable timeouts, bounded rule scoring, and a
structural guarantee that it cannot become the thing it is meant to defend against.

## Position in the traffic path

| Layer | Component | Position | Privileges | Blocks traffic? |
|---|---|---|---|---|
| 1 | Windows firewall | Static IP rules | System | Yes |
| 2 | **WPShield.NetworkFilter** | **Inbound TCP/UDP, user mode via WinDivert** | **Administrator (WinDivert driver only)** | **Yes** |
| 3 | WPShield.Gateway | HTTP reverse proxy, loopback only | Normal user | Yes (uploads) |
| 4 | IIS Request Filtering | URL-based filtering | System | Yes |
| 5 | WordPress | Application layer | Application pool | No |

The filter sits **between the network stack and IIS**. Blocked packets are dropped before
they reach IIS, so they never consume application pool threads, never hit PHP, and never
reach WordPress.

## Responsibilities

1. **Capture inbound TCP/UDP packets** through WinDivert on operator-configured filters
   (default: `tcp.Inbound`).
2. **Evaluate bounded rules** against source/destination IP, ports, protocol, packet size,
   and a bounded leading payload sample (first 64 bytes).
3. **Drop packets that match a blocking rule**; reinject all others so they continue to IIS.
4. **Enforce a per-packet inspection budget** (default 5 ms). If a rule takes longer, the
   packet is forwarded uninspected. The filter never stalls the network path.
5. **Emit events in the gateway's log envelope** (`timestamp`, `level`, `category`,
   `message`, `state`) so network findings correlate with gateway findings on the same field
   names.
6. **Fail closed on invalid configuration**, but **fail open on inspection timeout**: a slow
   rule never blocks traffic, it only logs a budget warning.

## What it does NOT do

- Does not run in kernel or acquire kernel spinlocks.
- Does not modify IIS bindings, URL Rewrite rules, ARR, application pools, or any IIS
  setting.
- Does not install WinDivert silently; the operator installs it explicitly.
- Does not capture full packet bodies. Only a bounded leading sample is exposed to rules.
- Does not decrypt TLS payloads (only TCP/UDP headers are visible).
- Does not replace the Windows firewall, Microsoft Defender, or a WAF. It complements them.

## Configuration (`appsettings.NetworkFilter.json` or `WPSHIELD_NETWORKFILTER_*`)

```json
{
  "NetworkFilter": {
    "Enabled": false,
    "Filter": "tcp.Inbound",
    "MaxInspectionTimeMilliseconds": 5,
    "MaxConnectionsPerMinute": 60,
    "MaxDistinctPortsPerMinute": 20,
    "BlockList": [ "45.227.254.34", "94.154.43.74" ]
  }
}
```

- `Enabled` defaults to `false`. The filter captures nothing until explicitly enabled.
- `Filter` is a WinDivert filter string. Default: `"tcp.Inbound"`.
- `MaxInspectionTimeMilliseconds` is the per-packet budget. Default: `5`. A rule exceeding
  this causes the packet to be forwarded and a budget-warning event logged.
- `MaxConnectionsPerMinute` feeds `WP-NET-002` (rate limiting). Default: `60`.
- `MaxDistinctPortsPerMinute` feeds `WP-NET-003` (port-scan detection). Default: `20`.
- `BlockList` feeds `WP-NET-001` (static block list). Default: empty.

## Rules

| RuleId | Signal | Score | Action at threshold |
|---|---|---|---|
| `WP-NET-001` | Source IP in dynamic block list | 100 | Block |
| `WP-NET-002` | > N connections from one IP per minute | 40 / 70 / 100 | Observe / Observe / Block |
| `WP-NET-003` | > N distinct destination ports from one IP per minute | 60 / 80 / 100 | Observe / Block / Block |

Scores follow the same 0–100 scale as the HTTP upload rules, and the same Monitor/Block
semantics apply per site.

## Interfaces (C#)

```csharp
namespace WPShield.Abstractions;

public enum NetworkInspectionAction
{
    Allow = 0,
    Observe = 1,
    Block = 2
}

public sealed record NetworkInspectionContext
{
    public required string SourceIp { get; init; }
    public required string DestinationIp { get; init; }
    public required int SourcePort { get; init; }
    public required int DestinationPort { get; init; }
    public required string Protocol { get; init; } // "TCP" or "UDP"
    public required DateTimeOffset Timestamp { get; init; }
    public int PacketSize { get; init; }
    public ReadOnlyMemory<byte> PayloadSample { get; init; } = default;
}

public sealed record NetworkInspectionResult
{
    public required string RuleId { get; init; }
    public required int Score { get; init; } // 0-100
    public required NetworkInspectionAction Action { get; init; }
    public required string MessageKey { get; init; }
    public required IReadOnlyDictionary<string, object> Evidence { get; init; }
}

public interface INetworkInspectionRule
{
    string RuleId { get; }
    NetworkInspectionResult Inspect(
        NetworkInspectionContext context,
        CancellationToken cancellationToken = default);
}
```

```csharp
namespace WPShield.NetworkFilter;

public sealed record NetworkFilterConfiguration
{
    public string Filter { get; init; } = "tcp.Inbound";
    public TimeSpan MaxInspectionTime { get; init; } = TimeSpan.FromMilliseconds(5);
    public int MaxConnectionsPerMinute { get; init; } = 60;
    public int MaxDistinctPortsPerMinute { get; init; } = 20;
    public IReadOnlyList<string> BlockList { get; init; } = [];
}

public static class NetworkFilterBuilder
{
    public static NetworkFilterEngine Build(NetworkFilterConfiguration? configuration = null);
}
```

## Capture flow

```
Operator enables NetworkFilter
        │
        ▼
Validate configuration (WinDivert present, filter parses, budget > 0)
        │
        ▼
Open WinDivert handle with filter "tcp.Inbound" (user mode)
        │
        ▼
For each intercepted packet:
  ├─ Parse IPv4 + TCP/UDP headers (no pointers, bounded sample)
  ├─ Stopwatch starts
  ├─ Evaluate RateLimitRule (WP-NET-002)
  ├─ Evaluate BlockListRule (WP-NET-001)
  ├─ Evaluate PortScanRule (WP-NET-003)
  ├─ If any rule returns Block → drop packet
  ├─ Stopwatch stops
  ├─ If elapsed > MaxInspectionTime → log budget warning, forward packet
  └─ Otherwise → reinject packet via WinDivertSend
        │
        ▼
Emit JSON Lines events to gateway log envelope
Rotate output file when size limit reached
```

## Security requirements

- **WinDivert is an external dependency.** The project P/Invokes `WinDivert.dll` but never downloads or installs it. The operator installs the WinDivert runtime explicitly.
- **User mode only.** All rule evaluation runs in this process. No kernel code is written by WPShield.
- **No spinlocks on the packet path.** In-process locks guard rate-limit state only; they are never held while a packet is being received or reinjected.
- **Inspection budget is structural.** 5 ms per packet by default. A slow rule is treated as a budget violation, not a blocking decision.
- **No default capture.** `Enabled: false` means zero packets are observed or dropped.
- **Privacy-safe evidence.** Logs carry rule IDs, scores, IPs, ports, and action — never full packet payloads, credentials, or cookies.

## Integration with milestones

| Milestone | Relationship |
|---|---|
| M2.6 Triage tool | NetworkFilter events use the same JSON Lines envelope as triage reports, so forensic correlation is one parser. |
| M3 Rate limiting | `WP-NET-002` and `WP-NET-003` are the network-layer half of rate limiting; M3 adds the HTTP half (per-IP burst controls on the gateway). |
| M4 Observability | NetworkFilter findings feed the structured event stream; rotation/retention patterns align with the gateway. |
| M6 Windows Service | `NetworkFilterEngine` can run as part of the WPShield Windows service under `NT SERVICE\WPShield`. |
| M7 Controlled activation | If WPShield is placed in front of IIS via ARR, NetworkFilter drops attack traffic before it reaches the rewrite rule. |

## Out of scope for this design

- Outbound traffic filtering (default filter is `tcp.Inbound`).
- ICMP fragmentation or other IP protocols.
- Deep packet inspection beyond the 64-byte leading sample.
- Integration with WordPress internals (database, `wp_options`, etc.).

## Next steps

1. Confirm `src/WPShield.NetworkFilter/` targets `net10.0-windows` and references only `WPShield.Abstractions`.
2. Document WinDivert installation as an explicit operator step (never silent).
3. Add unit tests for `RateLimitRule`, `BlockListRule`, and `PortScanRule`.
4. Add integration test using a synthetic local TCP server and WinDivert capture (requires WinDivert in CI leg).
5. Write `docs/es/diseno-filtro-red.md` mirroring this document.
