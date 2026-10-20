# WPShield.Integration — Design (English)

WPShield.Integration is an **optional, opt-in bridge project** that wires
`WPShield.SecurityMonitor` findings into `WPShield.NetworkFilter.BlockListRule`,
so IPs detected by security event rules (RDP brute force, failed logons, etc.)
are blocked at the packet layer by `WPShield.NetworkFilter.NetworkFilterEngine`
before they reach IIS.

## Why it exists

`WPShield.NetworkFilter` inspects TCP/UDP packet headers but cannot see whether an
RDP connection succeeded or failed — that happens inside the authentication session,
after the TCP handshake. `WPShield.SecurityMonitor` reads the Windows Security event
log and sees authentication results, but it cannot block packets directly.

`WPShield.Integration` closes the loop: security findings with `Action == Block`
(e.g., `WP-SEC-001` RDP brute force) add the offending source IP to the dynamic
block list used by `WPShield.NetworkFilter`, so the attacker's IP is dropped at the
packet layer on the next connection attempt.

## Position in the architecture

```
Security Event Log (4625 RDP failure)
        │
        ▼
WPShield.SecurityMonitor (WP-SEC-001 detects brute force)
        │
        ▼
WPShield.Integration → NetworkFilterBlockListSink
        │
        ▼
WPShield.NetworkFilter.BlockListRule (dynamic block list)
        │
        ▼
WPShield.NetworkFilter.NetworkFilterEngine (drops packets)
```

## Components

| Component | Responsibility |
|-----------|----------------|
| `NetworkFilterBlockListSink` | Implements `ISecurityEventSink`. Receives security findings; if `Action == Block`, extracts `source_ip` from evidence and adds it to the `BlockListRule`. |
| `SecurityToNetworkFilterBridge` | Convenience class that wires `SecurityEventMonitor`, `NetworkFilterEngine`, and `BlockListRule` together in one object. |

## Usage example

```csharp
using WPShield.Integration;
using WPShield.SecurityMonitor;
using WPShield.NetworkFilter;

// Build the bridge with default configurations.
using var bridge = new SecurityToNetworkFilterBridge();

// Scan the Security log on your own schedule (for example, every 30 seconds).
using var cts = new CancellationTokenSource();
while (!cts.Token.IsCancellationRequested)
{
    int processed = bridge.ScanSecurityLogOnce();
    await Task.Delay(TimeSpan.FromSeconds(30), cts.Token);
}

// The bridge.BlockListRule is shared with bridge.NetworkFilterEngine,
// so blocked IPs are immediately enforced by the packet filter.
```

### Manual wiring (without the bridge)

If you prefer to wire the components yourself:

```csharp
var blockListRule = new BlockListRule(new List<string>());
var sink = new NetworkFilterBlockListSink(blockListRule);

var monitor = SecurityEventBuilder.Build(
    new SecurityEventConfiguration { PublishingEnabled = true },
    sink: sink);

var filterEngine = NetworkFilterBuilder.Build(new NetworkFilterConfiguration
{
    BlockList = new List<string>() // populated by the sink
});
```

## Security requirements

- **Opt-in only.** The integration project is not referenced by the core gateway or rule projects. Operators must explicitly add it to their deployment.
- **No silent changes.** The sink only adds IPs that produced a `Block` finding. It never removes IPs unless the operator calls `RemoveIp` or `UpdateBlockList` on the `BlockListRule`.
- **Thread-safe.** Both `NetworkFilterBlockListSink` and `BlockListRule` use locks so the sink can publish from any thread without blocking the packet path for longer than a dictionary copy.
- **Privacy-safe.** The sink only stores source IP addresses and rule IDs — never credentials, session tokens, or full event payloads.

## Out of scope

- Real-time blocking. `SecurityEventMonitor.ScanOnce()` is polling-based; the bridge does not subscribe to live event streams.
- IP expiration. Blocked IPs remain in the list until the operator removes them. Consider pairing with `M3` rate limiting and temporary blocks when that milestone lands.

## Next steps

1. Confirm `src/WPShield.Integration/` targets `net10.0-windows` and references both `WPShield.SecurityMonitor` and `WPShield.NetworkFilter`.
2. Add unit tests for `NetworkFilterBlockListSink` and `SecurityToNetworkFilterBridge`.
3. Write `docs/es/diseno-integracion.md` mirroring this document.
