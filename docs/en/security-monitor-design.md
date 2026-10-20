# WPShield.SecurityMonitor — Design (English)

WPShield.SecurityMonitor is a **Windows-only, user-mode component** that reads the Windows
Security event log and detects authentication attacks such as RDP brute force and repeated
failed logons. It publishes findings to a sink that can feed the dynamic block list of
`WPShield.NetworkFilter`, closing the gap between packet-level filtering and authentication
failures that packets alone cannot reveal.

## Why it exists

A production WordPress host on Windows Server was observed receiving sustained attacks on
both web ports (80/443) and Remote Desktop (TCP 3389). `WPShield.NetworkFilter` can block
packets by source IP and rate, but it cannot see whether an RDP connection succeeded or
failed — that happens inside the authentication session, after the TCP handshake.

`WPShield.SecurityMonitor` reads Event ID `4625` (failed logon) and `4624` (logon success)
from the Security log, identifies Logon Type `10` (RemoteInteractive = RDP), and raises
findings when a source IP exceeds a configurable failure threshold. Those findings can be
published to a block list that `NetworkFilter` consumes, so the attacker's IP is dropped at
the packet layer before it can even attempt another logon.

## Position in the architecture

| Layer | Component | What it sees | Blocks? |
|---|---|---|---|
| 1 | Windows Firewall | Static IP rules | Yes |
| 2 | `WPShield.NetworkFilter` | TCP/UDP packet headers | Yes |
| 3 | **`WPShield.SecurityMonitor`** | **Security event log (auth results)** | **Indirectly** |
| 4 | `WPShield.Gateway` | HTTP request bodies | Yes (uploads) |
| 5 | IIS + WordPress | Application layer | No |

The monitor does not block traffic directly. It emits findings (score, action, evidence) to
an `ISecurityEventSink`. An operator-provided sink implementation decides what to do:
write to the JSON Lines log, publish IPs to the `NetworkFilter` dynamic block list, alert,
etc.

## Responsibilities

1. **Read the Windows Security event log** (read-only; never modifies, clears, or archives).
2. **Filter by configured Event IDs** (default: 4624 success, 4625 failure).
3. **Evaluate rules** against source IP, user name, logon type, process, and timestamp.
4. **Enforce sliding-window failure counting** per source IP.
5. **Publish findings** to a configured `ISecurityEventSink`.
6. **Require Administrator privileges**; refuse to start without elevation.

## What it does NOT do

- Does not modify the Security event log (read-only).
- Does not block packets directly (feeds findings to a sink instead).
- Does not install or configure anything silently.
- Does not replace the Windows firewall, Microsoft Defender, or an IDS/IPS.

## Configuration (`appsettings.SecurityMonitor.json` or `WPSHIELD_SECURITYMONITOR_*`)

```json
{
  "SecurityMonitor": {
    "Enabled": false,
    "LogName": "Security",
    "EventIds": [ 4624, 4625 ],
    "RemoteLogonTypes": [ "10" ],
    "MaxFailedLogonsPerWindow": 5,
    "WindowMinutes": 5,
    "AllowList": [ "127.0.0.1", "10.0.0.5" ],
    "PublishingEnabled": true
  }
}
```

- `Enabled` defaults to `false`. The monitor reads nothing until explicitly enabled.
- `LogName` is the Windows event log name. Default: `"Security"`.
- `EventIds` is the list of event IDs to inspect. Default: `[4624, 4625]`.
- `RemoteLogonTypes` identifies RDP logons (Logon Type `10` = RemoteInteractive).
- `MaxFailedLogonsPerWindow` is the threshold before a finding is raised. Default: `5`.
- `WindowMinutes` is the sliding window for failure counting. Default: `5`.
- `AllowList` contains source IPs that are never flagged or published.
- `PublishingEnabled` controls whether findings are sent to the sink. Default: `true`.

## Rules

| RuleId | Signal | Score | Action at threshold |
|---|---|---|---|
| `WP-SEC-001` | RDP brute force: ≥ N failed Logon Type 10 from one IP per window | 40 / 80 / 100 | Observe / Block / Block |
| `WP-SEC-002` | Any failed logon (4625): ≥ N failures from one IP per window | 30 / 70 / 100 | Observe / Block / Block |

Scores follow the same 0–100 scale as the HTTP upload rules and network packet rules.

## Interfaces (C#)

```csharp
namespace WPShield.Abstractions;

public sealed record SecurityInspectionContext
{
    public required int EventId { get; init; }
    public required string SourceIp { get; init; }
    public required string UserName { get; init; }
    public required string LogonType { get; init; }
    public required string ProcessName { get; init; }
    public required string ComputerName { get; init; }
    public required DateTimeOffset TimeCreated { get; init; }
    public required string Message { get; init; }
}

public sealed record SecurityInspectionResult
{
    public required string RuleId { get; init; }
    public required int Score { get; init; } // 0-100
    public required NetworkInspectionAction Action { get; init; }
    public required string MessageKey { get; init; }
    public required IReadOnlyDictionary<string, object> Evidence { get; init; }
}

public interface ISecurityInspectionRule
{
    string RuleId { get; }
    SecurityInspectionResult Inspect(
        SecurityInspectionContext context,
        CancellationToken cancellationToken = default);
}

public interface ISecurityEventSink
{
    void Publish(SecurityInspectionResult finding, SecurityInspectionContext context);
}
```

```csharp
namespace WPShield.SecurityMonitor;

public sealed record SecurityEventConfiguration
{
    public string LogName { get; init; } = "Security";
    public IReadOnlyList<int> EventIds { get; init; } = new[] { 4624, 4625 };
    public IReadOnlyList<string> RemoteLogonTypes { get; init; } = new[] { "10" };
    public int MaxFailedLogonsPerWindow { get; init; } = 5;
    public int WindowMinutes { get; init; } = 5;
    public IReadOnlyList<string> AllowList { get; init; } = [];
    public bool PublishingEnabled { get; init; } = true;
}

public static class SecurityEventBuilder
{
    public static SecurityEventMonitor Build(
        SecurityEventConfiguration? configuration = null,
        IEnumerable<ISecurityInspectionRule>? extraRules = null,
        ISecurityEventSink? sink = null);
}
```

## Usage example

```csharp
using WPShield.SecurityMonitor;
using WPShield.SecurityMonitor.Rules;

var config = new SecurityEventConfiguration
{
    MaxFailedLogonsPerWindow = 5,
    WindowMinutes = 5,
    AllowList = new[] { "127.0.0.1" }
};

var sink = new MyBlockListSink(); // implements ISecurityEventSink
var monitor = SecurityEventBuilder.Build(config, sink: sink);

// Scan periodically (for example, every 30 seconds)
using var cts = new CancellationTokenSource();
while (!cts.Token.IsCancellationRequested)
{
    int processed = monitor.ScanOnce();
    await Task.Delay(TimeSpan.FromSeconds(30), cts.Token);
}
```

## Security requirements

- **Read-only.** The monitor opens the Security log for reading only. It never modifies,
  clears, archives, or exports the log.
- **Elevation required.** Reading the Security log requires Administrator privileges.
  Missing elevation is a startup blocker, not a degraded mode.
- **No silent installation.** The operator runs the monitor explicitly; it never installs
  services or changes ACLs automatically.
- **Privacy-safe evidence.** Findings carry rule IDs, scores, IPs, user names, and logon
  types — never passwords, session tokens, or full event payloads.

## Integration with milestones

| Milestone | Relationship |
|---|---|
| M2.7 Network filter | SecurityMonitor findings feed the dynamic block list of `WPShield.NetworkFilter`. |
| M3 Rate limiting | `WP-SEC-001` and `WP-SEC-002` are the authentication half of rate limiting; M3 adds the HTTP half. |
| M4 Observability | SecurityMonitor findings use the same JSON Lines log envelope as the gateway. |
| M6 Windows Service | `SecurityEventMonitor` can run as part of the WPShield Windows service under `NT SERVICE\WPShield`. |

## Out of scope

- Real-time blocking (the monitor is polling-based via `ScanOnce`; it does not subscribe to live event streams).
- Reading other event logs (System, Application) — only Security.
- Decrypting or inspecting RDP session contents.

## Next steps

1. Confirm `src/WPShield.SecurityMonitor/` targets `net10.0-windows` and references only `WPShield.Abstractions`.
2. Add unit tests for `RdpBruteForceRule` and `FailedLogonRule`.
3. Add an example `ISecurityEventSink` implementation that publishes to `WPShield.NetworkFilter.BlockListRule`.
4. Write `docs/es/diseno-monitor-seguridad.md` mirroring this document.
