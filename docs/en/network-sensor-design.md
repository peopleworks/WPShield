# WPShield.NetworkSensor — Design (English)

WPShield.NetworkSensor is a **separate, optional, Windows-only component** that captures
network metadata on operator-named ports (for example `80` and `443`) so an operator can
see what traffic reaches the host. It is **not** the HTTP gateway, it is **not** in the
request path, and it never modifies IIS.

## Why it must be separate

| Concern | WPShield.Gateway (M1/M2) | WPShield.NetworkSensor (proposed) |
|---|---|---|
| Position | Inline reverse proxy, loopback only | Passive capture, separate process |
| Privileges | Normal user, loopback listener | Administrator, Npcap driver |
| Modifies IIS | No | No |
| Sees request bodies | Only bounded multipart samples | Never |
| Sees query strings | Never logged | Never logged |
| Default exposure | Loopback `127.0.0.1:10000` | None until operator enables it |

Mixing a packet capture driver into the HTTP gateway would break the loopback-only invariant,
require kernel privileges inside the request path, and tempt the implementation to inspect
full bodies — all prohibited by AGENTS.md and THREAT_MODEL.md.

## Responsibilities

1. **Capture only metadata.** Source/destination IP, source/destination port, HTTP method,
   request path (query string stripped), response status code, body size, timestamp, network
   interface name.
2. **Filter by operator-named ports only.** A BPF filter restricts capture to the ports listed
   in configuration (default: none — the sensor captures nothing until configured).
3. **Never capture full bodies, credentials, cookies, authorization headers, nonces, tokens,
   or complete query strings.** This is structural, not a threshold that can be lowered later.
4. **Emit events in the gateway's log envelope** (`timestamp`, `level`, `category`, `message`,
   `state`) so a forensic report and a gateway log correlate on the same field names.
5. **Fail closed.** If Npcap is missing, elevation is absent, or the configuration is invalid,
   the sensor refuses to start and writes a clear blocker message.

## What it does NOT do

- Does not bind to ports 80/443 or change IIS bindings.
- Does not modify URL Rewrite rules, ARR, application pools, or any IIS setting.
- Does not install Npcap silently; the operator installs it explicitly.
- Does not run in promiscuous mode unless the operator explicitly opts in.
- Does not inspect, buffer, or store request/response bodies.
- Does not block traffic. It observes and reports only.
- Does not replace IIS logs, Microsoft Defender, or a WAF.

## Configuration (`appsettings.NetworkSensor.json` or `WPSHIELD_NETWORKSENSOR_*`)

```json
{
  "NetworkSensor": {
    "Enabled": false,
    "Interfaces": [ "Ethernet", "vEthernet (WSL)" ],
    "Ports": [ 80, 443 ],
    "PromiscuousMode": false,
    "MaxEventsPerSecond": 1000,
    "OutputPath": "C:\\WPShield\\Logs\\network.ndjson",
    "Rotation": {
      "MaxFileSizeBytes": 104857600,
      "RetentionDays": 30
    }
  }
}
```

- `Enabled` defaults to `false`. The sensor captures nothing until explicitly enabled.
- `Interfaces`, when present, limits capture to those adapter names. When empty, all adapters
  matching the port filter are used.
- `Ports` is mandatory when enabled. Empty list = capture nothing.
- `PromiscuousMode` defaults to `false`. True is an explicit operator choice, logged as a blocker-level event.
- `MaxEventsPerSecond` bounds the emission rate so the sensor cannot become a noise amplifier.
- `OutputPath` is a file the sensor writes; it is the only write the component makes.

## Event model (JSON Lines, gateway envelope)

Every emitted line is one JSON object:

```json
{
  "timestamp": "2026-10-20T14:32:07.1234567Z",
  "level": "Information",
  "category": "WPShield.NetworkSensor",
  "message": "HTTP request observed",
  "state": "observed",
  "requestId": "ns-1a2b3c4d-...",
  "interface": "Ethernet",
  "srcIp": "192.0.2.10",
  "dstIp": "192.0.2.1",
  "srcPort": 51422,
  "dstPort": 443,
  "method": "POST",
  "path": "/wp-admin/admin-ajax.php",
  "statusCode": 200,
  "bodySizeBytes": 12450,
  "tls": true
}
```

Privacy-safe fields only. `path` is the request path **without** the query string. No
`Authorization`, `Cookie`, `Set-Cookie`, body content, or full query string ever appears.

## Interfaces (C#)

These contracts live in `WPShield.NetworkSensor` and reference only `WPShield.Abstractions`
for shared types where appropriate.

```csharp
namespace WPShield.NetworkSensor;

public sealed class NetworkSensorConfiguration
{
    public bool Enabled { get; init; }
    public IReadOnlyList<string> Interfaces { get; init; } = [];
    public IReadOnlyList<int> Ports { get; init; } = [];
    public bool PromiscuousMode { get; init; }
    public int MaxEventsPerSecond { get; init; } = 1000;
    public string OutputPath { get; init; } = string.Empty;
    public RotationConfiguration Rotation { get; init; } = new();
}

public sealed class RotationConfiguration
{
    public long MaxFileSizeBytes { get; init; } = 100_000_000;
    public int RetentionDays { get; init; } = 30;
}

public sealed record NetworkEvent
{
    public required DateTimeOffset Timestamp { get; init; }
    public required string Level { get; init; }
    public required string Category { get; init; }
    public required string Message { get; init; }
    public required string State { get; init; }
    public required string RequestId { get; init; }
    public required string InterfaceName { get; init; }
    public required string SourceIp { get; init; }
    public required string DestinationIp { get; init; }
    public required int SourcePort { get; init; }
    public required int DestinationPort { get; init; }
    public required string HttpMethod { get; init; }
    public required string Path { get; init; } // query string stripped
    public required int StatusCode { get; init; }
    public required long BodySizeBytes { get; init; }
    public required bool Tls { get; init; }
}

public interface INetworkSensor : IAsyncDisposable
{
    Task StartAsync(CancellationToken cancellationToken);
    Task StopAsync(CancellationToken cancellationToken);
    bool IsRunning { get; }
}

public interface INetworkEventSink
{
    Task WriteAsync(NetworkEvent @event, CancellationToken cancellationToken);
}
```

## Capture flow

```
Operator enables NetworkSensor
        │
        ▼
Validate configuration (ports non-empty, Npcap present, elevated)
        │
        ▼
Build BPF filter: "tcp port 80 or tcp port 443"
        │
        ▼
Open live capture on selected interfaces (non-promiscuous by default)
        │
        ▼
For each packet:
  ├─ Parse Ethernet/IP/TCP
  ├─ If destination port not in configured list → skip
  ├─ Attempt lightweight HTTP parse (method, path, status, size)
  ├─ Strip query string from path
  ├─ Emit NetworkEvent to sink (JSON Lines)
  └─ Enforce MaxEventsPerSecond token bucket
        │
        ▼
Rotate output file when size limit reached; purge files older than RetentionDays
```

## Security requirements

- **Npcap is an external dependency.** The sensor references it but never downloads or installs it.
- **Elevation required.** The process must run as Administrator. Missing elevation is a startup blocker, not a degraded mode.
- **No privileged service account changes.** The sensor does not create Windows services, change ACLs, or modify IIS.
- **Events are write-once appends.** Rotation replaces files but never edits existing content.
- **No default capture.** `Enabled: false` and empty `Ports` means zero packets are observed.

## Integration with milestones

| Milestone | Relationship |
|---|---|
| M4 Observability | NetworkSensor events feed the same structured event stream; rotation/retention patterns align. |
| M5 Dashboard | Loopback-only dashboard view of NetworkSensor events; Windows authentication before any remote use. |
| M7 Controlled activation | If WPShield is eventually placed in front of IIS via ARR (M7), the gateway already sees HTTP traffic; NetworkSensor becomes complementary network-layer visibility, not redundant. |

## Out of scope for this design

- Packet injection or blocking.
- Decryption of TLS payloads (only TLS handshake metadata: `tls: true`).
- Intrusion prevention signatures.
- Integration with WordPress internals (database, `wp_options`, etc.).

## Next steps

1. Add `src/WPShield.NetworkSensor/` project targeting `net10.0-windows`.
2. Add SharpPcap + PacketDotNet to `Directory.Packages.props`.
3. Implement configuration binding and validation.
4. Implement BPF filter construction and live capture loop.
5. Implement JSON Lines event sink with rotation.
6. Add unit tests for configuration validation, path stripping, and event serialization.
7. Add integration test using a synthetic local HTTP server and loopback capture (requires Npcap in CI leg).
8. Write `docs/es/diseno-sensor-red.md` mirroring this document.