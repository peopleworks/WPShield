# WPShield.NetworkSensor — Design (English)

WPShield.NetworkSensor is a **separate, optional, Windows-only component** that captures
network metadata on operator-named ports (for example `80` and `443`) so an operator can
see what traffic reaches the host. It is **not** the HTTP gateway, it is **not** in the
request path, and it never modifies IIS.

## Local listener inventory

Use this local command to see TCP listeners and bound UDP endpoints before choosing ports for a
traffic capture. It reads the Windows socket tables once and works independently of Npcap.

```powershell
wpshield network-monitor --listeners
wpshield network-monitor --listeners --ports 443,1433,3389 --json
```

Omitting `--ports` includes all local ports. The filter accepts 1–64 port numbers. Each protocol
has a separate UTC observation time, read status and list of distinct local addresses and ports.
Bindings are labelled `loopback`, `wildcard` (all local addresses of that family) or `specific`.
IPv6 addresses retain any scope ID. The output contains local addresses and is intended for the operator.

A `read` table can be empty. A `limited` table contains up to 4,096 distinct matching endpoints
and carries the reason `row-limit`. An `unavailable` table carries `access-denied` or `query-failed`.
Exit code 0 means both tables were read completely, 2 means partial results, and 1 means both
tables were unavailable or the arguments were invalid.

To check a change, repeat the command with the same filter and compare protocol, address and port
for each table marked `read` in both snapshots. TCP and UDP are read in sequence. A socket can
appear or disappear between reads. External reachability, service ownership, site and login
outcome all require independent evidence.

### Observed owner PID

```powershell
wpshield network-monitor --listeners --ports 443,1433,3389 --owners --json
```

For each protocol and IP family with retained endpoints, the CLI reads a second local Windows
table. It matches the full local address (including IPv6 scope) and port. Each endpoint gains
an `Owner` object with `ObservedAtUtc`, `ProcessId` and `Reason`. A unique nonzero PID is the
process identifier Windows reported at that second observation. The socket can change hands
between reads. Windows can also reuse a PID after a process exits. A historical PID cannot
identify a running process, Windows service, IIS site or login without further evidence.
[Windows TCP table](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable) · [Windows UDP table](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedudptable)

`ProcessId` is null if the endpoint disappeared (`not-observed`), the rows disagree
(`ambiguous`) or Windows supplied PID zero (`pid-unavailable`). A failed owner table
marks affected endpoints with `access-denied`, `query-failed`, `invalid-table` or `table-limit`.
Each native table read has a 1 MiB buffer ceiling and at most three attempts. A failed owner
table makes the result partial (exit 2) while preserving the listener rows. A successful table
can legitimately contain unresolved endpoints. Omitting `--owners` skips the extra reads and
the `Owner` field.

## Host flow view

To find the capture interface, run the local inventory first.

```powershell
wpshield network-monitor --list-interfaces
wpshield network-monitor --list-interfaces --json
```

Copy the Npcap device ID from the first column into `--interfaces` when starting a flow capture.
The ID remains usable after a Windows adapter rename. A unique friendly name or description also works.
The inventory reports whether Npcap sees local IPv4 or IPv6 addresses. An adapter with neither
cannot determine flow direction. The inventory reads device metadata without opening the adapter.
Capture permissions and link support are checked when capture starts. Successful enumeration with
zero devices returns `[]` in JSON. An enumeration error exits with code 1 and writes to stderr.
If the selected ID disappears, list the interfaces again and choose the intended source explicitly.

Run the CLI locally with administrator privileges and Npcap installed. Use the name of one
Windows adapter and the actual service ports on that host. These examples use common ports.

```powershell
wpshield network-monitor --flows --interfaces "Ethernet" --ports 443,1433,3389
wpshield network-monitor --flows --interfaces "Ethernet" --all-ports --json
```

Every two seconds the console shows up to 40 most recently active flows, with local and remote
endpoints, protocol, last activity in UTC, and observed IP bytes received and sent (including IP and
transport headers and retransmissions). Both directions share one row. An observed opening TCP SYN
identifies the local or remote initiator. UDP and TCP first seen midstream show `unknown`. A port
filter can match either endpoint. Service identity, site attribution and authentication outcomes
require separate evidence. Ctrl+C stops the capture and prints a final snapshot.

JSON includes every retained flow. The table holds at most 4,096 flows and expires entries after 60 seconds of inactivity. The display
includes the active count, packets skipped during decoding or direction assignment, packets dropped
at table capacity and the driver's reported drop counter (null in JSON when unavailable). A zero
driver counter cannot establish complete coverage. [Npcap capture statistics](https://npcap.com/guide/wpcap/pcap_stats.html)

The capture requests at most 160 bytes per frame and retains only flow metadata. TCP/UDP over
IPv4 and basic IPv6 are supported. VLAN encapsulation, IP fragments and IPv6 extension headers are
outside this version's coverage. Both-local and neither-local traffic cannot be assigned a remote
endpoint. Filters can exclude frames before software counters see them. Only addresses assigned to
the selected adapter at startup are used for direction. Output is local and includes IP addresses.

### Source status

Every flow snapshot identifies the adapter (`Interface`), the UTC snapshot time (`Timestamp`) and
the selected TCP/UDP ports (`CapturePorts`, an empty array for all ports). During capture,
`CaptureStatus` is `running`. The final snapshot reports `stopped` for an operator stop or
`interrupted` for an unexpected driver stop, including with zero flows and with history disabled.
A failure before capture starts reports a command error. In JSON mode diagnostics go to stderr.

For RDP and SQL, `WindowStart` and `WindowEnd` bound the event query in UTC. RDP names the
Security channel and selected local TCP port. SQL names the Application channel and instance
provider. Each query has its own `AuditStatus`. A completed empty query returns `read` and
provides no login evidence. For `unavailable`, `UnavailableReason` is `access-denied` or
`query-failed`; for a readable or limited query the reason is null. Older JSON may omit these
fields. Window timestamps describe the period queried. They cannot establish whether the
server was configured to record every login.

### Traffic history

```powershell
wpshield network-monitor --flows --interfaces "Ethernet" --ports 443,1433,3389 --history --json
```

The optional history shows observed IP bytes per second for each direction on the selected adapter
and ports. Counting happens after decoding and direction checks, before flow admission, expiry or
tuple reuse. A full flow table can omit an endpoint row while its observed bytes still count.
Each snapshot closes one interval. A monotonic clock measures its duration and UTC labels its
boundaries. The first and final intervals can be short. The console shows five intervals and JSON
includes up to 30 under `History` (under `Traffic.History` when an audit is selected).
Snapshots overlap in history; use each interval once when comparing them.

| Coverage | Meaning |
| --- | --- |
| `observed` | The driver counter was available at both boundaries and the reader detected no gap. Rates describe the selected, decodable traffic. |
| `unknown` | The driver counter was unavailable at a boundary. Rates still measure observed bytes. A zero is insufficient to establish an idle network. |
| `gap` | Packets were skipped, the driver counter rose or reset, capture stopped unexpectedly, sampling exceeded five seconds, or the UTC and monotonic clocks disagreed. Rates are null. Counts and `GapReasons` remain available. |

History is kept in memory during the capture. The graphical timeline and pausing its display are
planned for the local dashboard. Validation of rates with a live Windows Server/Npcap capture
remains pending.

### Remote Desktop logon evidence

On the monitored server, specify its configured local Remote Desktop TCP port. The account running
the command needs read access to the Windows Security log. Whether Windows records successes and
failures depends on the host's existing Audit Logon policy.

```powershell
wpshield network-monitor --flows --interfaces "Ethernet" --ports 443,1433,3389 --rdp-port 3389
```

For each snapshot WPShield reads up to 256 recent RemoteInteractive (type 10) events from the past
60 seconds, newest first. A match requires the same client IP and source port, a recorded time
between the first and last packet observed for that flow, and a unique candidate on the selected
adapter and local TCP port with an observed incoming SYN. Windows records a successful logon in
event 4624 and a failed attempt in 4625. Each match includes its UTC time and Security record ID
for lookup in Event Viewer. [Event 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624) · [Event 4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)

- `success`, `failure` and `mixed` summarize the matching audit records in this snapshot.
  `unknown` covers missing source ports, midstream captures, ambiguous flows and absent evidence.
  Failures recorded under other logon types are outside this view.
- `AuditStatus` is `read` when the query completes, `limited` when it reaches its record or polling
  budget, and `unavailable` when Windows denies access or the query fails. Traffic remains visible.
- With `--json`, each line contains `Traffic` and `RdpAudit`. A record may reappear in successive
  snapshots. Use its Security record ID to count it once within the same log. Output contains
  endpoint addresses but omits account names and event messages. A match concerns a logon on the
  host. The audit record omits the destination endpoint, so uniqueness applies only to the captured
  flows. Site attribution and activity inside a desktop session require other evidence.

To validate on a Windows Server test host with Npcap, start the command before an authorized
Remote Desktop sign-in. In Event Viewer, open **Windows Logs → Security** and compare the record
ID, UTC time, source IP and source port with the displayed flow. Record whether the audit read
completed and whether capture drops occurred. If Windows omits the source port, the expected
result is `unknown`. That run exercises missing evidence and leaves a positive match unverified.

### SQL Server login evidence

Read one minute of existing **Windows Logs → Application** events for one local Database Engine
instance. The standalone command needs permission to read Application and runs independently of
Npcap and SQL credentials. Use `MSSQLSERVER` for the default instance. For a named instance, copy
the suffix of its `MSSQL$<name>` source from Event Viewer, preserving spelling and case.

```powershell
wpshield network-monitor --sql-instance MSSQLSERVER --json
wpshield network-monitor --flows --interfaces "Ethernet" --ports 1433,3389 --rdp-port 3389 --sql-instance Example
```

Events 18453, 18454 and 18455 indicate a successful login. Event 18456 records a failure.
Availability depends on the server's auditing and logging configuration. The reader selects the
instance provider and event metadata only. Each row gives the event ID, Application record ID,
UTC time and outcome. The result applies to the instance. `FlowAttribution` stays `unknown`
even if a single TCP flow used its usual port. Usernames, event messages and SQL statements are
excluded. [SQL Server event IDs](https://learn.microsoft.com/en-us/sql/relational-databases/errors-events/database-engine-events-and-errors-18000-to-18999) · [Windows Application providers](https://learn.microsoft.com/en-us/sql/relational-databases/performance/view-the-windows-application-log-windows-10)

The newest 256 matching records fit in a snapshot, subject to a 500 ms polling budget.
`ObservedOutcome` summarizes only the returned records as `success`, `failure`, `mixed` or
`unknown`. A completed query with zero matches leaves the outcome unknown, including for an
absent provider. Standalone exit codes are 0 for `read`, 2 for `limited` and 1 for
`unavailable` or invalid arguments. With `--flows --json` the same fields appear under
`SqlAudit` alongside `Traffic` and optional `RdpAudit`. Overlapping windows can repeat a record.
For live validation compare the channel, provider, record ID and UTC time against a known login
in Event Viewer on a test server with existing audits. The command leaves auditing untouched.

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

## HTTP metadata mode responsibilities

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
