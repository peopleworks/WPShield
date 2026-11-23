using System.Security.Principal;
using System.Text.Json;
using System.Threading;
using WPShield.NetworkSensor;
using WPShield.SecurityMonitor;

namespace WPShield.Cli;

/// <summary>
/// <c>wpshield network-monitor</c> — live passive capture of HTTP metadata on operator-named ports.
/// </summary>
/// <remarks>
/// <para>
/// This is the operator entry point for WPShield.NetworkSensor. It starts a read-only packet
/// capture on the ports named in <c>--ports</c> (for example 80, 443), extracts HTTP metadata
/// only — method, path without query string, status code, body size — and writes it as JSON Lines
/// to <c>--output</c>. It never captures bodies, credentials, cookies, or query strings, and it
/// never touches IIS.
/// </para>
/// <para>
/// <b>Elevation is required.</b> Packet capture needs the Npcap driver and an Administrator
/// token. The command refuses to start without both, rather than degrading silently into a monitor
/// that sees nothing.
/// </para>
/// <para>
/// <b>Nothing here modifies IIS.</b> No bindings, no rewrite rules, no application pools. The
/// command observes traffic on the wire; it does not put WPShield in the path. To do that, use
/// <c>wpshield enable</c> and the IIS URL Rewrite rule documented in ADR 0001.
/// </para>
/// <para>
/// Stop it with Ctrl+C. Nothing on this machine is changed by running it.
/// </para>
/// </remarks>
internal static class NetworkMonitorCommand
{
    public const string Help = """
        wpshield network-monitor - observe host TCP/UDP flows or HTTP metadata. Reads only.

        Usage: wpshield network-monitor [options]

        Host flow view (local console, administrator and Npcap required):
          wpshield network-monitor --flows --interfaces Ethernet --ports 443,1433,3389
          wpshield network-monitor --flows --interfaces Ethernet --all-ports
          Select exactly one adapter. Shows TCP/UDP endpoints, observed IP bytes in each
          direction, initiator and capture counters every two seconds. Add --json for JSON Lines.
          The console shows 40 recent rows. JSON includes all retained rows (up to 4096).
          Add --history for observed inbound and outbound IP bytes per second. The console
          shows the latest five intervals, JSON up to 30. Gaps keep counts and omit rates.
          Add --rdp-port <port> to match remote interactive logon records from the local
          Security log against observed TCP flows. Include the local RDP port in the capture.
          Add --sql-instance <name> to show Database Engine login events for one local instance.
          Ctrl+C prints the final snapshot and stops capture.

        SQL Server audit snapshot (Application log read permission, no Npcap required):
          wpshield network-monitor --sql-instance MSSQLSERVER [--json]
          Use MSSQLSERVER for the default instance or the instance name as shown in Event Viewer.
          Reads the last minute. Events identify the instance; flow attribution is unknown.

        HTTP metadata mode:

          --ports <numbers>   Comma-separated TCP ports to capture. Required. Example: 80,443.
          --interfaces <names> Comma-separated network interface names. Default: all interfaces
                               that have an IP address.
          --output <file>     JSON Lines output file. Default:
                              C:\ProgramData\WPShield\logs\network.ndjson.
          --max-events-per-second <n>  Maximum events emitted per second. Default: 1000.
          --promiscuous       Put the interface in promiscuous mode. Off by default; enabling it is
                              an explicit operator choice and is logged as a blocker-level event.
          --rotation-max-size-bytes <n> Rotate the output file when it reaches this size.
                              Default: 104857600 (100 MiB).
          --rotation-retention-days <n> Purge rotated files older than this many days.
                              Default: 30.

        HTTP mode emits recognizable plaintext HTTP metadata. Use --flows for transport endpoints
        and byte counts, including encrypted connections.

        What it does NOT do: block traffic, modify IIS, install Npcap, or capture in promiscuous
        mode unless --promiscuous is passed. Npcap must be installed separately by the operator;
        this command does not download or install it.

        Stop it with Ctrl+C. Nothing on this machine is changed by running it.

        Exit codes:
          0   stopped cleanly
          1   invalid arguments, capture unavailable, or standalone SQL audit unavailable
          2   standalone SQL audit returned a partial window
        """;

    private static readonly string[] KnownOptions =
    [
        "--ports", "--interfaces", "--output", "--max-events-per-second",
        "--promiscuous", "--rotation-max-size-bytes", "--rotation-retention-days"
    ];

    public static int Run(CliOptions arguments, TextWriter output)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(output);

        if (arguments.Has("--flows"))
            return RunFlows(arguments, output);
        if (arguments.Has("--sql-instance"))
        {
            arguments.RejectUnknown("--sql-instance", "--json");
            arguments.RejectRepeated();
            if (arguments.Get("--json") is not null) throw new CliArgumentException("--json takes no value.");
            var sql = SqlLoginAuditReader.Read(RequiredSqlInstance(arguments), DateTimeOffset.UtcNow);
            return WriteStandaloneSqlAudit(output, sql, arguments.Has("--json"));
        }
        arguments.RejectUnknown(KnownOptions);

        if (!IsElevated())
        {
            output.WriteLine("ERROR: network-monitor requires an Administrator elevation.");
            output.WriteLine("       Run the command from an elevated command prompt or PowerShell.");
            return 1;
        }

        var ports = arguments.IntegerList("--ports", []);
        if (ports.Count == 0)
        {
            output.WriteLine("ERROR: --ports is required. Example: wpshield network-monitor --ports 80,443");
            return 1;
        }

        var interfaces = arguments.List("--interfaces");
        var outputPath = arguments.Get("--output") ??
            @"C:\ProgramData\WPShield\logs\network.ndjson";
        var maxEventsPerSecond = arguments.Integer("--max-events-per-second", 1000);
        var promiscuous = arguments.Flag("--promiscuous");
        var maxFileSizeBytes = arguments.Integer("--rotation-max-size-bytes", 100 * 1024 * 1024);
        var retentionDays = arguments.Integer("--rotation-retention-days", 30);

        var configuration = new NetworkSensorConfiguration
        {
            Enabled = true,
            Interfaces = interfaces,
            Ports = ports,
            PromiscuousMode = promiscuous,
            MaxEventsPerSecond = maxEventsPerSecond,
            OutputPath = outputPath,
            Rotation = new RotationConfiguration
            {
                MaxFileSizeBytes = maxFileSizeBytes,
                RetentionDays = retentionDays,
            }
        };

        try
        {
            using var sink = new JsonLinesEventSink(
                configuration.OutputPath,
                configuration.Rotation.MaxFileSizeBytes,
                configuration.Rotation.RetentionDays);
            using var sensor = new WPShield.NetworkSensor.NetworkSensor(configuration, sink);

            var started = new ManualResetEventSlim();
            var stopping = new ManualResetEventSlim();
            sensor.IsRunningChanged += (_, running) =>
            {
                if (running)
                {
                    started.Set();
                }
            };

            sensor.StartAsync(CancellationToken.None).GetAwaiter().GetResult();

            if (!started.Wait(TimeSpan.FromSeconds(10)))
            {
                output.WriteLine("ERROR: the network sensor did not start within 10 seconds.");
                return 1;
            }

            output.WriteLine($"Network sensor running. Ports: {string.Join(",", ports)} Output: {outputPath}");
            output.WriteLine("Press Ctrl+C to stop. Nothing is written to IIS.");

            var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (_, e) =>
            {
                e.Cancel = true;
                stopping.Set();
                cts.Cancel();
            };

            stopping.Wait();

            sensor.StopAsync(CancellationToken.None).GetAwaiter().GetResult();
            output.WriteLine("Network sensor stopped.");
            return 0;
        }
        catch (Exception exception) when (exception is InvalidOperationException or
                                          UnauthorizedAccessException or IOException)
        {
            output.WriteLine($"ERROR: {exception.Message}");
            return 1;
        }
    }

    private static int RunFlows(CliOptions arguments, TextWriter output)
    {
        arguments.RejectUnknown("--flows", "--interfaces", "--ports", "--all-ports", "--json", "--rdp-port", "--sql-instance", "--history");
        arguments.RejectRepeated();
        if (arguments.Get("--flows") is not null || arguments.Get("--all-ports") is not null ||
            arguments.Get("--json") is not null || arguments.Get("--history") is not null)
            throw new CliArgumentException("--flows, --all-ports, --json and --history take no value.");
        var interfaces = arguments.List("--interfaces");
        if (interfaces.Count != 1 || interfaces[0].Any(char.IsControl))
            throw new CliArgumentException("--flows requires one named --interfaces adapter.");
        var allPorts = arguments.Has("--all-ports");
        var ports = arguments.IntegerList("--ports", []);
        if (arguments.Has("--ports") == allPorts || !allPorts && ports.Count == 0 ||
            ports.Count > 64 || ports.Any(port => port is < 1 or > 65535))
            throw new CliArgumentException("Specify --ports with 1..64 ports in 1..65535, or --all-ports.");
        int? rdpPort = null;
        if (arguments.Has("--rdp-port"))
        {
            rdpPort = arguments.Integer("--rdp-port", 0);
            if (rdpPort is < 1 or > 65535 || !allPorts && !ports.Contains(rdpPort.Value))
                throw new CliArgumentException("--rdp-port requires a local TCP port from 1..65535 included in the capture.");
        }
        var instance = arguments.Has("--sql-instance") ? RequiredSqlInstance(arguments) : null;
        var json = arguments.Has("--json");
        var history = arguments.Has("--history");
        var diagnostics = json && history ? Console.Error : output;
        if (!IsElevated())
        {
            diagnostics.WriteLine("ERROR: flow monitoring requires an Administrator token.");
            return 1;
        }
        using var stop = new CancellationTokenSource();
        ConsoleCancelEventHandler cancel = (_, e) => { e.Cancel = true; stop.Cancel(); };
        Console.CancelKeyPress += cancel;
        try
        {
            HostFlowMonitor.Run(interfaces[0], ports, allPorts,
                snapshot =>
                {
                    var rdp = rdpPort is int port ? RdpFlowReport.Create(snapshot, port, RdpAuditReader.Read(snapshot.Timestamp)) : null;
                    var sql = instance is null ? null : SqlLoginAuditReader.Read(instance, snapshot.Timestamp);
                    WriteSnapshot(output, snapshot, json, rdp, sql);
                }, stop.Token, includeAllRows: json || rdpPort.HasValue, includeHistory: history);
            return 0;
        }
        catch (Exception ex) when (ex.GetBaseException() is DllNotFoundException or BadImageFormatException or EntryPointNotFoundException)
        {
            diagnostics.WriteLine("ERROR: a compatible Npcap installation is required for live flow monitoring.");
            return 1;
        }
        catch (Exception ex) when (ex is InvalidOperationException or SharpPcap.PcapException)
        {
            diagnostics.WriteLine($"ERROR: {ex.Message}");
            return 1;
        }
        catch (OperationCanceledException) when (stop.IsCancellationRequested) { return 0; }
        finally { Console.CancelKeyPress -= cancel; }
    }

    private static string RequiredSqlInstance(CliOptions arguments)
    {
        var name = arguments.Get("--sql-instance");
        if (!SqlLoginAuditReader.IsValidInstance(name))
            throw new CliArgumentException("--sql-instance requires MSSQLSERVER or a local instance name (1..16 characters, starting with a letter).");
        return name;
    }

    internal static int WriteStandaloneSqlAudit(TextWriter output, SqlLoginAuditWindow sql, bool json)
    {
        if (json) output.WriteLine(JsonSerializer.Serialize(sql));
        else WriteSqlAudit(output, sql);
        return sql.AuditStatus switch { "read" => 0, "limited" => 2, _ => 1 };
    }

    private static void WriteSqlAudit(TextWriter output, SqlLoginAuditWindow sql)
    {
        output.WriteLine($"{sql.WindowEnd:u}  {sql.Provider}  Application log: {sql.AuditStatus}  Login records: {sql.Events.Count}  Observed outcome: {sql.ObservedOutcome}  Flow attribution: {sql.FlowAttribution}");
        foreach (var item in sql.Events)
            output.WriteLine($"  {item.Timestamp:u}  {item.Outcome}  Event {item.EventId}  Application record {item.RecordId}");
    }

    private static void WriteRdpAudit(TextWriter output, RdpFlowReport report, IReadOnlyList<FlowRow> visible)
    {
        output.WriteLine($"Remote interactive logons on TCP {report.LocalPort} | Security log: {report.AuditStatus}");
        var endpoints = visible.Where(f => f.Protocol == "TCP").Select(f => (f.Local, f.Remote)).ToHashSet();
        foreach (var row in report.Flows.Where(f => endpoints.Contains((f.Local, f.Remote))))
        {
            output.WriteLine($"  {row.Local}  <->  {row.Remote}  {row.Outcome}");
            foreach (var match in row.Events)
                output.WriteLine($"    {match.Timestamp:u}  Event {match.EventId}  Security record {match.RecordId}");
        }
    }

    internal static void WriteSnapshot(TextWriter output, FlowSnapshot snapshot, bool json,
        RdpFlowReport? rdp = null, SqlLoginAuditWindow? sql = null)
    {
        if (json)
        {
            if (rdp is null && sql is null) output.WriteLine(JsonSerializer.Serialize(snapshot));
            else
            {
                var sections = new Dictionary<string, object> { ["Traffic"] = snapshot };
                if (rdp is not null) sections.Add("RdpAudit", rdp);
                if (sql is not null) sections.Add("SqlAudit", sql);
                output.WriteLine(JsonSerializer.Serialize(sections));
            }
            return;
        }
        var driver = snapshot.DriverDrops?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "unavailable";
        var visible = snapshot.Flows.Take(40).ToArray();
        output.WriteLine($"{snapshot.Timestamp:u}  {snapshot.Interface}  Showing {visible.Length}/{snapshot.ActiveFlows} flows");
        output.WriteLine($"Skipped packets: {snapshot.SkippedPackets}  Table capacity drops: {snapshot.CapacityDrops}  Driver drop counter: {driver}");
        if (snapshot.History is { } history)
        {
            output.WriteLine("UTC INTERVAL (START / END)  RECEIVED (B/s)  SENT (B/s)  COVERAGE");
            foreach (var interval in history.TakeLast(5))
            {
                var coverage = interval.GapReasons.Count == 0 ? interval.Coverage : $"gap ({string.Join(", ", interval.GapReasons)})";
                var rx = interval.ReceivedBytesPerSecond?.ToString("F1", System.Globalization.CultureInfo.InvariantCulture) ?? "--";
                var tx = interval.SentBytesPerSecond?.ToString("F1", System.Globalization.CultureInfo.InvariantCulture) ?? "--";
                output.WriteLine($"{interval.StartUtc:HH:mm:ss.fff} / {interval.EndUtc:HH:mm:ss.fff}  {rx,14}  {tx,10}  {coverage}");
            }
        }
        output.WriteLine("UTC LAST SEEN  PROTO  INITIATOR  RECEIVED (B)  SENT (B)  LOCAL  <->  REMOTE");
        foreach (var flow in visible)
            output.WriteLine($"{flow.LastSeen.UtcDateTime:HH:mm:ss}       {flow.Protocol,-5}  {flow.Initiator,-8}  {flow.ReceivedBytes,12}  {flow.SentBytes,8}  {flow.Local}  <->  {flow.Remote}");
        output.WriteLine();
        if (rdp is not null) WriteRdpAudit(output, rdp, visible);
        if (sql is not null) WriteSqlAudit(output, sql);
    }

    /// <summary>
    /// Whether the current process is running with an Administrator token.
    /// </summary>
    private static bool IsElevated()
    {
        try
        {
            var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }
}
