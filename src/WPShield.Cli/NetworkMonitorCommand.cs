using System.Security.Principal;
using System.Threading;
using WPShield.NetworkSensor;

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
        wpshield network-monitor - live passive capture of HTTP metadata on named ports. Reads only.

        Usage: wpshield network-monitor [options]

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

        What it shows: one JSON line per observed HTTP request or response, with timestamp, source
        and destination IP/port, method, path (query string stripped), status code, body size, and
        TLS flag. Nothing else - no bodies, no credentials, no cookies, no query strings.

        What it does NOT do: block traffic, modify IIS, install Npcap, or capture in promiscuous
        mode unless --promiscuous is passed. Npcap must be installed separately by the operator;
        this command does not download or install it.

        Stop it with Ctrl+C. Nothing on this machine is changed by running it.

        Exit codes:
          0   stopped cleanly
          1   an argument was wrong, Npcap is missing, or elevation is absent
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
