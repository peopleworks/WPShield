using System.Security.Principal;
using System.Threading;
using WPShield.Abstractions;
using WPShield.NetworkFilter;
using WPShield.NetworkFilter.Rules;

namespace WPShield.Cli;

/// <summary>
/// <c>wpshield network-filter</c> — user-mode inbound packet filter built on WinDivert.
/// </summary>
/// <remarks>
/// <para>
/// This is the operator entry point for WPShield.NetworkFilter. It starts a read-write packet
/// filter on the WinDivert handle named in <c>--filter</c> (default <c>tcp.Inbound</c>),
/// evaluates each intercepted packet against the rate-limit, block-list and port-scan rules,
/// drops packets that match a blocking rule, and reinjects all others.
/// </para>
/// <para>
/// <b>Design constraint inherited from the Malwarebytes mwac.sys failure:</b> this command never
/// runs in kernel, never acquires a kernel spinlock on the packet path, and enforces a strict
/// per-packet inspection budget (default 5 ms). If a rule takes longer, the packet is forwarded
/// uninspected rather than risking a DPC watchdog violation that reboots the server.
/// </para>
/// <para>
/// <b>WinDivert is an external dependency.</b> The operator installs the WinDivert runtime
/// explicitly; this command does not download or install it. <c>WinDivertOpen</c> fails with a
/// clear message if the driver is absent.
/// </para>
/// <para>
/// <b>Nothing here modifies IIS.</b> No bindings, no rewrite rules, no application pools. The
/// command drops attack traffic before it reaches IIS.
/// </para>
/// <para>
/// Stop it with Ctrl+C. Nothing on this machine is changed by running it except the packets
/// that match a blocking rule.
/// </para>
/// </remarks>
internal static class NetworkFilterCommand
{
    public const string Help = """
        wpshield network-filter - user-mode inbound packet filter via WinDivert. Drops attack traffic before IIS.

        Usage: wpshield network-filter [options]

          --filter <string>            WinDivert filter string. Default: tcp.Inbound.
          --max-inspection-time-ms <n> Max milliseconds to inspect one packet before forwarding
                                       it uninspected. Default: 5.
          --max-connections-per-minute <n> Rate-limit threshold per source IP per minute.
                                       Default: 60.
          --max-distinct-ports-per-minute <n> Port-scan threshold per source IP per minute.
                                       Default: 20.
          --block-list <ips>           Comma-separated source IPs to always block.
                                       Default: none.

        What it shows: one line per blocked packet with timestamp, source IP, destination port,
        rule ID, score and action. All other packets are reinjected to continue to IIS.

        What it does NOT do: run in kernel, acquire kernel spinlocks, modify IIS, install
        WinDivert, or capture outbound traffic. WinDivert must be installed separately by the
        operator; this command does not download or install it.

        Stop it with Ctrl+C. Blocked packets are dropped; everything else continues to IIS.

        Exit codes:
          0   stopped cleanly
          1   an argument was wrong, WinDivert is missing, or elevation is absent
        """;

    private static readonly string[] KnownOptions =
    [
        "--filter", "--max-inspection-time-ms", "--max-connections-per-minute",
        "--max-distinct-ports-per-minute", "--block-list"
    ];

    public static int Run(CliOptions arguments, TextWriter output)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(output);

        arguments.RejectUnknown(KnownOptions);

        if (!IsElevated())
        {
            output.WriteLine("ERROR: network-filter requires an Administrator elevation.");
            output.WriteLine("       Run the command from an elevated command prompt or PowerShell.");
            return 1;
        }

        var filter = arguments.Get("--filter") ?? "tcp.Inbound";
        var maxInspectionTimeMs = arguments.Integer("--max-inspection-time-ms", 5);
        var maxConnectionsPerMinute = arguments.Integer("--max-connections-per-minute", 60);
        var maxDistinctPortsPerMinute = arguments.Integer("--max-distinct-ports-per-minute", 20);
        var blockList = arguments.List("--block-list");

        var configuration = new NetworkFilterConfiguration
        {
            Filter = filter,
            MaxInspectionTime = TimeSpan.FromMilliseconds(maxInspectionTimeMs),
            MaxConnectionsPerMinute = maxConnectionsPerMinute,
            MaxDistinctPortsPerMinute = maxDistinctPortsPerMinute,
            BlockList = blockList
        };

        try
        {
            var rules = new List<INetworkInspectionRule>
            {
                new BlockListRule(configuration.BlockList),
                new RateLimitRule(configuration.MaxConnectionsPerMinute),
                new PortScanRule(configuration.MaxDistinctPortsPerMinute)
            };

            using var engine = new NetworkFilterEngine(
                rules,
                configuration.Filter,
                configuration.MaxInspectionTime);

            var started = new ManualResetEventSlim();
            var stopping = new ManualResetEventSlim();

            output.WriteLine($"Network filter running. Filter: {configuration.Filter}");
            output.WriteLine($"  Max inspection time: {configuration.MaxInspectionTime.TotalMilliseconds} ms");
            output.WriteLine($"  Max connections/minute: {configuration.MaxConnectionsPerMinute}");
            output.WriteLine($"  Max distinct ports/minute: {configuration.MaxDistinctPortsPerMinute}");
            if (blockList.Count > 0)
            {
                output.WriteLine($"  Block list: {string.Join(", ", blockList)}");
            }
            output.WriteLine("Press Ctrl+C to stop. Nothing is written to IIS.");

            var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (_, e) =>
            {
                e.Cancel = true;
                stopping.Set();
                cts.Cancel();
            };

            // Run the capture loop until cancelled. The engine logs blocked packets to stdout.
            engine.Run(cts.Token);

            stopping.Wait();
            output.WriteLine("Network filter stopped.");
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
