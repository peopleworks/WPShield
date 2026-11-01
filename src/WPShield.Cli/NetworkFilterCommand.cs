using System.Globalization;
using System.Security.Principal;
using WPShield.NetworkFilter;

namespace WPShield.Cli;

/// <summary>
/// <c>wpshield network-filter</c>: observes new inbound TCP connections and, in Block mode, drops
/// packets from the addresses on its block list. See ADR 0006.
/// </summary>
/// <remarks>
/// <para>
/// Normal traffic never passes through this process. The observer receives copies of connection
/// attempts; blocks are WinDivert DROP filters the driver applies in the kernel. Stopping the command,
/// or the command dying, closes the handles and lifts every block: nothing is written to the Windows
/// Firewall, the registry or the disk, apart from the optional JSON Lines log.
/// </para>
/// <para>
/// Monitor is the default and never opens a DROP handle. Block refuses to start without an allow-list,
/// when an RDP client is not on it, or when the WinDivert self-test fails.
/// </para>
/// </remarks>
internal static class NetworkFilterCommand
{
    public const string Help = """
        wpshield network-filter - observe new inbound connections and, in Block mode, drop packets from
        the addresses on the block list. Normal traffic never passes through WPShield. See ADR 0006.

        Usage: wpshield network-filter [options]
          --mode <Monitor|Block>        Default Monitor: reports who would be blocked, drops nothing.
          --allow <addresses>           Comma-separated addresses or CIDR blocks that are never blocked.
                                        Required for Block. Include the address you administer from.
          --block <addresses>           Comma-separated addresses or CIDR blocks (no wider than /16 or
                                        IPv6 /48) to drop for as long as the command runs.
          --block-ttl-minutes <n>       How long a block added by a rule lasts. Default 60.
          --max-blocks <n>              Ceiling on the block set. Default 1000.
          --syn-rules-may-block         Let WP-NET-002 and WP-NET-003 add blocks. Off by default: their
                                        evidence is a SYN, whose source anyone can forge, so this lets
                                        a third party get any address not on the allow-list blocked.
          --max-connections-per-minute <n>    WP-NET-002 threshold per source. Default 60.
          --max-distinct-ports-per-minute <n> WP-NET-003 threshold per source. Default 20.
          --output <file.jsonl>         Also append every event as JSON Lines, in the gateway's envelope.
          --check                       Run the WinDivert self-test and exit. Opens no handle; needs
                                        WinDivert.dll but neither elevation nor the driver.
          --install-driver              Let WinDivert install its driver service if it is missing. An
                                        explicit, reversible change to this host: undo it with
                                        'sc stop WinDivert' and 'sc delete WinDivert'.

        Requires: WinDivert.dll and WinDivert64.sys from the official WinDivert 2.2.2 release, next to
        wpshield.exe. WPShield does not bundle or download them. Administrator elevation, except --check.

        What it never does: reinject or delay a packet, write a Windows Firewall rule, persist a block,
        install a driver unless --install-driver is given, or touch IIS.

        Stop it with Ctrl+C. Stopping lifts every block at once.

        Exit codes:
          0   stopped cleanly, or --check passed
          1   an argument was wrong, a refusal (allow-list, RDP client, self-test), WinDivert missing,
              or elevation absent
        """;

    private static readonly string[] KnownOptions =
    [
        "--mode", "--allow", "--block", "--block-ttl-minutes", "--max-blocks", "--syn-rules-may-block",
        "--max-connections-per-minute", "--max-distinct-ports-per-minute", "--output", "--check",
        "--install-driver",
    ];

    public static int Run(CliOptions arguments, TextWriter output) =>
        Run(arguments, output, static mayInstall => new WinDivertDriver(mayInstall), IsElevated, WaitForCtrlC);

    internal static int Run(
        CliOptions arguments,
        TextWriter output,
        Func<bool, IDivertDriver> createDriver,
        Func<bool> isElevated,
        Action waitForStop)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(createDriver);
        ArgumentNullException.ThrowIfNull(isElevated);
        ArgumentNullException.ThrowIfNull(waitForStop);

        arguments.RejectUnknown(KnownOptions);
        arguments.RejectRepeated(KnownOptions);
        var options = BuildOptions(arguments);

        if (arguments.Flag("--check"))
        {
            return Check(options, createDriver(false), output);
        }

        if (!isElevated())
        {
            output.WriteLine("ERROR: network-filter needs Administrator elevation (only --check does not).");
            return 1;
        }

        using var sink = new NetworkFilterEventWriter(output, arguments.Get("--output"));
        using var service = new NetworkFilterService(options, createDriver(arguments.Flag("--install-driver")), sink);
        var outcome = service.Start();
        if (!outcome.Started)
        {
            output.WriteLine($"ERROR: {outcome.Refusal}");
            return 1;
        }

        output.WriteLine(string.Create(
            CultureInfo.InvariantCulture,
            $"Network filter running in {options.Mode} mode. Allow-list: {Describe(options.AllowList)}. Operator blocks: {Describe(options.Blocks)}."));
        output.WriteLine(options.Mode == NetworkFilterMode.Monitor
            ? "Monitor mode drops nothing; it reports who would be blocked. Press Ctrl+C to stop."
            : "Press Ctrl+C to stop. Stopping lifts every block.");

        waitForStop();
        service.Stop();
        return 0;
    }

    internal static NetworkFilterOptions BuildOptions(CliOptions arguments)
    {
        var modeText = arguments.Get("--mode", "Monitor");
        if (!Enum.TryParse<NetworkFilterMode>(modeText, ignoreCase: true, out var mode) || !Enum.IsDefined(mode))
        {
            throw new CliArgumentException($"--mode must be Monitor or Block. It was '{modeText}'.");
        }

        var options = new NetworkFilterOptions
        {
            Mode = mode,
            AllowList = ParseAll(arguments.List("--allow"), "--allow", IpRange.TryParseAllow),
            Blocks = ParseAll(arguments.List("--block"), "--block", IpRange.TryParseBlock),
            DynamicBlockLifetime = TimeSpan.FromMinutes(arguments.Integer("--block-ttl-minutes", 60)),
            MaximumBlocks = arguments.Integer("--max-blocks", BlockSet.DefaultCapacity),
            SynRulesMayBlock = arguments.Flag("--syn-rules-may-block"),
            MaxConnectionsPerMinute = arguments.Integer("--max-connections-per-minute", WPShield.NetworkFilter.Rules.RateLimitRule.DefaultThreshold),
            MaxDistinctPortsPerMinute = arguments.Integer("--max-distinct-ports-per-minute", WPShield.NetworkFilter.Rules.PortScanRule.DefaultThreshold),
        };

        var invalid = options.Validate();
        if (invalid is not null)
        {
            throw new CliArgumentException(invalid);
        }

        return options;
    }

    private delegate bool RangeParser(string? text, out IpRange? range, out string? error);

    private static List<IpRange> ParseAll(IReadOnlyList<string> values, string option, RangeParser parse)
    {
        var ranges = new List<IpRange>(values.Count);
        foreach (var value in values)
        {
            if (!parse(value, out var range, out var error))
            {
                throw new CliArgumentException($"{option}: {error}.");
            }

            ranges.Add(range!);
        }

        return ranges;
    }

    private static int Check(NetworkFilterOptions options, IDivertDriver driver, TextWriter output)
    {
        SelfTestReport report;
        try
        {
            report = NetworkFilterSelfTest.Run(driver, options.AllowList, options.Blocks);
        }
        catch (DivertDriverException exception)
        {
            output.WriteLine($"ERROR: {exception.Message}");
            return 1;
        }

        foreach (var check in report.Checks)
        {
            output.WriteLine(check.Passed
                ? $"  PASS  {check.Name}"
                : $"  FAIL  {check.Name} - {check.Detail}");
        }

        var failed = report.Failures.Count();
        output.WriteLine(failed == 0
            ? string.Create(CultureInfo.InvariantCulture, $"Self-test passed: {report.Checks.Count} checks. WinDivert evaluates WPShield's filters as intended.")
            : string.Create(CultureInfo.InvariantCulture, $"Self-test FAILED: {failed} of {report.Checks.Count} checks. Block mode will refuse to start."));
        return failed == 0 ? 0 : 1;
    }

    private static string Describe(IReadOnlyList<IpRange> ranges) =>
        ranges.Count == 0 ? "none" : string.Join(", ", ranges);

    private static bool IsElevated()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static void WaitForCtrlC()
    {
        using var stop = new ManualResetEventSlim();
        void OnCancel(object? sender, ConsoleCancelEventArgs e)
        {
            e.Cancel = true;
            stop.Set();
        }

        Console.CancelKeyPress += OnCancel;
        try
        {
            stop.Wait();
        }
        finally
        {
            Console.CancelKeyPress -= OnCancel;
        }
    }
}
