using System.Security.Principal;
using System.ServiceProcess;
using WPShield.NetworkFilter;

namespace WPShield.Cli;

internal static class NetworkFilterCommand
{
    public const string Help = """
        wpshield network-filter

        --mode <Monitor|Block>   Monitor reports proposed blocks. Block enforces them host-wide with WFP.
        --allow <addresses>      Comma-separated addresses or CIDRs. Required for Block. Include your RDP client.
        --block <addresses>      Comma-separated addresses or CIDRs (/16 or longer for IPv4, /48 or longer for IPv6).
        --block-ttl-minutes <n>  Dynamic block lifetime. Default 60, allowed range 1 to 10080.
        --max-blocks <n>         Block capacity. Default 1000, allowed range 1 to 10000.
        --output <file.jsonl>    Append events in the gateway's JSON Lines envelope.
        --check                  Probe WFP with the current Windows identity and exit.
        --service-check-output <absolute-file>  Run --check under the WPShield service in a lab VM.

        Block runs until Ctrl+C. Closing the process removes its dynamic filters. Inspect them with
        'netsh wfp show filters'. --check and Block need WFP access (typically an elevated Administrator).
        """;

    private static readonly string[] KnownOptions =
    [
        "--mode", "--allow", "--block", "--block-ttl-minutes", "--max-blocks", "--output", "--check", "--service-check-output",
    ];

    public static int Run(CliOptions arguments, TextWriter output) => Run(arguments, output, WfpSession.Open, WaitForCtrlC);

    internal static int Run(CliOptions arguments, TextWriter output, Func<IWfpSession> openSession, Action waitForStop)
    {
        arguments.RejectUnknown(KnownOptions);
        arguments.RejectRepeated();
        var options = BuildOptions(arguments);

        if (arguments.Has("--service-check-output"))
        {
            var path = arguments.Get("--service-check-output");
            if (!arguments.Flag("--check") || path is null || !Path.IsPathFullyQualified(path))
            {
                throw new CliArgumentException("--service-check-output requires --check and an absolute file path.");
            }

            using var serviceCheck = new CheckService(path, options, openSession);
            ServiceBase.Run(serviceCheck);
            return serviceCheck.ExitCode;
        }

        if (arguments.Flag("--check"))
        {
            return Check(options, openSession, output);
        }

        using var sink = new NetworkFilterEventWriter(output, arguments.Get("--output"));
        using var service = new NetworkFilterService(options, openSession, sink);
        var outcome = service.Start();
        if (!outcome.Started)
        {
            output.WriteLine($"ERROR: {outcome.Refusal}");
            return 1;
        }

        if (options.Mode == NetworkFilterMode.Block)
        {
            output.WriteLine("Press Ctrl+C to stop and remove the dynamic filters.");
            waitForStop();
        }

        return 0;
    }

    private static NetworkFilterOptions BuildOptions(CliOptions arguments)
    {
        var modeText = arguments.Get("--mode", "Monitor");
        if (!string.Equals(modeText, "Monitor", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(modeText, "Block", StringComparison.OrdinalIgnoreCase))
        {
            throw new CliArgumentException("--mode must be Monitor or Block.");
        }

        var options = new NetworkFilterOptions
        {
            Mode = Enum.Parse<NetworkFilterMode>(modeText, ignoreCase: true),
            AllowList = ParseAll(arguments.List("--allow"), "--allow", IpRange.TryParseAllow, NetworkFilterOptions.MaximumAllowEntries),
            Blocks = ParseAll(arguments.List("--block"), "--block", IpRange.TryParseBlock, BlockSet.MaximumCapacity),
            DynamicBlockLifetime = TimeSpan.FromMinutes(arguments.Integer("--block-ttl-minutes", 60)),
            MaximumBlocks = arguments.Integer("--max-blocks", BlockSet.DefaultCapacity),
        };

        if (options.Validate() is { } invalid)
        {
            throw new CliArgumentException(invalid);
        }

        return options;
    }

    private delegate bool RangeParser(string? text, out IpRange? range, out string? error);

    private static List<IpRange> ParseAll(IReadOnlyList<string> values, string option, RangeParser parse, int limit)
    {
        if (values.Count > limit)
        {
            throw new CliArgumentException($"{option} supports at most {limit} entries.");
        }

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

    private static int Check(NetworkFilterOptions options, Func<IWfpSession> openSession, TextWriter output)
    {
        using var identity = WindowsIdentity.GetCurrent();
        output.WriteLine($"Windows identity: {identity.Name}");

        SelfTestReport report;
        try
        {
            using var session = openSession();
            report = NetworkFilterSelfTest.Run(session, options.AllowList);
        }
        catch (WfpException exception)
        {
            report = new SelfTestReport(false, exception.Message);
        }

        output.WriteLine($"{(report.Passed ? "PASS" : "FAIL")}: {report.Detail}");
        return report.Passed ? 0 : 1;
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

    private sealed class CheckService : ServiceBase
    {
        private readonly string _path;
        private readonly NetworkFilterOptions _options;
        private readonly Func<IWfpSession> _openSession;

        internal CheckService(string path, NetworkFilterOptions options, Func<IWfpSession> openSession)
        {
            ServiceName = "WPShield";
            AutoLog = false;
            _path = path;
            _options = options;
            _openSession = openSession;
        }

        protected override void OnStart(string[] args)
        {
            using var output = new StreamWriter(_path, append: false);
            using var identity = WindowsIdentity.GetCurrent();
            if (!string.Equals(identity.Name, @"NT SERVICE\WPShield", StringComparison.OrdinalIgnoreCase))
            {
                output.WriteLine($"FAIL: Expected the WPShield virtual service account; SCM launched {identity.Name}.");
                ExitCode = 1;
                return;
            }

            ExitCode = Check(_options, _openSession, output);
        }
    }
}
