using System.Security.Principal;
using System.Threading;
using WPShield.Abstractions;
using WPShield.SecurityMonitor;
using WPShield.SecurityMonitor.Rules;

namespace WPShield.Cli;

/// <summary>
/// <c>wpshield security-monitor</c> — read-only Windows Security event log monitor.
/// </summary>
/// <remarks>
/// <para>
/// This is the operator entry point for WPShield.SecurityMonitor. It reads Event ID 4624
/// (logon success) and 4625 (logon failure) from the Security event log, evaluates them
/// against the RDP brute-force and failed-logon rules, and publishes findings to the console
/// as JSON Lines. It never modifies, clears, or archives the Security log.
/// </para>
/// <para>
/// <b>Elevation is required.</b> Reading the Security log needs an Administrator token. The
/// command refuses to start without it, rather than degrading silently into a monitor that sees
/// nothing.
/// </para>
/// <para>
/// By default it scans once and exits. Pass <c>--watch</c> to rescan on an interval and keep
/// the process running until Ctrl+C.
/// </para>
/// <para>
/// Nothing here modifies IIS. It observes authentication events; it does not put WPShield in
/// the traffic path.
/// </para>
/// </remarks>
internal static class SecurityMonitorCommand
{
    public const string Help = """
        wpshield security-monitor - read-only Windows Security event log monitor. Prints findings as JSON Lines.

        Usage: wpshield security-monitor [options]

          --log-name <string>      Windows event log name. Default: Security.
          --event-ids <numbers>    Comma-separated event IDs. Default: 4624,4625.
          --max-failed-logons <n>  Max failed logons from one IP per window before a finding.
                                   Default: 5.
          --window-minutes <n>     Sliding window in minutes for failure counting. Default: 5.
          --allow-list <ips>       Comma-separated source IPs to never flag. Default: none.
          --watch                  Rescan on an interval until Ctrl+C. Default: scan once and exit.
          --interval-seconds <n>   Seconds between scans when --watch is used. Default: 30.
          --output <file>          JSON Lines output file. Default: stdout.

        What it shows: one JSON line per finding with rule ID, score, action, source IP, user
        name, logon type, event ID, and timestamp. Only findings with Action of Observe or Block
        are emitted.

        What it does NOT do: modify the Security log, block packets directly, install anything,
        or touch IIS. To block offending IPs at the packet layer, pair this with
        'wpshield network-filter' and the WPShield.Integration bridge.

        Exit codes:
          0   stopped cleanly
          1   an argument was wrong, or elevation is absent
        """;

    private static readonly string[] KnownOptions =
    [
        "--log-name", "--event-ids", "--max-failed-logons", "--window-minutes",
        "--allow-list", "--watch", "--interval-seconds", "--output"
    ];

    public static int Run(CliOptions arguments, TextWriter output)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        ArgumentNullException.ThrowIfNull(output);

        arguments.RejectUnknown(KnownOptions);

        if (!IsElevated())
        {
            output.WriteLine("ERROR: security-monitor requires an Administrator elevation.");
            output.WriteLine("       Run the command from an elevated command prompt or PowerShell.");
            return 1;
        }

        var logName = arguments.Get("--log-name") ?? "Security";
        var eventIds = arguments.IntegerList("--event-ids", new List<int> { 4624, 4625 });
        var maxFailedLogons = arguments.Integer("--max-failed-logons", 5);
        var windowMinutes = arguments.Integer("--window-minutes", 5);
        var allowList = arguments.List("--allow-list");
        var watch = arguments.Flag("--watch");
        var intervalSeconds = arguments.Integer("--interval-seconds", 30);
        var outputPath = arguments.Get("--output");

        var configuration = new SecurityEventConfiguration
        {
            LogName = logName,
            EventIds = eventIds,
            RemoteLogonTypes = new List<string> { "10" },
            MaxFailedLogonsPerWindow = maxFailedLogons,
            WindowMinutes = windowMinutes,
            AllowList = allowList,
            PublishingEnabled = true
        };

        var rules = new List<ISecurityInspectionRule>
        {
            new RdpBruteForceRule(maxFailedLogons, windowMinutes),
            new FailedLogonRule(maxFailedLogons * 2, windowMinutes * 2)
        };

        ISecurityEventSink sink = new ConsoleSecurityEventSink(output, outputPath);

        try
        {
            using var monitor = SecurityEventBuilder.Build(configuration, rules, sink);

            if (!watch)
            {
                int processed = monitor.ScanOnce();
                output.WriteLine($"Security monitor scanned {processed} event(s). Findings written above.");
                return 0;
            }

            output.WriteLine($"Security monitor watching {logName} every {intervalSeconds}s. Press Ctrl+C to stop.");
            output.WriteLine($"  Max failed logons per {windowMinutes} min: {maxFailedLogons}");
            if (allowList.Count > 0)
            {
                output.WriteLine($"  Allow list: {string.Join(", ", allowList)}");
            }

            var stopping = new ManualResetEventSlim();
            var cts = new CancellationTokenSource();
            Console.CancelKeyPress += (_, e) =>
            {
                e.Cancel = true;
                stopping.Set();
                cts.Cancel();
            };

            while (!stopping.Wait(TimeSpan.FromSeconds(intervalSeconds)))
            {
                int processed = monitor.ScanOnce();
                if (processed > 0)
                {
                    output.WriteLine($"  Scanned {processed} event(s) at {DateTimeOffset.Now:yyyy-MM-ddTHH:mm:ssZ}.");
                }
            }

            output.WriteLine("Security monitor stopped.");
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

    /// <summary>
    /// Sink that writes security findings as JSON Lines to stdout or a file.
    /// </summary>
    private sealed class ConsoleSecurityEventSink : ISecurityEventSink, IDisposable
    {
        private readonly TextWriter _output;
        private readonly TextWriter? _file;
        private bool _disposed;

        public ConsoleSecurityEventSink(TextWriter output, string? outputPath)
        {
            _output = output;
            _file = string.IsNullOrWhiteSpace(outputPath) ? null : new StreamWriter(outputPath, append: true)
            {
                AutoFlush = true
            };
        }

        public void Publish(
            WPShield.Abstractions.SecurityInspectionResult finding,
            WPShield.Abstractions.SecurityInspectionContext context)
        {
            if (finding.Action != NetworkInspectionAction.Block &&
                finding.Action != NetworkInspectionAction.Observe)
            {
                return;
            }

            var line = $$"""
                {
                  "timestamp": "{{context.TimeCreated:yyyy-MM-ddTHH:mm:ss.fffZ}}",
                  "level": "Information",
                  "category": "WPShield.SecurityMonitor",
                  "message": "{{finding.MessageKey}}",
                  "state": "{{finding.Action}}",
                  "ruleId": "{{finding.RuleId}}",
                  "score": {{finding.Score}},
                  "eventId": {{context.EventId}},
                  "sourceIp": "{{context.SourceIp}}",
                  "userName": "{{context.UserName}}",
                  "logonType": "{{context.LogonType}}",
                  "computerName": "{{context.ComputerName}}",
                  "evidence": {{SerializeEvidence(finding.Evidence)}}
                }
                """;

            _output.WriteLine(line);
            _file?.WriteLine(line);
        }

        private static string SerializeEvidence(IReadOnlyDictionary<string, object> evidence)
        {
            if (evidence.Count == 0)
            {
                return "{}";
            }

            var pairs = new List<string>();
            foreach (var kvp in evidence)
            {
                var value = kvp.Value switch
                {
                    string s => $"\"{EscapeJsonString(s)}\"",
                    int i => i.ToString(),
                    bool b => b ? "true" : "false",
                    _ => $"\"{EscapeJsonString(kvp.Value.ToString() ?? string.Empty)}\""
                };
                pairs.Add($"\"{EscapeJsonString(kvp.Key)}\": {value}");
            }

            return $"{{{string.Join(", ", pairs)}}}";
        }

        private static string EscapeJsonString(string s) =>
            s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\r", "\\r");

        public void Dispose()
        {
            if (!_disposed)
            {
                _file?.Dispose();
                _disposed = true;
            }
        }
    }
}
