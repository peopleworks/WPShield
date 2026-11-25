using System.Globalization;
using System.Net;
using Microsoft.Data.Sqlite;
using WPShield.Analyst;
using WPShield.Cli.Analyst;
using WPShield.Cli.Mcp;
using WPShield.Evidence;

namespace WPShield.Cli;

/// <summary>What <c>wpshield analyst</c> reads from the machine, replaceable in tests.</summary>
/// <param name="Environment">Reads an environment variable of this process: the only place a key comes from.</param>
/// <param name="MachineScoped">Whether a variable is also set for the whole machine, where every process can read it.</param>
/// <param name="Providers">Builds the provider for a configuration and its key.</param>
internal sealed record AnalystHost(
    string DefaultStore,
    Func<bool> Elevated,
    Func<string, string?> Environment,
    Func<string, bool> MachineScoped,
    TimeProvider Clock,
    Func<AnalystConfiguration, string, IAnalystProvider> Providers)
{
    /// <summary>The run's time bound; tests shorten it.</summary>
    public TimeSpan Timeout { get; init; } = AnalystRunner.RunTimeout;

    public static AnalystHost System { get; } = new(
        EvidenceStore.DefaultPath,
        EvidenceAccess.IsElevated,
        global::System.Environment.GetEnvironmentVariable,
        name => !string.IsNullOrEmpty(global::System.Environment.GetEnvironmentVariable(name, EnvironmentVariableTarget.Machine)),
        TimeProvider.System,
        DefaultProvider);

    internal static IAnalystProvider DefaultProvider(AnalystConfiguration configuration, string key) => configuration.Provider switch
    {
        "anthropic" => MessagesProvider.Anthropic(key, configuration.Model, configuration.Effort),
        "relay" => MessagesProvider.Relay(key, configuration.RelayUrl!, configuration.Model, configuration.Effort),
        _ => throw new InvalidOperationException("No provider is chosen.")
    };
}

/// <summary>
/// <c>wpshield analyst</c> - the optional AI analyst (ADR 0010): it reads the evidence store through the
/// MCP server's read-only tools and writes a report for the operator. It never acts.
/// </summary>
/// <remarks>
/// <para>
/// <b>Nothing leaves the host</b> until <c>analyst.enabled</c> is true, <c>analyst.provider</c> names a
/// provider and that provider's key is in this account's environment. The key is read from
/// <c>ANTHROPIC_API_KEY</c> or <c>RELAY_API_KEY</c> and nowhere else - never a setting, an argument or a
/// file - and every provider message is scrubbed of it before it is shown or stored.
/// </para>
/// <para>
/// <b>A person starts every run.</b> This command is the only way in; nothing event-driven calls it, and
/// a scheduled digest exists only if the operator creates the scheduled task by hand.
/// </para>
/// </remarks>
internal static class AnalystCommand
{
    public const string Help = """
        wpshield analyst - an optional AI analyst over the evidence store (ADR 0010). It reads, explains
        and recommends; it never blocks, unblocks or changes a setting.

        Usage:
          wpshield analyst status                     settings, key present (yes/no), today's usage, and
                                                      what leaves this host for the chosen provider
          wpshield analyst test                       check the provider and the key without a model call
                                                      where the provider allows it (Relay: whoami)
          wpshield analyst digest [--since 24h]       what happened, what changed, what matters, the gaps
          wpshield analyst investigate <ip|network>   one source in depth, such as 203.0.113.7 or 203.0.113.0/24
          wpshield analyst ask "<question>"           an answer to your question from the evidence
          wpshield analyst reports [--last 20]        the latest stored reports, newest first
          wpshield analyst show <id>                  one stored report

          Every form takes --store <path> (the evidence store). digest, investigate and ask take
          --simulated: the whole loop against the real tools with a scripted provider that sends nothing.

        Off by default. Before a run: an elevated prompt, and
          wpshield settings set analyst.provider anthropic --reason "..."   (or relay, with analyst.relay_url)
          wpshield settings set analyst.enabled true --reason "..."
          the key in this account's environment: ANTHROPIC_API_KEY or RELAY_API_KEY (see the docs for
          setting it with Read-Host -AsSecureString). Never on the command line, never in a file.

        Bounds: 12 tool calls, 16,000 output tokens per turn and 5 minutes per run; Ctrl+C cancels.
        analyst.daily_runs (10) and analyst.daily_input_tokens (2,000,000) per UTC day. A run past a
        bound is refused or stopped, and says which bound; it never becomes a smaller analysis.

        Reports go to wpshield-analyst.db beside the evidence store, 90 days and 1,000 reports at most.
        Every report is an opinion, not evidence.

        Exit codes:
          0   done; for a run, the report is complete
          1   an argument was wrong, the analyst is off or has no key, a budget refused the run, the
              provider check failed, or the store could not be opened (not elevated)
          2   the run ended without a complete analysis (declined, stopped by a bound, cut off, timed
              out, cancelled or failed), or a store cannot be read by this build
          3   there is no evidence store
        """;

    private static readonly string[] ValueOptions = ["--store", "--since", "--last"];
    private static readonly string[] Ranges = ["1h", "6h", "24h", "7d", "30d", "90d"];

    public static int Run(IReadOnlyList<string> args, TextWriter output, TextWriter error) =>
        Run(args, output, error, AnalystHost.System, CancellationToken.None);

    internal static int Run(IReadOnlyList<string> args, TextWriter output, TextWriter error, AnalystHost host, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(output);
        ArgumentNullException.ThrowIfNull(error);
        ArgumentNullException.ThrowIfNull(host);

        var (positionals, options) = Split(args);
        options.RejectRepeated();
        var verb = positionals.Count > 0 ? positionals[0].Trim().ToLowerInvariant() : "status";
        var path = AttacksCommand.StorePath(options, host.DefaultStore);
        string? key = null;
        try
        {
            return verb switch
            {
                "status" => Status(positionals, options, output, error, host, path),
                "test" => Test(positionals, options, output, error, host, path, token, k => key = k),
                "digest" or "investigate" or "ask" => Analyse(verb, positionals, options, output, error, host, path, token, k => key = k),
                "reports" => Reports(positionals, options, output, error, host, path),
                "show" => Show(positionals, options, output, error, host, path),
                _ => throw new CliArgumentException(
                    $"Unknown analyst action '{NetworkMonitorCommand.ConsoleLabel(verb)}'. Use status, test, digest, investigate, ask, reports or show.")
            };
        }
        catch (EvidenceAccessException ex)
        {
            error.WriteLine("ERROR: " + ex.Message);
            return ex.ExitCode;
        }
        catch (CliArgumentException)
        {
            throw;
        }
        catch (Exception ex)
        {
            // One choke point for everything else: the message may carry provider text, so it is scrubbed
            // of the key before it reaches the console, and only this command's own words are added.
            error.WriteLine($"ERROR: the analyst failed ({ex.GetType().Name}): {SecretScrubber.Scrub(ex.Message, key, 400)}");
            return 2;
        }
    }

    // ---------------------------------------------------------------------------------------------
    //  Verbs
    // ---------------------------------------------------------------------------------------------

    private static int Status(List<string> positionals, CliOptions options, TextWriter output, TextWriter error, AnalystHost host, string path)
    {
        options.RejectUnknown("--store");
        Positionals(positionals, 1, "analyst status takes no argument.");
        using var evidence = EvidenceAccess.OpenReadOnly(path, host.Elevated());
        var settings = new EvidenceSettings(evidence);
        var configuration = AnalystConfiguration.Read(settings);
        var detailed = DetailedRecords(settings);
        var variable = ProviderDisclosure.KeyVariable(configuration.Provider);
        var usage = Usage(path, host.Clock.GetUtcNow());

        output.WriteLine("WPShield analyst (ADR 0010). It reads and recommends; it never acts.");
        output.WriteLine($"  Enabled          {(configuration.Enabled ? "yes" : "no (analyst.enabled is false: nothing leaves this host)")}");
        output.WriteLine($"  Provider         {(configuration.Provider.Length == 0 ? "none chosen (analyst.provider)" : configuration.Provider)}");
        output.WriteLine($"  Model            {configuration.Model}, effort {configuration.Effort}");
        output.WriteLine($"  Language         {configuration.Language}");
        if (configuration.Provider == "relay")
            output.WriteLine($"  Relay            {configuration.RelayUrl?.ToString() ?? "not set (analyst.relay_url): a run is refused"}");
        if (variable is not null)
        {
            var present = !string.IsNullOrEmpty(host.Environment(variable));
            output.WriteLine($"  Key              {variable} present: {(present ? "yes" : "no")}");
            if (present && host.MachineScoped(variable))
                output.WriteLine($"                   WARNING: {variable} is also set for the whole machine, where every process on this host can read it. Keep it in the user scope only.");
        }
        output.WriteLine($"  Today (UTC)      {usage.Runs} of {configuration.DailyRuns} runs; {usage.InputTokens.ToString("N0", CultureInfo.InvariantCulture)} of " +
            $"{configuration.DailyInputTokens.ToString("N0", CultureInfo.InvariantCulture)} input tokens on a provider you pay");
        output.WriteLine($"  Reports          {AnalystReportStore.PathBeside(path)}");
        output.WriteLine();
        foreach (var line in ProviderDisclosure.Lines(configuration.Provider, configuration.RelayUrl, detailed, configuration.Spanish))
            output.WriteLine(line);
        var blocker = Blocker(configuration, host);
        if (blocker is not null)
        {
            output.WriteLine();
            output.WriteLine("A run would be refused now: " + blocker);
        }
        return 0;
    }

    private static int Test(List<string> positionals, CliOptions options, TextWriter output, TextWriter error, AnalystHost host, string path,
        CancellationToken token, Action<string> keyRead)
    {
        options.RejectUnknown("--store");
        Positionals(positionals, 1, "analyst test takes no argument.");
        AnalystConfiguration configuration;
        using (var evidence = EvidenceAccess.OpenReadOnly(path, host.Elevated()))
            configuration = AnalystConfiguration.Read(new EvidenceSettings(evidence));
        if (Blocker(configuration, host) is { } blocker)
        {
            error.WriteLine("ERROR: " + blocker);
            return 1;
        }
        var key = host.Environment(ProviderDisclosure.KeyVariable(configuration.Provider)!)!;
        keyRead(key);
        var provider = host.Providers(configuration, key);
        try
        {
            using var cancel = new CtrlC(token);
            cancel.CancelAfter(TimeSpan.FromSeconds(60));
            var check = provider.TestAsync(cancel.Token).GetAwaiter().GetResult();
            output.WriteLine($"{provider.Name}: {SecretScrubber.Scrub(check.Summary, key, 400)}");
            foreach (var (label, value) in check.Details)
                output.WriteLine($"  {label,-20} {SecretScrubber.Scrub(value, key, 200)}");
            if (check.Ok && provider.Name == "relay")
                output.WriteLine("Check that this is the project you meant: a token of another project would still be answered.");
            return check.Ok ? 0 : 1;
        }
        finally
        {
            (provider as IDisposable)?.Dispose();
        }
    }

    private static int Analyse(string verb, List<string> positionals, CliOptions options, TextWriter output, TextWriter error, AnalystHost host,
        string path, CancellationToken token, Action<string> keyRead)
    {
        var simulated = options.Has("--simulated");
        if (options.Get("--simulated") is not null) throw new CliArgumentException("--simulated takes no value.");
        var (role, subject, question) = Request(verb, positionals, options);

        AnalystConfiguration configuration;
        using (var evidence = EvidenceAccess.OpenReadOnly(path, host.Elevated()))
            configuration = AnalystConfiguration.Read(new EvidenceSettings(evidence));

        IAnalystProvider provider;
        string? key = null;
        if (simulated)
        {
            provider = SimulatedProvider.Demonstration(role == AnalystRole.Digest ? subject! : "7d");
            configuration = configuration with { Model = SimulatedProvider.ModelName };
        }
        else
        {
            if (Blocker(configuration, host) is { } blocker)
            {
                error.WriteLine("ERROR: " + blocker);
                return 1;
            }
            key = host.Environment(ProviderDisclosure.KeyVariable(configuration.Provider)!)!;
            keyRead(key);
            provider = host.Providers(configuration, key);
        }

        try
        {
            using var reports = OpenReports(path);
            using var access = new McpEvidenceAccess(path);
            var tools = McpAnalystTools.Create(new EvidenceTools(access, host.Clock));
            output.WriteLine(simulated
                ? "Simulated run: a scripted provider, nothing leaves this host."
                : $"Sending to {provider.Name} ({configuration.Model}): the analyst's instructions, your request and every tool result the model asks for. 'wpshield analyst status' lists what that includes.");
            var runner = new AnalystRunner(provider, tools, reports, host.Clock)
            {
                Timeout = host.Timeout,
                OnToolCall = call => output.WriteLine($"  reading {call.Name} {SecretScrubber.Scrub(call.Arguments.ToJsonString(), key, 200)}")
            };
            long id;
            using (var cancel = new CtrlC(token))
            {
                try
                {
                    id = runner.RunAsync(new AnalystRunRequest(role, subject, question, configuration), cancel.Token).GetAwaiter().GetResult();
                }
                catch (AnalystBudgetException ex)
                {
                    error.WriteLine("ERROR: " + ex.Message);
                    return 1;
                }
            }
            var report = reports.Get(id)!;
            output.WriteLine();
            ReportRenderer.Render(report, output);
            return report.Status == ReportStatus.Completed ? 0 : 2;
        }
        finally
        {
            (provider as IDisposable)?.Dispose();
        }
    }

    private static int Reports(List<string> positionals, CliOptions options, TextWriter output, TextWriter error, AnalystHost host, string path)
    {
        options.RejectUnknown("--store", "--last");
        Positionals(positionals, 1, "analyst reports takes no argument; use --last N.");
        var last = options.Integer("--last", 20);
        if (last is < 1 or > 100) throw new CliArgumentException("--last must be a number from 1 to 100.");
        AnalystConfiguration configuration;
        using (var evidence = EvidenceAccess.OpenReadOnly(path, host.Elevated()))
            configuration = AnalystConfiguration.Read(new EvidenceSettings(evidence));
        using var reports = OpenReportsReadOnly(path);
        output.WriteLine(ReportRenderer.Label(configuration.Spanish));
        var list = reports?.Recent(last) ?? [];
        if (list.Count == 0)
        {
            output.WriteLine("No analyst report has been written on this host.");
            return 0;
        }
        foreach (var report in list) output.WriteLine(ReportRenderer.Summary(report));
        output.WriteLine();
        output.WriteLine($"{reports!.Count()} report(s) stored, 90 days and 1,000 at most. 'wpshield analyst show <id>' prints one.");
        return 0;
    }

    private static int Show(List<string> positionals, CliOptions options, TextWriter output, TextWriter error, AnalystHost host, string path)
    {
        options.RejectUnknown("--store");
        if (positionals.Count != 2 || !long.TryParse(positionals[1].TrimStart('#'), NumberStyles.None, CultureInfo.InvariantCulture, out var id))
            throw new CliArgumentException("analyst show takes one report number, as 'wpshield analyst reports' lists it.");
        using (EvidenceAccess.OpenReadOnly(path, host.Elevated()))
        {
        }
        using var reports = OpenReportsReadOnly(path);
        if (reports?.Get(id) is not { } report)
        {
            error.WriteLine($"ERROR: there is no analyst report #{id} on this host. 'wpshield analyst reports' lists them.");
            return 1;
        }
        ReportRenderer.Render(report, output);
        return 0;
    }

    // ---------------------------------------------------------------------------------------------
    //  Shared
    // ---------------------------------------------------------------------------------------------

    /// <summary>Why a run would be refused now, or null. The same gate for <c>test</c> and for every run.</summary>
    internal static string? Blocker(AnalystConfiguration configuration, AnalystHost host)
    {
        if (!configuration.Enabled)
            return "the analyst is off (analyst.enabled is false). Read 'wpshield analyst status' for what would leave this host, then set it.";
        if (ProviderDisclosure.KeyVariable(configuration.Provider) is not { } variable)
            return "no provider is chosen (analyst.provider: anthropic or relay).";
        if (configuration.Provider == "relay" && configuration.RelayUrl is null)
            return "analyst.relay_url is not set; there is no default Relay host.";
        if (string.IsNullOrEmpty(host.Environment(variable)))
            return $"{variable} is not set in this account's environment. Set it as a user variable (see the analyst documentation); it is never read from a setting, an argument or a file.";
        return null;
    }

    /// <summary>The address, network, range or question a run is about, validated before anything is opened.</summary>
    private static (AnalystRole Role, string? Subject, string? Question) Request(string verb, List<string> positionals, CliOptions options)
    {
        switch (verb)
        {
            case "digest":
                options.RejectUnknown("--store", "--since", "--simulated");
                Positionals(positionals, 1, "analyst digest takes no argument; use --since.");
                var since = (options.Get("--since") ?? "24h").Trim().ToLowerInvariant();
                if (!Ranges.Contains(since, StringComparer.Ordinal))
                    throw new CliArgumentException("--since must be one of 1h, 6h, 24h, 7d, 30d or 90d.");
                return (AnalystRole.Digest, since, null);
            case "investigate":
                options.RejectUnknown("--store", "--simulated");
                if (positionals.Count != 2) throw new CliArgumentException("analyst investigate takes one address or network, such as 203.0.113.7 or 203.0.113.0/24.");
                return (AnalystRole.Investigate, Target(positionals[1]), null);
            default:
                options.RejectUnknown("--store", "--simulated");
                var text = string.Join(' ', positionals.Skip(1)).Trim();
                if (text.Length == 0) throw new CliArgumentException("analyst ask takes a question: wpshield analyst ask \"who attacked RDP last night?\"");
                if (text.Length > AnalystLimits.MaxQuestionChars)
                    throw new CliArgumentException($"A question is at most {AnalystLimits.MaxQuestionChars} characters.");
                return (AnalystRole.Ask, null, ReportText.Line(text, AnalystLimits.MaxQuestionChars));
        }
    }

    /// <summary>One canonical address, or a network with no host bits set, as the tools accept them.</summary>
    internal static string Target(string text)
    {
        var value = text.Trim();
        if (value.Length <= 64 && !value.Contains('/', StringComparison.Ordinal) && IPAddress.TryParse(value, out var ip))
            return (ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip).ToString();
        var slash = value.IndexOf('/', StringComparison.Ordinal);
        if (value.Length <= 64 && slash > 0 && IPAddress.TryParse(value[..slash], out var host) &&
            IPNetwork.TryParse(value, out var network) && network.BaseAddress.Equals(host))
            return network.ToString();
        throw new CliArgumentException($"'{NetworkMonitorCommand.ConsoleLabel(value)}' is not an IP address or a network with no host bits set, such as 203.0.113.0/24.");
    }

    private static AnalystUsage Usage(string path, DateTimeOffset now)
    {
        using var reports = OpenReportsReadOnly(path);
        return reports?.UsageOn(now) ?? new AnalystUsage(0, 0, new DateTimeOffset(now.UtcDateTime.Date, TimeSpan.Zero));
    }

    private static AnalystReportStore OpenReports(string evidencePath)
    {
        var path = AnalystReportStore.PathBeside(evidencePath);
        try
        {
            return AnalystReportStore.Open(path);
        }
        catch (UnauthorizedAccessException)
        {
            throw new EvidenceAccessException(EvidenceProblem.AccessDenied,
                $"The analyst's report store at {NetworkMonitorCommand.ConsoleLabel(path)} could not be written. Check the evidence folder's permissions.");
        }
        catch (DirectoryNotFoundException ex)
        {
            throw new EvidenceAccessException(EvidenceProblem.Missing, NetworkMonitorCommand.ConsoleLabel(ex.Message));
        }
        catch (Exception ex) when (ex is SqliteException or InvalidDataException)
        {
            throw new EvidenceAccessException(EvidenceProblem.Unreadable,
                $"The analyst's report store at {NetworkMonitorCommand.ConsoleLabel(path)} could not be opened: {NetworkMonitorCommand.ConsoleLabel(ex.Message)}");
        }
    }

    private static AnalystReportStore? OpenReportsReadOnly(string evidencePath)
    {
        var path = AnalystReportStore.PathBeside(evidencePath);
        try
        {
            return AnalystReportStore.OpenReadOnly(path);
        }
        catch (Exception ex) when (ex is SqliteException or InvalidDataException)
        {
            throw new EvidenceAccessException(EvidenceProblem.Unreadable,
                $"The analyst's report store at {NetworkMonitorCommand.ConsoleLabel(path)} could not be read: {NetworkMonitorCommand.ConsoleLabel(ex.Message)}");
        }
    }

    private static bool DetailedRecords(EvidenceSettings settings) =>
        settings.Get("mcp.detailed_records") is System.Text.Json.Nodes.JsonValue v && v.TryGetValue<bool>(out var b) && b;


    private static void Positionals(List<string> positionals, int max, string message)
    {
        if (positionals.Count > max) throw new CliArgumentException(message);
    }

    /// <summary>
    /// Separates the verb and its argument from the options. Only the options that take a value consume
    /// the token after them, so a question is never mistaken for a flag's value.
    /// </summary>
    private static (List<string> Positionals, CliOptions Options) Split(IReadOnlyList<string> args)
    {
        var positionals = new List<string>();
        var options = new List<string>();
        for (var i = 0; i < args.Count; i++)
        {
            var token = args[i];
            if (!token.StartsWith("--", StringComparison.Ordinal))
            {
                positionals.Add(token);
                continue;
            }
            options.Add(token);
            if (!token.Contains('=', StringComparison.Ordinal) && ValueOptions.Contains(token, StringComparer.OrdinalIgnoreCase) &&
                i + 1 < args.Count && !args[i + 1].StartsWith("--", StringComparison.Ordinal))
                options.Add(args[++i]);
        }
        return (positionals, CliOptions.Parse(options));
    }

    /// <summary>
    /// Prints what leaves the host after an <c>analyst.*</c> setting changes while the analyst is enabled,
    /// so turning it on, or changing where it sends, shows exactly what will leave (ADR 0010, section 1).
    /// </summary>
    internal static void AfterSettingChange(string key, EvidenceStore store, TextWriter output)
    {
        if (!key.StartsWith("analyst.", StringComparison.Ordinal) && key != "mcp.detailed_records") return;
        var settings = new EvidenceSettings(store);
        var configuration = AnalystConfiguration.Read(settings);
        if (!configuration.Enabled) return;
        output.WriteLine();
        foreach (var line in ProviderDisclosure.Lines(configuration.Provider, configuration.RelayUrl, DetailedRecords(settings), configuration.Spanish))
            output.WriteLine(line);
    }

    /// <summary>A token that Ctrl+C cancels, linked to the caller's, unhooked from the console when disposed.</summary>
    private sealed class CtrlC : IDisposable
    {
        private readonly CancellationTokenSource source;

        public CtrlC(CancellationToken token)
        {
            source = CancellationTokenSource.CreateLinkedTokenSource(token);
            Console.CancelKeyPress += Cancel;
        }

        public CancellationToken Token => source.Token;

        public void CancelAfter(TimeSpan delay) => source.CancelAfter(delay);

        private void Cancel(object? sender, ConsoleCancelEventArgs e)
        {
            e.Cancel = true;
            try { source.Cancel(); } catch (ObjectDisposedException) { }
        }

        public void Dispose()
        {
            Console.CancelKeyPress -= Cancel;
            source.Dispose();
        }
    }
}
