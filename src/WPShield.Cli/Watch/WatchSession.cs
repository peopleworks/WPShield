using System.Globalization;
using Spectre.Console;
using Spectre.Console.Rendering;

namespace WPShield.Cli.Watch;

/// <summary>
/// Runs one watch: it opens the tail reader, feeds the model, and renders — either as a live console
/// or as plain lines. It stops on Ctrl+C.
/// </summary>
/// <remarks>
/// The two render modes share the reader, the model and the host filter; they differ only in how a
/// snapshot becomes output. Plain mode prints each new event as a line, which is what a redirect or a
/// pipe wants; live mode redraws a table and a footer in place, which is what an operator watching a
/// rollout wants.
/// </remarks>
internal sealed class WatchSession
{
    private static readonly char[] Sparkline = [' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

    private readonly WatchSettings _settings;
    private readonly JsonlTailReader _reader;
    private readonly WatchModel _model = new();

    public WatchSession(WatchSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        _settings = settings;
        _reader = new JsonlTailReader(settings.LogDirectory, settings.FromStart);
    }

    public int RunPlain(TextWriter output)
    {
        ArgumentNullException.ThrowIfNull(output);

        using var stop = new CancellationTokenSource();
        HookCancel(stop);

        output.WriteLine();
        output.WriteLine($"WPShield watch - {_settings.LogDirectory}");
        output.WriteLine(HostLine());
        output.WriteLine("Reading only. Ctrl+C to stop.");
        output.WriteLine();

        while (!stop.IsCancellationRequested)
        {
            foreach (var evidence in Drain())
            {
                output.WriteLine(PlainLine(evidence));
            }

            output.Flush();
            Wait(stop);
        }

        return 0;
    }

    public int RunLive()
    {
        using var stop = new CancellationTokenSource();
        HookCancel(stop);

        AnsiConsole.Live(BuildRenderable())
            .AutoClear(false)
            .Overflow(VerticalOverflow.Ellipsis)
            .Start(context =>
            {
                while (!stop.IsCancellationRequested)
                {
                    foreach (var _ in Drain())
                    {
                        // Draining feeds the model; the render below reads it.
                    }

                    _model.Tick(DateTimeOffset.Now);
                    context.UpdateTarget(BuildRenderable());
                    context.Refresh();
                    Wait(stop);
                }

                // One last render so the final state is what stays on screen after Ctrl+C.
                _model.Tick(DateTimeOffset.Now);
                context.UpdateTarget(BuildRenderable());
                context.Refresh();
            });

        return 0;
    }

    /// <summary>
    /// Reads whatever is available once and folds it into the model, without rendering. The live and
    /// plain loops do this on every poll; a test does it once to populate a model it can then render
    /// or inspect.
    /// </summary>
    internal void PumpOnce() => Drain();

    /// <summary>
    /// Writes one frame of the live layout to a console. The loop calls this through Spectre's live
    /// context; a test calls it against a recording console to see exactly what an operator would.
    /// </summary>
    internal void RenderOnce(IAnsiConsole console)
    {
        ArgumentNullException.ThrowIfNull(console);
        _model.Tick(DateTimeOffset.Now);
        console.Write(BuildRenderable());
    }

    /// <summary>Reads and parses the new lines, applies the host filter, and folds them into the model.</summary>
    private IReadOnlyList<EvidenceEvent> Drain()
    {
        var events = new List<EvidenceEvent>();
        foreach (var line in _reader.ReadNewLines())
        {
            var evidence = EvidenceParser.Parse(line);
            if (evidence is null || evidence.Kind == EvidenceKind.Other || !_settings.Includes(evidence))
            {
                continue;
            }

            _model.Add(evidence);
            events.Add(evidence);
        }

        return events;
    }

    private IRenderable BuildRenderable()
    {
        var table = new Table()
            .Border(TableBorder.Rounded)
            .Expand()
            .AddColumn("[grey]time[/]")
            .AddColumn("[grey]site[/]")
            .AddColumn("[grey]rule[/]")
            .AddColumn(new TableColumn("[grey]score[/]").RightAligned())
            .AddColumn("[grey]action[/]")
            .AddColumn("[grey]request[/]");

        foreach (var evidence in RecentForView())
        {
            table.AddRow(
                Dim(evidence.Timestamp.ToLocalTime().ToString("HH:mm:ss", CultureInfo.InvariantCulture)),
                Plain(evidence.Host ?? "-"),
                RuleCell(evidence),
                ScoreCell(evidence),
                ActionCell(evidence),
                Dim(Request(evidence)));
        }

        return new Rows(new Panel(Header()).Border(BoxBorder.None), table, Footer());
    }

    private IReadOnlyList<EvidenceEvent> RecentForView()
    {
        var recent = _model.Recent;
        var rows = VisibleRows();
        return recent.Count <= rows ? recent : recent.Skip(recent.Count - rows).ToArray();
    }

    private static int VisibleRows()
    {
        try
        {
            // Leave room for the header line, the footer line, the table's own borders and headings.
            return Math.Clamp(AnsiConsole.Profile.Height - 8, 5, 40);
        }
        catch (Exception exception) when (exception is IOException or InvalidOperationException)
        {
            return 20;
        }
    }

    private IRenderable Header()
    {
        var scope = _settings.Hosts.Count == 0 ? "all sites" : string.Join(", ", _settings.Hosts);
        var file = _reader.CurrentFile ?? "waiting for a log file…";
        return new Markup(
            $"[bold]WPShield watch[/]  [grey]{Markup.Escape(scope)}[/]  " +
            $"[grey]{Markup.Escape(file)}[/]  [grey]{DateTime.Now.ToString("HH:mm:ss", CultureInfo.InvariantCulture)}[/]");
    }

    private IRenderable Footer()
    {
        var spark = RenderSparkline(_model.RateWindow(DateTimeOffset.Now));
        var since = _model.FirstSeen is { } first
            ? first.ToLocalTime().ToString("HH:mm:ss", CultureInfo.InvariantCulture)
            : "-";

        var dropped = _model.Dropped > 0
            ? $"  [red]dropped {_model.Dropped}[/]"
            : string.Empty;

        return new Markup(
            $"[grey]events/s[/] {spark}   " +
            $"[bold]findings[/] {_model.Findings}   " +
            $"[yellow]observed[/] {_model.Observed}   " +
            $"[red]blocked[/] {_model.Blocked}   " +
            $"[green]uploads ok[/] {_model.AllowedUploads}   " +
            $"[grey]since[/] {since}{dropped}");
    }

    private static string RenderSparkline(IReadOnlyList<int> window)
    {
        if (window.Count == 0)
        {
            return string.Empty;
        }

        var max = window.Max();
        if (max == 0)
        {
            return new string(Sparkline[0], window.Count);
        }

        var chars = new char[window.Count];
        for (var index = 0; index < window.Count; index++)
        {
            var scaled = (int)Math.Round((double)window[index] / max * (Sparkline.Length - 1));
            chars[index] = Sparkline[Math.Clamp(scaled, 0, Sparkline.Length - 1)];
        }

        return new string(chars);
    }

    private static IRenderable RuleCell(EvidenceEvent evidence)
    {
        if (!string.IsNullOrEmpty(evidence.Rules))
        {
            return new Markup($"[bold]{Markup.Escape(evidence.Rules)}[/]");
        }

        return evidence.Kind == EvidenceKind.Verdict ? Dim("verdict") : Dim("-");
    }

    private static IRenderable ScoreCell(EvidenceEvent evidence)
    {
        if (evidence.Score is not { } score)
        {
            return Dim("-");
        }

        var color = score >= 80 ? "red" : score >= 30 ? "yellow" : "grey";
        return new Markup($"[{color}]{score}[/]");
    }

    private static IRenderable ActionCell(EvidenceEvent evidence)
    {
        return evidence.Action switch
        {
            EvidenceAction.Block => new Markup("[red]● Block[/]"),
            EvidenceAction.Observe => new Markup("[yellow]● Observe[/]"),
            EvidenceAction.Allow => new Markup("[green]● Allow[/]"),
            _ => evidence.Kind == EvidenceKind.Finding ? Dim("finding") : Dim("-")
        };
    }

    private static string Request(EvidenceEvent evidence)
    {
        var method = evidence.Method;
        var path = evidence.Path;
        return (method, path) switch
        {
            (not null, not null) => $"{method} {path}",
            (not null, null) => method,
            (null, not null) => path,
            _ => string.Empty
        };
    }

    private static IRenderable Plain(string text) => new Markup(Markup.Escape(text));

    private static IRenderable Dim(string text) => new Markup($"[grey]{Markup.Escape(text)}[/]");

    private static string PlainLine(EvidenceEvent evidence)
    {
        var time = evidence.Timestamp.ToLocalTime().ToString("HH:mm:ss", CultureInfo.InvariantCulture);
        var action = evidence.Action == EvidenceAction.Unknown
            ? evidence.Kind == EvidenceKind.Finding ? "finding" : "-"
            : evidence.Action.ToString();
        var score = evidence.Score?.ToString(CultureInfo.InvariantCulture) ?? "-";

        return string.Join("  ", new[]
        {
            time,
            (evidence.Host ?? "-").PadRight(22),
            (evidence.Rules ?? "-").PadRight(24),
            score.PadLeft(3),
            action.PadRight(8),
            Request(evidence)
        });
    }

    private string HostLine() =>
        _settings.Hosts.Count == 0 ? "All sites." : $"Sites: {string.Join(", ", _settings.Hosts)}";

    private static void HookCancel(CancellationTokenSource stop)
    {
        Console.CancelKeyPress += (_, eventArgs) =>
        {
            // Handle it ourselves: cancel the loop and let it unwind cleanly rather than letting the
            // runtime kill the process mid-render and leave the terminal in the live layout.
            eventArgs.Cancel = true;
            stop.Cancel();
        };
    }

    private void Wait(CancellationTokenSource stop)
    {
        // Returns as soon as Ctrl+C fires, so stopping is immediate rather than up to one interval
        // late.
        stop.Token.WaitHandle.WaitOne(_settings.PollInterval);
    }
}
