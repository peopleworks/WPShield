using System.Text.Json.Nodes;

namespace WPShield.Analyst;

/// <summary>What the operator asked for: the role, and its subject or question.</summary>
/// <param name="Subject">The digest's range (<c>24h</c>) or the address or network to investigate.</param>
internal sealed record AnalystRunRequest(AnalystRole Role, string? Subject, string? Question, AnalystConfiguration Configuration);

/// <summary>A daily bound refused the run before anything was sent (ADR 0010, section 8).</summary>
/// <param name="Bound">The setting that bounds it, such as <c>analyst.daily_runs</c>.</param>
internal sealed class AnalystBudgetException(string bound, string message) : Exception(message)
{
    public string Bound { get; } = bound;
}

/// <summary>
/// The analyst's loop: a few dozen lines, auditable call by call (ADR 0010, sections 3 and 8).
/// </summary>
/// <remarks>
/// <para>
/// <b>Bounded.</b> At most <see cref="MaxToolCalls"/> tool calls, <see cref="MaxOutputTokensPerTurn"/>
/// output tokens per turn, <see cref="RunTimeout"/> for the whole run, and the caller's cancellation
/// token. The daily budgets are checked before anything is sent. Reaching a bound ends the run as
/// stopped, naming the bound, and keeps none of the model's text: a smaller analysis presented as a
/// complete one is exactly what this must never produce.
/// </para>
/// <para>
/// <b>Started only by a person.</b> Nothing here subscribes to an event; the CLI calls it when the
/// operator types a command, and a scheduled task runs only if the operator creates it.
/// </para>
/// </remarks>
internal sealed class AnalystRunner(IAnalystProvider provider, IReadOnlyList<IAnalystTool> tools, AnalystReportStore store,
    TimeProvider? clock = null)
{
    public const int MaxToolCalls = 12;
    public const int MaxOutputTokensPerTurn = 16_000;
    public static readonly TimeSpan RunTimeout = TimeSpan.FromMinutes(5);

    private readonly TimeProvider clock = clock ?? TimeProvider.System;
    private readonly Dictionary<string, IAnalystTool> byName = tools.ToDictionary(t => t.Name, StringComparer.Ordinal);

    /// <summary>The run's wall-clock bound. Five minutes; tests shorten it.</summary>
    public TimeSpan Timeout { get; init; } = RunTimeout;

    /// <summary>Called as each tool call runs, so the operator can watch what the model reads.</summary>
    public Action<AnalystToolCall>? OnToolCall { get; init; }

    /// <summary>
    /// Runs one analysis and returns its report's ID. Throws <see cref="AnalystBudgetException"/> when a
    /// daily bound refuses it, before anything is sent.
    /// </summary>
    public async Task<long> RunAsync(AnalystRunRequest request, CancellationToken cancellationToken)
    {
        var configuration = request.Configuration;
        var now = clock.GetUtcNow();
        var usage = store.UsageOn(now);
        CheckBudget(configuration, usage);

        var spec = new AnalystConversationSpec(
            AnalystPrompts.System(request.Role, configuration.Spanish),
            AnalystPrompts.FirstMessage(request.Role, request.Subject, request.Question, now),
            tools, MaxOutputTokensPerTurn);
        var id = store.Begin(new ReportStart(now, provider.Name, provider.OperatorPays, configuration.Model, request.Role,
            request.Subject, request.Question, configuration.Language));

        using var timeout = new CancellationTokenSource(Timeout, clock);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeout.Token);
        long spent = 0;
        var calls = 0;
        var outcomes = (IReadOnlyList<AnalystToolOutcome>)[];
        try
        {
            var conversation = provider.Begin(spec);
            while (true)
            {
                if (provider.OperatorPays && usage.InputTokens + spent >= configuration.DailyInputTokens)
                    return Stop(id, null, $"analyst.daily_input_tokens ({configuration.DailyInputTokens:N0} input tokens per UTC day) was reached during the run.");

                var turn = await conversation.NextAsync(outcomes, linked.Token);
                store.AddTurn(id, turn);
                spent += turn.InputTokens;

                if (turn.StopReason == "refusal")
                {
                    store.Finish(id, new ReportEnd(clock.GetUtcNow(), ReportStatus.Refused, turn.StopReason,
                        RefusalCategory: turn.RefusalCategory ?? "none given", RefusalExplanation: turn.RefusalExplanation));
                    return id;
                }
                if (turn.StopReason == "max_tokens")
                {
                    store.Finish(id, new ReportEnd(clock.GetUtcNow(), ReportStatus.Truncated, turn.StopReason,
                        Bound: $"{MaxOutputTokensPerTurn:N0} output tokens per turn", Text: turn.Text));
                    return id;
                }
                if (turn.ToolCalls.Count == 0)
                {
                    var finished = turn.StopReason is "end_turn" or "stop_sequence";
                    store.Finish(id, new ReportEnd(clock.GetUtcNow(), finished ? ReportStatus.Completed : ReportStatus.Failed, turn.StopReason,
                        Error: finished ? null : $"The provider stopped with '{turn.StopReason}', which this version does not continue from.",
                        Text: finished ? turn.Text : null));
                    return id;
                }
                if (calls + turn.ToolCalls.Count > MaxToolCalls)
                    return Stop(id, turn.StopReason,
                        $"{MaxToolCalls} tool calls per run: the model asked for {calls + turn.ToolCalls.Count}.");

                var results = new List<AnalystToolOutcome>(turn.ToolCalls.Count);
                foreach (var call in turn.ToolCalls)
                {
                    linked.Token.ThrowIfCancellationRequested();
                    OnToolCall?.Invoke(call);
                    var result = Invoke(call, linked.Token);
                    store.AddToolCall(id, ++calls, call.Name, call.Arguments.ToJsonString(), result.IsError);
                    results.Add(new AnalystToolOutcome(call.Id, result.Json, result.IsError));
                }
                outcomes = results;
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            store.Finish(id, new ReportEnd(clock.GetUtcNow(), ReportStatus.Cancelled, Error: "Cancelled by the operator (Ctrl+C)."));
            return id;
        }
        catch (OperationCanceledException) when (timeout.IsCancellationRequested)
        {
            store.Finish(id, new ReportEnd(clock.GetUtcNow(), ReportStatus.TimedOut,
                Bound: $"{Timeout.TotalMinutes:0.##} minutes per run", Error: "The run reached its time bound and was stopped."));
            return id;
        }
        catch (AnalystProviderException exception)
        {
            store.Finish(id, new ReportEnd(clock.GetUtcNow(), ReportStatus.Failed, Error: exception.Message));
            return id;
        }
        catch (Exception exception)
        {
            // Anything else is a defect here, not a provider answer. The row says so by type only - the
            // message could carry text from anywhere - and the caller sees the exception.
            store.Finish(id, new ReportEnd(clock.GetUtcNow(), ReportStatus.Failed, Error: $"The run failed with {exception.GetType().Name}."));
            throw;
        }
    }

    private long Stop(long id, string? stopReason, string bound)
    {
        store.Finish(id, new ReportEnd(clock.GetUtcNow(), ReportStatus.Stopped, stopReason, Bound: bound,
            Error: "A bound stopped the run before the model finished. Nothing the model wrote is kept: it would read as a complete analysis."));
        return id;
    }

    private static void CheckBudget(AnalystConfiguration configuration, AnalystUsage usage)
    {
        if (usage.Runs >= configuration.DailyRuns)
            throw new AnalystBudgetException("analyst.daily_runs",
                $"Refused: analyst.daily_runs allows {configuration.DailyRuns} runs per UTC day, and {usage.Runs} have started today " +
                $"(since {usage.DayStart:yyyy-MM-dd} 00:00 UTC). Nothing was sent. Raise the setting or wait for the next UTC day.");
        if (usage.InputTokens >= configuration.DailyInputTokens)
            throw new AnalystBudgetException("analyst.daily_input_tokens",
                $"Refused: analyst.daily_input_tokens allows {configuration.DailyInputTokens:N0} input tokens per UTC day on a provider you pay, " +
                $"and {usage.InputTokens:N0} were spent today (since {usage.DayStart:yyyy-MM-dd} 00:00 UTC). Nothing was sent. " +
                "Raise the setting or wait for the next UTC day.");
    }

    private AnalystToolResult Invoke(AnalystToolCall call, CancellationToken cancellationToken)
    {
        if (!byName.TryGetValue(call.Name, out var tool))
            return Error(call.Name, "unknown-tool", "There is no tool with that name. Use only the tools listed in this conversation.");
        try
        {
            return tool.Invoke(call.Arguments, cancellationToken);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            return Error(call.Name, "internal-error", $"The tool failed with {exception.GetType().Name}.");
        }
    }

    private static AnalystToolResult Error(string tool, string code, string message) => new(new JsonObject
    {
        ["answer"] = ReportText.Line(tool, 64),
        ["error"] = new JsonObject { ["code"] = code, ["message"] = message },
        ["notes"] = new JsonArray("No evidence was read. This is not an empty result: it says nothing about whether attacks happened.")
    }.ToJsonString(), IsError: true);
}
