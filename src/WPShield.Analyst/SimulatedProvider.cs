using System.Text.Json.Nodes;

namespace WPShield.Analyst;

/// <summary>
/// A provider that sends nothing anywhere (ADR 0010, section 7): it answers from a script. Tests use
/// it to drive the loop through every outcome; <c>wpshield analyst ... --simulated</c> uses
/// <see cref="Demonstration"/> to show the whole flow against the real tools without a key.
/// </summary>
internal sealed class SimulatedProvider(Func<int, IReadOnlyList<AnalystToolOutcome>, CancellationToken, Task<ProviderTurn>> script) : IAnalystProvider
{
    public const string ModelName = "simulated";

    public string Name => "simulated";

    public bool OperatorPays { get; init; }

    /// <summary>The specs each conversation was started with, for tests to inspect.</summary>
    public List<AnalystConversationSpec> Started { get; } = [];

    /// <summary>A provider that plays <paramref name="turns"/> in order and then fails.</summary>
    public static SimulatedProvider Scripted(params ProviderTurn[] turns) => new((index, _, _) =>
        index < turns.Length ? Task.FromResult(turns[index]) : throw new AnalystProviderException("The script has no more turns."));

    /// <summary>
    /// Three tool calls (coverage, a summary and the top sources for the range), then a fixed text that
    /// says no model read anything. Counts nothing against a budget but the run itself.
    /// </summary>
    public static SimulatedProvider Demonstration(string range) => new((index, outcomes, _) => Task.FromResult(index switch
    {
        0 => Turn("tool_use", "",
            Call("sim-1", "coverage", new JsonObject { ["range"] = range }),
            Call("sim-2", "attacks_summary", new JsonObject { ["range"] = range }),
            Call("sim-3", "top_sources", new JsonObject { ["range"] = range, ["limit"] = 5 })),
        _ => Turn("end_turn",
            "Simulated run: no model read this evidence and nothing left the host. The loop called three read-only tools, " +
            $"which answered {outcomes.Count(o => !o.IsError)} times with data and {outcomes.Count(o => o.IsError)} times with an error. " +
            "Their answers are in the store's tool-call record, not interpreted here. Choose a provider and set its key to get an analysis.")
    }));

    public static ProviderTurn Turn(string stopReason, string text, params AnalystToolCall[] calls) =>
        new(ModelName, stopReason, null, null, text, calls, 0, 0);

    public static AnalystToolCall Call(string id, string name, JsonObject arguments) => new(id, name, arguments);

    public IAnalystConversation Begin(AnalystConversationSpec spec)
    {
        Started.Add(spec);
        return new Conversation(script);
    }

    public Task<ProviderCheck> TestAsync(CancellationToken cancellationToken) =>
        Task.FromResult(new ProviderCheck(true, "The simulated provider answers from a script; it sends nothing anywhere.", []));

    private sealed class Conversation(Func<int, IReadOnlyList<AnalystToolOutcome>, CancellationToken, Task<ProviderTurn>> script) : IAnalystConversation
    {
        private int turn;

        public Task<ProviderTurn> NextAsync(IReadOnlyList<AnalystToolOutcome> outcomes, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return script(turn++, outcomes, cancellationToken);
        }
    }
}
