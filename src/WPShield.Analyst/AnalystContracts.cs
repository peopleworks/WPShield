using System.Text.Json.Nodes;

namespace WPShield.Analyst;

/// <summary>
/// One read-only tool the analyst may call. The CLI implements it over the MCP server's tool functions
/// (ADR 0010, section 3), so the untrusted wrapping, the <c>mcp.detailed_records</c> gate and the bounds
/// stay defined once. This assembly cannot reference the CLI, so the contract lives here.
/// </summary>
internal interface IAnalystTool
{
    string Name { get; }

    /// <summary>What the model reads to decide when to call it.</summary>
    string Description { get; }

    /// <summary>A JSON schema strict tool use accepts: <c>additionalProperties: false</c>, no numeric bounds.</summary>
    JsonObject InputSchema { get; }

    /// <summary>Runs the tool. Never throws for bad arguments: they come back as an error result the model can correct from.</summary>
    AnalystToolResult Invoke(JsonObject arguments, CancellationToken cancellationToken);
}

/// <param name="Json">The tool's answer, exactly as the MCP server would return it.</param>
/// <param name="IsError">Whether it is an error the model must not read as data.</param>
internal sealed record AnalystToolResult(string Json, bool IsError);

/// <summary>What the model asked a tool to do.</summary>
internal sealed record AnalystToolCall(string Id, string Name, JsonObject Arguments);

/// <summary>What a tool answered, sent back to the model as a <c>tool_result</c>.</summary>
internal sealed record AnalystToolOutcome(string CallId, string Json, bool IsError);

/// <summary>
/// One response from a provider, reduced to what the loop and the report need. Thinking blocks and
/// fallback markers stay inside the provider's own conversation, which echoes them back unchanged.
/// </summary>
/// <param name="Model">The model that produced this response; after a fallback, not the one asked for.</param>
/// <param name="StopReason">The provider's stop reason, such as <c>end_turn</c>, <c>tool_use</c>, <c>max_tokens</c> or <c>refusal</c>.</param>
/// <param name="FellBack">Whether a fallback model served this response.</param>
internal sealed record ProviderTurn(
    string Model,
    string StopReason,
    string? RefusalCategory,
    string? RefusalExplanation,
    string Text,
    IReadOnlyList<AnalystToolCall> ToolCalls,
    long InputTokens,
    long OutputTokens,
    bool FellBack = false);

/// <summary>Everything a conversation is started with. The system prompt and the tools are fixed for the run.</summary>
internal sealed record AnalystConversationSpec(string SystemPrompt, string FirstMessage, IReadOnlyList<IAnalystTool> Tools, int MaxOutputTokens);

/// <summary>A conversation with one provider, for one run.</summary>
internal interface IAnalystConversation
{
    /// <summary>
    /// The first call sends the opening message; each later call sends the outcomes of every tool call
    /// in the previous turn, in order.
    /// </summary>
    Task<ProviderTurn> NextAsync(IReadOnlyList<AnalystToolOutcome> outcomes, CancellationToken cancellationToken);
}

/// <summary>The result of <c>wpshield analyst test</c>: whether the provider answered, and what it said about itself.</summary>
internal sealed record ProviderCheck(bool Ok, string Summary, IReadOnlyList<KeyValuePair<string, string>> Details);

/// <summary>A model provider. Phase 1: the Anthropic API, the PeopleWorks Relay, and a simulated one for tests.</summary>
internal interface IAnalystProvider
{
    /// <summary><c>anthropic</c>, <c>relay</c> or <c>simulated</c>.</summary>
    string Name { get; }

    /// <summary>
    /// Whether the operator pays per token. False for the Relay, whose cost is counted as zero here
    /// because WPShield does not pay it, and for the simulated provider.
    /// </summary>
    bool OperatorPays { get; }

    IAnalystConversation Begin(AnalystConversationSpec spec);

    /// <summary>Checks the provider without spending model tokens where the provider allows it.</summary>
    Task<ProviderCheck> TestAsync(CancellationToken cancellationToken);
}

/// <summary>A provider failure, with a message already scrubbed of the key and of control characters.</summary>
internal sealed class AnalystProviderException(string message) : Exception(message);
