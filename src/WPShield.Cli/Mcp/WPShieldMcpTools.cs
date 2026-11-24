using System.ComponentModel;
using System.Reflection;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace WPShield.Cli.Mcp;

/// <summary>
/// The MCP face of <see cref="EvidenceTools"/>: names, descriptions and annotations, and nothing else.
/// Every tool is annotated read-only, non-destructive, idempotent and closed-world, and every
/// description carries the untrusted-text rule, because a description is what the model reads.
/// </summary>
[McpServerToolType]
internal sealed class WPShieldMcpTools(EvidenceTools tools)
{
    private const string Safety = " Read-only: nothing here blocks, unblocks or changes a setting. " + EvidenceTools.UntrustedNote +
        " Every answer has a coverage section: a gap is a period nothing was recorded, not a quiet one.";

    private const string Range = "One of 1h, 6h, 24h, 7d, 30d, 90d (default 24h). Leave it out when giving from and to.";
    private const string From = "Start of an explicit range, ISO-8601 UTC such as 2026-11-24T08:00:00Z. Needs to; at most 90 days before it.";
    private const string To = "End of an explicit range, ISO-8601 UTC. Needs from; not in the future.";
    private const string Limit = "How many rows to return, 1 to 100 (default 20). The answer says when more exist.";

    [McpServerTool(Name = "attacks_summary", Title = "Failed logons: summary", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("Totals of failed Windows logons recorded on this server (Remote Desktop, SMB and other network logons): attempts, source addresses, attempts on nonexistent accounts, and from when the range was fully recorded." + Safety)]
    public CallToolResult AttacksSummary(
        [Description(Range)] string? range = null,
        [Description(From)] string? from = null,
        [Description(To)] string? to = null) =>
        Result("attacks_summary", () => tools.AttacksSummary(range, from, to));

    [McpServerTool(Name = "top_sources", Title = "Failed logons: top source addresses", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("The source addresses with the most failed logons in a range, with first and last attempt, attempts on nonexistent accounts, distinct accounts tried, their /24 or /64 network and how many other sources share it, and the operator's label if one matches." + Safety)]
    public CallToolResult TopSources(
        [Description(Range)] string? range = null,
        [Description(Limit)] int limit = EvidenceTools.DefaultLimit,
        [Description(From)] string? from = null,
        [Description(To)] string? to = null) =>
        Result("top_sources", () => tools.TopSources(range, limit, from, to));

    [McpServerTool(Name = "source_history", Title = "Failed logons: one address", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("The history of one source address: when the store first saw it, on how many days, and a timeline of its failed logons. Account names and single attempts are included only if the operator enabled mcp.detailed_records; the answer says which." + Safety)]
    public CallToolResult SourceHistory(
        [Description("One IPv4 or IPv6 address, such as 203.0.113.7.")] string address,
        [Description("One of 1h, 6h, 24h, 7d, 30d, 90d (default 7d). Leave it out when giving from and to.")] string? range = null,
        [Description(From)] string? from = null,
        [Description(To)] string? to = null) =>
        Result("source_history", () => tools.SourceHistory(address, range, from, to));

    [McpServerTool(Name = "attack_timeline", Title = "Failed logons: timeline", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("Failed logons per time bucket across a range, split into attempts on nonexistent accounts and the rest. Buckets the collector did not fully record are marked covered=false, never shown as a plain zero." + Safety)]
    public CallToolResult AttackTimeline(
        [Description(Range)] string? range = null,
        [Description("auto (default), 5m, 15m, 1h, 6h or 1d. At most 200 buckets.")] string? bucket = null,
        [Description(From)] string? from = null,
        [Description(To)] string? to = null) =>
        Result("attack_timeline", () => tools.AttackTimeline(range, bucket, from, to));

    [McpServerTool(Name = "coverage", Title = "What was recorded", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("Which parts of a range the WPShield service actually recorded, per source, with the gaps and any problems it reported (log unavailable, service not running), and whether detailed rows still reach the start of the range. Ask this before concluding that a quiet period was quiet." + Safety)]
    public CallToolResult Coverage(
        [Description(Range)] string? range = null,
        [Description(From)] string? from = null,
        [Description(To)] string? to = null) =>
        Result("coverage", () => tools.Coverage(range, from, to));

    [McpServerTool(Name = "decisions", Title = "Block decisions: audit trail", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("The audit trail of block decisions (would-block, block, expire, unblock, allow) with rule, mode, reason and expiry, newest first. History only: a past block is not necessarily in force now." + Safety)]
    public CallToolResult Decisions(
        [Description(Range)] string? range = null,
        [Description(Limit)] int limit = EvidenceTools.DefaultLimit,
        [Description("Only decisions about this address or network, such as 203.0.113.7 or 203.0.113.0/24.")] string? target = null,
        [Description(From)] string? from = null,
        [Description(To)] string? to = null) =>
        Result("decisions", () => tools.Decisions(range, limit, target, from, to));

    [McpServerTool(Name = "evidence_kinds", Title = "Other evidence: kinds", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("The kinds of evidence other than failed Windows logons stored in a range (for example HTTP requests the gateway refused, SQL Server or FTP logons), with a count for each." + Safety)]
    public CallToolResult EvidenceKinds(
        [Description(Range)] string? range = null,
        [Description(From)] string? from = null,
        [Description(To)] string? to = null) =>
        Result("evidence_kinds", () => tools.EvidenceKinds(range, from, to));

    [McpServerTool(Name = "evidence_events", Title = "Other evidence: events of one kind", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("Events of one kind in a range, newest first, optionally for one address. Single events (time, source, address, subject, detail) are returned only if the operator enabled mcp.detailed_records; otherwise only the count." + Safety)]
    public CallToolResult EvidenceEvents(
        [Description("The kind, as evidence_kinds lists it, such as http.request-refused.")] string kind,
        [Description(Range)] string? range = null,
        [Description(Limit)] int limit = EvidenceTools.DefaultLimit,
        [Description("Only events from this IPv4 or IPv6 address.")] string? address = null,
        [Description(From)] string? from = null,
        [Description(To)] string? to = null) =>
        Result("evidence_events", () => tools.EvidenceEventsOfKind(kind, range, limit, address, from, to));

    [McpServerTool(Name = "list_settings", Title = "Evidence store settings", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("Every setting the evidence store knows, its value, whether it is the default, who changed it last and when it takes effect, including whether this server may return detailed records." + Safety)]
    public CallToolResult ListSettings() => Result("list_settings", tools.ListSettings);

    [McpServerTool(Name = "address_labels", Title = "Address labels", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = false)]
    [Description("The operator's names for known addresses and networks, such as an office or a monitoring service. A label describes; it never allows or blocks." + Safety)]
    public CallToolResult AddressLabels() => Result("address_labels", tools.AddressLabels);

    /// <summary>
    /// Every answer leaves as JSON text. An exception the tool logic did not expect becomes an explicit
    /// error naming only its type, so neither a stack trace nor an empty success reaches the model.
    /// </summary>
    internal static CallToolResult Result(string tool, Func<ToolAnswer> run)
    {
        ToolAnswer answer;
        try
        {
            answer = run();
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            answer = EvidenceTools.Failure(tool, "internal-error", $"The tool failed with {exception.GetType().Name}.");
        }
        return new CallToolResult
        {
            Content = [new TextContentBlock { Text = answer.ToJson() }],
            IsError = answer.IsError
        };
    }

    /// <summary>The tools, created from the attributed methods above, bound to one instance.</summary>
    internal static McpServerPrimitiveCollection<McpServerTool> Collection(EvidenceTools tools)
    {
        var target = new WPShieldMcpTools(tools);
        var collection = new McpServerPrimitiveCollection<McpServerTool>();
        foreach (var method in typeof(WPShieldMcpTools).GetMethods(BindingFlags.Public | BindingFlags.Instance))
            if (method.IsDefined(typeof(McpServerToolAttribute), inherit: false))
                collection.Add(McpServerTool.Create(method, target));
        return collection;
    }
}
