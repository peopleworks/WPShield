using System.Globalization;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using WPShield.Analyst;
using WPShield.Cli.Mcp;

namespace WPShield.Cli.Analyst;

/// <summary>
/// The analyst's tools: the MCP server's tool functions, called in-process (ADR 0010, section 3).
/// </summary>
/// <remarks>
/// <para>
/// <b>Defined once.</b> The tools are found by reflection over <see cref="WPShieldMcpTools"/>, the class
/// <c>wpshield mcp</c> serves, and each call goes through the same attributed method, so the name, the
/// description, the <c>{"untrusted": ...}</c> wrapping, the bounds and the <c>mcp.detailed_records</c> and
/// <c>mcp.host_details</c> gates (frozen in <see cref="McpEvidenceAccess"/> when the store first opens) are the
/// MCP server's own.
/// A tool added there reaches the analyst without a change here, and nothing else does: no shell, file,
/// web or code tool exists to add.
/// </para>
/// <para>
/// <b>Strict schemas.</b> The analyst's tools are declared with <c>strict: true</c>, whose schemas take
/// <c>additionalProperties: false</c>, no numeric bounds, at most 24 optional parameters across all tools
/// and at most 16 union-typed ones. The MCP schema is reduced to that: each property keeps its type and
/// description, a nullable type becomes the plain type of an optional property, and the explicit
/// <c>from</c>/<c>to</c> range is kept only on the tools a digest needs it for - comparing a period with
/// the one before. The other tools take named ranges, which they already accept.
/// </para>
/// <para>
/// <b>Server defaults instead of optional parameters.</b> Twenty tools with every optional parameter
/// would need 33 optional parameters, over the budget of 24. The analyst's schemas therefore leave out a
/// few parameters whose MCP default is what a digest or an investigation wants, listed in
/// <see cref="ServerDefaults"/>: <c>limit</c> on every tool but <c>top_sources</c> (20 rows), the timeline's
/// <c>bucket</c> (chosen from the range), the web tools' <c>site</c> (every site; each row names its site
/// ID) and the address filter of <c>web_findings</c> (<c>address_report</c> answers one address). That
/// leaves 24, exactly the budget: the host tools of ADR 0013 add one optional parameter, the range of
/// <c>rdp_sessions</c>, and nothing else (four take none, and <c>host_inventory</c>'s <c>kind</c> is
/// required). Twenty tools is also the most strict tool use takes in one request. The next tool needs a
/// tool or a parameter to give way first; the budget test fails the build before a request would fail at
/// the provider. MCP clients still see every parameter: only what the analyst is offered is reduced, and
/// the tool's own default applies to what it is not offered.
/// </para>
/// </remarks>
internal static class McpAnalystTools
{
    /// <summary>The tools whose explicit <c>from</c>/<c>to</c> range the analyst keeps.</summary>
    internal static readonly IReadOnlySet<string> ExplicitRangeTools =
        new HashSet<string>(["attacks_summary", "top_sources", "attack_timeline", "coverage"], StringComparer.Ordinal);

    /// <summary>
    /// Parameters the analyst's schema leaves out, by tool. The MCP tool's own default applies to them.
    /// See the remarks above for why each one.
    /// </summary>
    internal static readonly IReadOnlyDictionary<string, IReadOnlySet<string>> ServerDefaults =
        new Dictionary<string, IReadOnlySet<string>>(StringComparer.Ordinal)
        {
            ["attack_timeline"] = Names("bucket"),
            ["decisions"] = Names("limit"),
            ["evidence_events"] = Names("limit"),
            ["web_summary"] = Names("site"),
            ["web_top_sources"] = Names("site", "limit"),
            ["web_findings"] = Names("site", "address", "limit")
        };

    private static readonly string[] ExplicitRange = ["from", "to"];

    private static HashSet<string> Names(params string[] names) => new(names, StringComparer.Ordinal);

    public static IReadOnlyList<IAnalystTool> Create(EvidenceTools tools)
    {
        ArgumentNullException.ThrowIfNull(tools);
        var target = new WPShieldMcpTools(tools);
        var result = new List<IAnalystTool>();
        foreach (var method in typeof(WPShieldMcpTools).GetMethods(BindingFlags.Public | BindingFlags.Instance))
        {
            if (!method.IsDefined(typeof(McpServerToolAttribute), inherit: false)) continue;
            RequireReadOnly(method);
            var protocol = McpServerTool.Create(method, target).ProtocolTool;
            result.Add(new Tool(target, method, protocol.Name, protocol.Description ?? "", StrictSchema(protocol.Name, protocol.InputSchema)));
        }
        return [.. result.OrderBy(t => t.Name, StringComparer.Ordinal)];
    }

    /// <summary>
    /// Refuses a tool that is not declared read-only and non-destructive. Every MCP tool reaches the analyst
    /// without a change here, so this is what keeps an action tool - which ADR 0008, section 2 says needs its
    /// own ADR and a confirmation outside the model - from reaching a model that reads attacker text
    /// (ADR 0010, section 2). It throws rather than skipping: a silently missing tool would hide the change.
    /// </summary>
    internal static void RequireReadOnly(MethodInfo method)
    {
        var tool = method.GetCustomAttribute<McpServerToolAttribute>(inherit: false)
            ?? throw new InvalidOperationException($"{method.Name} is not an MCP tool.");
        if (!tool.ReadOnly || tool.Destructive)
            throw new InvalidOperationException(
                $"The MCP tool {tool.Name ?? method.Name} is not declared read-only and non-destructive, so the analyst refuses it (ADR 0010, section 2).");
    }

    /// <summary>The MCP input schema, reduced to what strict tool use accepts. See the remarks above.</summary>
    internal static JsonObject StrictSchema(string tool, JsonElement inputSchema)
    {
        var source = JsonNode.Parse(inputSchema.GetRawText()) as JsonObject
            ?? throw new InvalidOperationException($"The MCP schema of {tool} is not an object.");
        var keep = ExplicitRangeTools.Contains(tool);
        var omitted = ServerDefaults.GetValueOrDefault(tool);
        var properties = new JsonObject();
        foreach (var (name, node) in source["properties"] as JsonObject ?? [])
        {
            if (!keep && ExplicitRange.Contains(name, StringComparer.Ordinal)) continue;
            if (omitted?.Contains(name) == true) continue;
            var property = new JsonObject { ["type"] = PlainType(tool, name, node?["type"]) };
            if (node?["description"] is JsonValue description) property["description"] = description.DeepClone();
            properties[name] = property;
        }
        var required = (source["required"] as JsonArray ?? [])
            .Select(n => n!.GetValue<string>()).Where(n => properties.ContainsKey(n)).ToArray();
        return new JsonObject
        {
            ["type"] = "object",
            ["properties"] = properties,
            ["required"] = new JsonArray([.. required.Select(r => (JsonNode)r)]),
            ["additionalProperties"] = false
        };
    }

    private static string PlainType(string tool, string name, JsonNode? type)
    {
        switch (type)
        {
            case JsonValue value when value.TryGetValue<string>(out var single):
                return single;
            case JsonArray types:
                var concrete = types.Select(t => t?.GetValue<string>()).Where(t => t is not null and not "null").ToArray();
                if (concrete.Length == 1) return concrete[0]!;
                break;
        }
        throw new InvalidOperationException($"{tool}.{name} has a type the analyst's strict schemas cannot express.");
    }

    /// <summary>One MCP tool function, bound to the instance <c>wpshield mcp</c> would serve.</summary>
    private sealed class Tool(WPShieldMcpTools target, MethodInfo method, string name, string description, JsonObject schema) : IAnalystTool
    {
        public string Name { get; } = name;

        public string Description { get; } = description;

        public JsonObject InputSchema { get; } = schema;

        public AnalystToolResult Invoke(JsonObject arguments, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var properties = (JsonObject)InputSchema["properties"]!;
            var unknown = arguments.Select(a => a.Key).FirstOrDefault(k => !properties.ContainsKey(k));
            if (unknown is not null) return Invalid($"{Name} has no argument '{ReportText.Line(unknown, 40)}'.");

            var parameters = method.GetParameters();
            var values = new object?[parameters.Length];
            for (var i = 0; i < parameters.Length; i++)
            {
                var parameter = parameters[i];
                var given = properties.ContainsKey(parameter.Name!) ? arguments[parameter.Name!] : null;
                if (given is null)
                {
                    if (!parameter.HasDefaultValue) return Invalid($"{Name} needs the argument '{parameter.Name}'.");
                    values[i] = parameter.DefaultValue;
                    continue;
                }
                var type = Nullable.GetUnderlyingType(parameter.ParameterType) ?? parameter.ParameterType;
                if (Bind(type, given) is not { } bound)
                    return Invalid($"{Name}: '{parameter.Name}' must be {(type == typeof(int) ? "a whole number" : "text")}.");
                values[i] = bound;
            }
            var answer = (CallToolResult)method.Invoke(target, values)!;
            var text = answer.Content.OfType<TextContentBlock>().FirstOrDefault()?.Text
                ?? EvidenceTools.Failure(Name, "internal-error", "The tool returned no text.").ToJson();
            return new AnalystToolResult(text, answer.IsError == true);
        }

        private static object? Bind(Type type, JsonNode node)
        {
            if (node is not JsonValue value) return null;
            if (type == typeof(string)) return value.TryGetValue<string>(out var text) ? text : null;
            if (type == typeof(int))
            {
                if (value.TryGetValue<int>(out var number)) return number;
                if (value.TryGetValue<double>(out var real) && real == Math.Floor(real) && real is >= int.MinValue and <= int.MaxValue)
                    return (int)real;
                return value.TryGetValue<string>(out var digits) && int.TryParse(digits, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed)
                    ? parsed : null;
            }
            return null;
        }

        private AnalystToolResult Invalid(string message) =>
            new(EvidenceTools.Failure(Name, "invalid-argument", message).ToJson(), IsError: true);
    }
}
