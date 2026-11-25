using System.Net;
using System.Text;
using System.Text.Json.Nodes;

namespace WPShield.Analyst.Tests;

/// <summary>
/// An HTTP handler that answers from a script and records every request, so the SDK runs exactly as it
/// would against a provider while nothing leaves the process. No test calls a real provider.
/// </summary>
internal sealed class FakeHandler : HttpMessageHandler
{
    private readonly Queue<Func<HttpRequestMessage, string, HttpResponseMessage>> answers = new();

    public List<Recorded> Requests { get; } = [];

    public FakeHandler Then(HttpStatusCode status, string json)
    {
        answers.Enqueue((_, _) => new HttpResponseMessage(status)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        });
        return this;
    }

    public FakeHandler Then(Func<HttpRequestMessage, string, HttpResponseMessage> answer)
    {
        answers.Enqueue(answer);
        return this;
    }

    public FakeHandler ThenJson(string json) => Then(HttpStatusCode.OK, json);

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(cancellationToken);
        var headers = request.Headers.Concat(request.Content?.Headers ?? Enumerable.Empty<KeyValuePair<string, IEnumerable<string>>>())
            .ToDictionary(h => h.Key, h => string.Join(",", h.Value), StringComparer.OrdinalIgnoreCase);
        Requests.Add(new Recorded(request.Method, request.RequestUri!, headers, body));
        if (answers.Count == 0) throw new InvalidOperationException("The fake provider has no answer left: " + request.RequestUri);
        return answers.Dequeue()(request, body);
    }

    internal sealed record Recorded(HttpMethod Method, Uri Uri, IReadOnlyDictionary<string, string> Headers, string Body)
    {
        public JsonObject Json => (JsonObject)JsonNode.Parse(Body)!;
    }

    /// <summary>A Messages API response, in the wire shape.</summary>
    internal static string Message(string stopReason, string content, string model = "claude-opus-5-5", long input = 1000, long output = 200,
        string stopDetails = "null", string iterations = "null") =>
        "{\"id\":\"msg_test\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"" + model + "\",\"content\":[" + content + "]," +
        "\"stop_reason\":\"" + stopReason + "\",\"stop_sequence\":null,\"stop_details\":" + stopDetails + "," +
        "\"usage\":{\"input_tokens\":" + input + ",\"output_tokens\":" + output +
        ",\"cache_creation_input_tokens\":0,\"cache_read_input_tokens\":0,\"iterations\":" + iterations + "}}";

    internal static string Text(string text) => "{\"type\":\"text\",\"text\":" + System.Text.Json.JsonSerializer.Serialize(text) + ",\"citations\":null}";

    internal static string Thinking(string signature) => $$"""{"type":"thinking","thinking":"","signature":"{{signature}}"}""";

    internal static string ToolUse(string id, string name, string input) =>
        "{\"type\":\"tool_use\",\"id\":\"" + id + "\",\"name\":\"" + name + "\",\"input\":" + input + ",\"caller\":{\"type\":\"direct\"}}";
}
