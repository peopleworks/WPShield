using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Nodes;
using Anthropic;
using Anthropic.Exceptions;
using Anthropic.Models.Beta.Messages;
using WPShield.Evidence;

namespace WPShield.Analyst;

/// <summary>
/// The Anthropic Messages API, through the official SDK: the Anthropic provider, and the PeopleWorks
/// Relay, which is the same SDK pointed at <c>analyst.relay_url</c> (ADR 0010, section 7).
/// </summary>
/// <remarks>
/// <para>
/// <b>The client is never built bare.</b> Left to itself the SDK resolves a credential from
/// <c>ANTHROPIC_AUTH_TOKEN</c>, from profiles on disk and from workload-identity variables, and a base
/// address from <c>ANTHROPIC_BASE_URL</c>. The key here is passed explicitly, which the SDK documents as
/// reading nothing else, and so is the base address. Redirects are refused: a redirect would carry the
/// key's header to an address nobody chose.
/// </para>
/// <para>
/// Requests are not streamed. The Relay's responder lane answers in one piece and refuses
/// <c>stream: true</c>, and a turn's output is capped well under the SDK's non-streaming limits.
/// </para>
/// </remarks>
internal sealed class MessagesProvider : IAnalystProvider, IDisposable
{
    public const string FallbackBeta = "server-side-fallback-2026-07-01";
    public static readonly Uri AnthropicBaseUrl = new("https://api.anthropic.com");

    private readonly AnthropicClient client;
    private readonly HttpClient http;
    private readonly string key;
    private readonly Uri baseUrl;
    private readonly string model;
    private readonly string effort;

    private MessagesProvider(string name, string key, Uri baseUrl, string model, string effort, HttpMessageHandler? handler)
    {
        Name = name;
        this.key = key;
        this.baseUrl = baseUrl;
        this.model = model;
        this.effort = effort;
        http = new HttpClient(handler ?? new SocketsHttpHandler { AllowAutoRedirect = false }, disposeHandler: handler is null)
        {
            // The SDK applies its own timeout; HttpClient's 100-second default would cut a long turn short.
            Timeout = Timeout.InfiniteTimeSpan
        };
        client = new AnthropicClient
        {
            ApiKey = key,
            BaseUrl = baseUrl.ToString().TrimEnd('/'),
            HttpClient = http,
            MaxRetries = 2,
            Timeout = AnalystRunner.RunTimeout
        };
    }

    public string Name { get; }

    public bool OperatorPays => Name == "anthropic";

    private bool IsRelay => Name == "relay";

    /// <summary>The Anthropic API, with server-side fallback on a refusal.</summary>
    public static MessagesProvider Anthropic(string key, string model, string effort, HttpMessageHandler? handler = null, Uri? baseUrl = null) =>
        new("anthropic", key, baseUrl ?? AnthropicBaseUrl, model, effort, handler);

    /// <summary>The PeopleWorks Relay's <c>/v1/messages</c> lane. No server-side fallback through it.</summary>
    public static MessagesProvider Relay(string key, Uri relayUrl, string model, string effort, HttpMessageHandler? handler = null)
    {
        if (AnalystSettings.ValidateRelayUrl(relayUrl.ToString()) is { } problem)
            throw new ArgumentException("analyst.relay_url must be " + problem + ".", nameof(relayUrl));
        return new("relay", key, relayUrl, model, effort, handler);
    }

    public IAnalystConversation Begin(AnalystConversationSpec spec) => new Conversation(this, spec);

    public async Task<ProviderCheck> TestAsync(CancellationToken cancellationToken)
    {
        try
        {
            return IsRelay ? await WhoAmIAsync(cancellationToken) : await ModelCheckAsync(cancellationToken);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            return new ProviderCheck(false, Describe(exception), []);
        }
    }

    /// <summary>The Anthropic API: reading the model's entry proves the key and the model without spending a token.</summary>
    private async Task<ProviderCheck> ModelCheckAsync(CancellationToken cancellationToken)
    {
        var info = await client.Models.Retrieve(model, cancellationToken: cancellationToken);
        return new ProviderCheck(true, "The Anthropic API accepted the key and knows the model.",
        [
            new("model", Clean(info.ID, 100)),
            new("display name", Clean(info.DisplayName, 100))
        ]);
    }

    /// <summary>
    /// The Relay: <c>GET /v1/auth/whoami</c>. A Relay token issued for another project still answers
    /// <c>200</c> on <c>/v1/messages</c>, so naming the project the token belongs to is the only cheap way
    /// to see that it is the wrong one.
    /// </summary>
    private async Task<ProviderCheck> WhoAmIAsync(CancellationToken cancellationToken)
    {
        // Resolved against the base with a trailing slash, so a Relay under a path prefix keeps its prefix.
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(new Uri(baseUrl.ToString().TrimEnd('/') + "/"), "v1/auth/whoami"));
        request.Headers.Add("x-api-key", key);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));
        using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
        var body = await ReadBoundedAsync(response.Content, 16 * 1024, timeout.Token);
        if (response.StatusCode != HttpStatusCode.OK)
            return new ProviderCheck(false,
                $"The Relay answered {(int)response.StatusCode} {Clean(response.ReasonPhrase, 60)}: {RelayError(body)}", []);
        return RelayIdentity.Parse(body) is { } identity
            ? new ProviderCheck(true, $"The Relay accepted the token. It belongs to project '{identity.Project}'.", identity.Details())
            : new ProviderCheck(false, "The Relay answered 200, but not with a project: this is not the WPShield-compatible whoami answer.", []);
    }

    private string RelayError(string body)
    {
        try
        {
            var message = JsonNode.Parse(body)?["error"]?["message"]?.GetValue<string>();
            if (!string.IsNullOrEmpty(message)) return Clean(message, 300);
        }
        catch (Exception exception) when (exception is JsonException or InvalidOperationException or FormatException)
        {
        }
        return "no error message";
    }

    private static async Task<string> ReadBoundedAsync(HttpContent content, int max, CancellationToken cancellationToken)
    {
        await using var stream = await content.ReadAsStreamAsync(cancellationToken);
        var buffer = new byte[max];
        var total = 0;
        int read;
        while (total < max && (read = await stream.ReadAsync(buffer.AsMemory(total, max - total), cancellationToken)) > 0) total += read;
        return System.Text.Encoding.UTF8.GetString(buffer, 0, total);
    }

    private string Clean(string? text, int max) => SecretScrubber.Scrub(text, key, max);

    /// <summary>Every provider failure, in words the operator can act on and with the key removed.</summary>
    internal string Describe(Exception exception)
    {
        var what = exception switch
        {
            AnthropicUnauthorizedException => IsRelay ? "The Relay refused the token (401)." : "The Anthropic API refused the key (401).",
            AnthropicForbiddenException => "The provider refused this key for that request (403).",
            AnthropicNotFoundException => "The provider does not know that model or address (404).",
            AnthropicRateLimitException => "The provider is rate limiting this key (429). Try again later.",
            Anthropic5xxException => "The provider failed on its side (5xx). Try again later.",
            AnthropicApiException => "The provider refused the request.",
            HttpRequestException => IsRelay ? "The Relay could not be reached." : "The Anthropic API could not be reached.",
            _ => "The request to the provider failed."
        };
        return $"{what} {Clean(exception.Message, 300)} ({exception.GetType().Name})".TrimEnd();
    }

    public void Dispose()
    {
        client.Dispose();
        http.Dispose();
    }

    /// <summary>
    /// One run's conversation. The system prompt and the tool list are fixed at the start, and every
    /// block of every response is echoed back unchanged - thinking blocks with their signatures, and a
    /// fallback marker where it appeared - so the history is append-only.
    /// </summary>
    private sealed class Conversation(MessagesProvider provider, AnalystConversationSpec spec) : IAnalystConversation
    {
        private readonly List<BetaMessageParam> messages = [];
        private readonly List<BetaToolUnion> tools = [.. spec.Tools.Select(Tool)];
        private IReadOnlyList<string> pending = [];

        public async Task<ProviderTurn> NextAsync(IReadOnlyList<AnalystToolOutcome> outcomes, CancellationToken cancellationToken)
        {
            if (messages.Count == 0)
                messages.Add(new BetaUserMessageParam { Content = spec.FirstMessage });
            else
                messages.Add(new BetaUserMessageParam { Content = Results(outcomes) });

            BetaMessage response;
            try
            {
                response = await provider.client.Beta.Messages.Create(Request(), cancellationToken: cancellationToken);
            }
            catch (Exception exception) when (exception is not OperationCanceledException)
            {
                throw new AnalystProviderException(provider.Describe(exception));
            }

            var (echo, calls, text, fellBack) = Read(response);
            messages.Add(new BetaAssistantMessageParam { Content = echo });
            pending = [.. calls.Select(c => c.Id)];
            var refusal = response.StopDetails;
            var stopReason = response.StopReason?.Raw() ?? "unknown";
            fellBack |= response.Usage.Iterations?.Any(i => i.TryPickBetaFallbackMessageIterationUsage(out _)) == true;
            return new ProviderTurn(
                Model: provider.Clean(response.Model.Raw(), 100),
                StopReason: provider.Clean(stopReason, 40),
                RefusalCategory: refusal?.Category is { } category ? provider.Clean(category.Raw(), 60) : null,
                RefusalExplanation: refusal?.Explanation is { } explanation ? provider.Clean(explanation, 500) : null,
                Text: text,
                ToolCalls: calls,
                InputTokens: response.Usage.InputTokens + (response.Usage.CacheCreationInputTokens ?? 0) + (response.Usage.CacheReadInputTokens ?? 0),
                OutputTokens: response.Usage.OutputTokens,
                FellBack: fellBack);
        }

        private MessageCreateParams Request() => new()
        {
            Model = provider.model,
            MaxTokens = spec.MaxOutputTokens,
            System = spec.SystemPrompt,
            Messages = messages,
            Tools = tools,
            ToolChoice = new BetaToolChoiceAuto(),
            Thinking = new BetaThinkingConfigAdaptive(),
            OutputConfig = new BetaOutputConfig { Effort = EffortOf(provider.effort) },
            // Every turn re-sends the conversation; caching its prefix makes those re-reads cheaper. The
            // budget still counts cached input tokens as input tokens.
            CacheControl = new BetaCacheControlEphemeral(),
            // Server-side fallback on a refusal, on the Anthropic API only: the Relay forwards to a host
            // whose configuration WPShield does not know, and it offers no such retry.
            Betas = provider.IsRelay ? null : [FallbackBeta],
            Fallbacks = provider.IsRelay ? null : (BetaFallbacksParam)new Default()
        };

        private List<BetaContentBlockParam> Results(IReadOnlyList<AnalystToolOutcome> outcomes)
        {
            // Every tool_use in the previous turn needs exactly one tool_result, or the API refuses the request.
            if (outcomes.Count != pending.Count || outcomes.Select(o => o.CallId).Except(pending).Any())
                throw new InvalidOperationException("Every tool call of the previous turn needs exactly one result.");
            return [.. outcomes.Select(o => (BetaContentBlockParam)new BetaToolResultBlockParam
            {
                ToolUseID = o.CallId,
                Content = o.Json,
                IsError = o.IsError
            })];
        }

        /// <summary>
        /// The response as a message to echo, the tool calls to run and the text to report. After a
        /// mid-output fallback, the declined model's thinking and tool calls before the last fallback
        /// marker are not echoed and not run; the marker itself stays where it was.
        /// </summary>
        private (List<BetaContentBlockParam> Echo, List<AnalystToolCall> Calls, string Text, bool FellBack) Read(BetaMessage response)
        {
            var blocks = response.Content;
            var boundary = -1;
            for (var i = 0; i < blocks.Count; i++)
                if (blocks[i].TryPickFallback(out _)) boundary = i;
            var echo = new List<BetaContentBlockParam>();
            var calls = new List<AnalystToolCall>();
            var text = new List<string>();
            for (var i = 0; i < blocks.Count; i++)
            {
                var block = blocks[i];
                var beforeBoundary = i < boundary;
                if (block.TryPickText(out var t))
                {
                    echo.Add(new BetaTextBlockParam { Text = t.Text });
                    text.Add(t.Text);
                }
                else if (block.TryPickThinking(out var thinking))
                {
                    if (!beforeBoundary) echo.Add(new BetaThinkingBlockParam { Thinking = thinking.Thinking, Signature = thinking.Signature });
                }
                else if (block.TryPickRedactedThinking(out var redacted))
                {
                    if (!beforeBoundary) echo.Add(new BetaRedactedThinkingBlockParam { Data = redacted.Data });
                }
                else if (block.TryPickToolUse(out var use))
                {
                    if (beforeBoundary) continue;
                    echo.Add(new BetaToolUseBlockParam { ID = use.ID, Name = use.Name, Input = use.Input });
                    calls.Add(new AnalystToolCall(use.ID, use.Name, ToObject(use.Input)));
                }
                else if (block.TryPickFallback(out var fallback))
                {
                    echo.Add(new BetaFallbackBlockParam
                    {
                        From = new BetaFallbackInfoParam { Model = fallback.From.Model },
                        To = new BetaFallbackInfoParam { Model = fallback.To.Model }
                    });
                }
                else
                {
                    // The analyst declares no server tool, so nothing else should arrive. Dropping an
                    // unknown block would make the next request's history differ from what the model wrote.
                    throw new AnalystProviderException("The provider returned a content block this version does not know; the run was stopped rather than continued with an altered history.");
                }
            }
            return (echo, calls, string.Join("\n\n", text.Where(s => s.Length > 0)), boundary >= 0);
        }

        private static JsonObject ToObject(IReadOnlyDictionary<string, JsonElement> input)
        {
            var result = new JsonObject();
            foreach (var (name, value) in input) result[name] = JsonNode.Parse(value.GetRawText());
            return result;
        }

        private static BetaToolUnion Tool(IAnalystTool tool) => new BetaTool
        {
            Name = tool.Name,
            Description = tool.Description,
            InputSchema = InputSchema.FromRawUnchecked(tool.InputSchema.ToDictionary(p => p.Key, p => JsonSerializer.SerializeToElement(p.Value))),
            Strict = true
        };

        private static Effort EffortOf(string effort) => effort switch
        {
            "low" => Effort.Low,
            "high" => Effort.High,
            "xhigh" => Effort.Xhigh,
            "max" => Effort.Max,
            _ => Effort.Medium
        };
    }
}

/// <summary>The Relay's answer to <c>GET /v1/auth/whoami</c>: which project the token belongs to.</summary>
internal sealed record RelayIdentity(string Project, string? Label, string? DefaultModel, string? Billing)
{
    /// <summary>
    /// Parses <c>{"proyecto": ..., "etiqueta": ..., "modelo_default": ..., "facturacion": ...}</c>. Every
    /// value is cleaned before it can reach a terminal. Null when the body names no project.
    /// </summary>
    public static RelayIdentity? Parse(string body)
    {
        JsonObject? json;
        try
        {
            json = JsonNode.Parse(body) as JsonObject;
        }
        catch (JsonException)
        {
            return null;
        }
        if (json is null) return null;
        string? Text(string name) => json[name] is JsonValue v && v.TryGetValue<string>(out var s) && s.Length > 0
            ? EvidenceText.Clean(s, 100) : null;
        var project = Text("proyecto");
        return project is null ? null : new RelayIdentity(project, Text("etiqueta"), Text("modelo_default"), Text("facturacion"));
    }

    public IReadOnlyList<KeyValuePair<string, string>> Details()
    {
        var details = new List<KeyValuePair<string, string>> { new("project", Project) };
        if (Label is not null) details.Add(new("token label", Label));
        if (DefaultModel is not null) details.Add(new("relay default model", DefaultModel));
        if (Billing is not null) details.Add(new("billing", Billing));
        return details;
    }
}
