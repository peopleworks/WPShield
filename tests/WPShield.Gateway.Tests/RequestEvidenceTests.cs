using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Threading.Channels;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using WPShield.Abstractions;
using WPShield.Core;
using WPShield.Logging;

namespace WPShield.Gateway.Tests;

public sealed class RequestEvidenceTests
{
    [Theory]
    [InlineData("Monitor", false, "complete", "Observe", "forwarded", 200)]
    [InlineData("Block", false, "complete", "Block", "rejected", 403)]
    [InlineData("Disabled", false, "not_inspected", null, "forwarded", 200)]
    [InlineData("Monitor", true, "partial", null, "forwarded", 200)]
    [InlineData("Block", true, "partial", null, "rejected", 415)]
    public async Task FinalEvent_DistinguishesInspectionFromOutcome(
        string mode, bool malformed, string status, string? action, string disposition, int httpStatus)
    {
        await using var harness = await Harness.StartAsync(mode);
        using var request = Upload(malformed);
        using var response = await harness.Client.SendAsync(request);
        var evidence = await harness.NextAsync();

        Assert.Equal(httpStatus, (int)response.StatusCode);
        Assert.Equal(httpStatus, evidence["StatusCode"]);
        Assert.Equal(status, evidence["UploadStatus"]);
        Assert.Equal(action, evidence["UploadAction"]);
        Assert.Equal(disposition, evidence["Disposition"]);
        Assert.Equal(disposition == "forwarded", evidence["ForwardingAttempted"]);
        Assert.Equal(mode == "Disabled" ? "not_inspected" : "complete", evidence["PathStatus"]);
        Assert.Equal(mode, evidence["Mode"]);
        var metrics = EvidenceMetricSnapshot.Read(harness.Metrics);
        Assert.Equal(mode == "Disabled" ? 2 : 0, metrics["wpshield.evidence.skipped_stages"]);
        Assert.Equal(0, metrics["wpshield.evidence.degraded"]);
        Assert.Equal(0, metrics["wpshield.evidence.file_enabled"]);
        Assert.Equal("one", evidence["SiteId"]);
        Assert.Equal(Assert.Single(response.Headers.GetValues("X-WPShield-Request-ID")), evidence["RequestId"]);
        Assert.Equal(1, evidence["SchemaVersion"]);
        Assert.True(Guid.TryParseExact(Assert.IsType<string>(evidence["ConfigurationRevision"]), "N", out _));
        foreach (var version in new[] { "GatewayVersion", "EngineVersion", "WindowsRulesVersion", "WordPressRulesVersion" })
        {
            Assert.NotEqual("unknown", Assert.IsType<string>(evidence[version]));
        }
        if (malformed)
        {
            Assert.Equal("malformed", evidence["UploadReason"]);
            Assert.Null(evidence["UploadScore"]);
            Assert.Equal(0, evidence["FilesRead"]);
        }
        else if (mode != "Disabled")
        {
            Assert.Equal(90, evidence["UploadScore"]);
            Assert.Contains("WP-UPLOAD-001", Assert.IsType<string>(evidence["UploadRuleIds"]), StringComparison.Ordinal);
            Assert.Equal(1, evidence["FilesInspected"]);
        }
        Assert.Single(harness.Logs.Events);
    }

    [Fact]
    public async Task CompleteBenignSample_IsDifferentFromSkipping_AndDoesNotClaimFullContentCoverage()
    {
        await using var harness = await Harness.StartAsync("Monitor", settings: new()
        {
            ["Gateway:Multipart:SampleBytes"] = "512"
        });
        using var request = Upload(fileName: "note.txt", content: new string('a', 2048));
        using var response = await harness.Client.SendAsync(request);
        var evidence = await harness.NextAsync();
        Assert.Equal("complete", evidence["UploadStatus"]);
        Assert.Equal("sampled_scope", evidence["UploadReason"]);
        Assert.Equal("Allow", evidence["UploadAction"]);
        Assert.Equal(0, evidence["UploadScore"]);
        Assert.Equal("", evidence["UploadRuleIds"]);
        Assert.Equal(512L, evidence["SampleBytesInspected"]);
        Assert.Equal(512, evidence["SampleLimitBytes"]);
    }

    [Theory]
    [InlineData(false, "non_multipart")]
    [InlineData(true, "inspection_disabled")]
    public async Task SkippedBody_HasReasonAndNoInventedAllow(bool disabled, string reason)
    {
        await using var harness = await Harness.StartAsync("Monitor", settings: new()
        {
            ["Gateway:Multipart:Enabled"] = disabled ? "false" : "true"
        });
        using var request = new HttpRequestMessage(HttpMethod.Post, "/") { Content = new StringContent("synthetic") };
        using var response = await harness.Client.SendAsync(request);
        var evidence = await harness.NextAsync();
        Assert.Equal("not_inspected", evidence["UploadStatus"]);
        Assert.Equal(reason, evidence["UploadReason"]);
        Assert.Null(evidence["UploadScore"]);
        Assert.Null(evidence["UploadAction"]);
    }

    [Theory]
    [InlineData("Monitor", "forwarded", 200)]
    [InlineData("Block", "rejected", 415)]
    public async Task ParserLimit_PreservesPartialFindings(string mode, string disposition, int status)
    {
        await using var harness = await Harness.StartAsync(mode, settings: new()
        {
            ["Gateway:Multipart:MaximumFileCount"] = "1"
        });
        using var request = Upload(fileName: "note.txt", secondFile: true);
        using var response = await harness.Client.SendAsync(request);
        var evidence = await harness.NextAsync();
        Assert.Equal(status, (int)response.StatusCode);
        Assert.Equal("partial", evidence["UploadStatus"]);
        Assert.Equal("limit_exceeded", evidence["UploadReason"]);
        Assert.Equal(1, evidence["FilesInspected"]);
        Assert.Equal(0, evidence["UploadScore"]);
        Assert.Equal(disposition, evidence["Disposition"]);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task ForwardingFailure_DoesNotBecomeSuccessfulForward(bool malformed)
    {
        await using var harness = await Harness.StartAsync("Monitor", new Backend(fail: true));
        using var request = Upload(malformed);
        using var response = await harness.Client.SendAsync(request);
        var evidence = await harness.NextAsync();
        Assert.Equal(HttpStatusCode.BadGateway, response.StatusCode);
        Assert.Equal("forwarding_failed", evidence["Disposition"]);
        Assert.Equal("backend_unavailable", evidence["Reason"]);
        Assert.Equal(true, evidence["ForwardingAttempted"]);
        Assert.Equal(malformed ? "partial" : "complete", evidence["UploadStatus"]);
        Assert.DoesNotContain(harness.Logs.Messages, message => message.Contains("Disposition=forwarded", StringComparison.Ordinal));
        Assert.DoesNotContain(harness.Logs.Messages, message => message.Contains("synthetic-exception-secret", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData("Monitor", "forwarded", 200)]
    [InlineData("Block", "rejected", 429)]
    public async Task CapacityExhaustion_IsNotACompletedInspection(string mode, string disposition, int status)
    {
        var backend = new Backend(holdFirst: true);
        await using var harness = await Harness.StartAsync(mode, backend, new()
        {
            ["Gateway:Multipart:MaximumConcurrentInspections"] = "1"
        });
        using var firstRequest = Upload(fileName: "note.txt");
        var first = harness.Client.SendAsync(firstRequest);
        try
        {
            await backend.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            using var secondRequest = Upload(fileName: "note.txt");
            using var second = await harness.Client.SendAsync(secondRequest);
            var skipped = await harness.NextAsync();
            Assert.Equal(status, (int)second.StatusCode);
            Assert.Equal("not_inspected", skipped["UploadStatus"]);
            Assert.Equal("capacity_exhausted", skipped["UploadReason"]);
            Assert.Null(skipped["UploadAction"]);
            Assert.Equal(disposition, skipped["Disposition"]);
        }
        finally
        {
            backend.Release.TrySetResult();
            using var response = await first;
        }
        var completed = await harness.NextAsync();
        Assert.Equal("complete", completed["UploadStatus"]);
        Assert.Equal("forwarded", completed["Disposition"]);
        Assert.Equal(2, harness.Logs.Events.Count);
    }

    [Fact]
    public async Task CancellationDuringForward_RetainsCompletedInspectionButNotSuccess()
    {
        var backend = new Backend(holdFirst: true);
        await using var harness = await Harness.StartAsync("Monitor", backend);
        using var cancellation = new CancellationTokenSource();
        using var request = Upload(fileName: "note.txt");
        var send = harness.Client.SendAsync(request, cancellation.Token);
        await backend.Entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
        await cancellation.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => send);
        var evidence = await harness.NextAsync();
        Assert.Equal("cancelled", evidence["Disposition"]);
        Assert.Equal("request_cancelled", evidence["Reason"]);
        Assert.Equal("complete", evidence["UploadStatus"]);
        Assert.Equal(true, evidence["ForwardingAttempted"]);
        Assert.Null(evidence["StatusCode"]);
    }

    [Theory]
    [InlineData("unknown.example", "/", "unknown_host", "not_started", 421)]
    [InlineData("one.example", "/wp-content/uploads/sample.php", "request_blocked", "complete", 403)]
    public async Task EarlyRefusal_DoesNotInventBodyInspection(string host, string path, string reason, string pathStatus, int status)
    {
        await using var harness = await Harness.StartAsync("Block");
        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Host = host;
        using var response = await harness.Client.SendAsync(request);
        var evidence = await harness.NextAsync();
        Assert.Equal(status, (int)response.StatusCode);
        Assert.Equal("rejected", evidence["Disposition"]);
        Assert.Equal(reason, evidence["Reason"]);
        Assert.Equal(pathStatus, evidence["PathStatus"]);
        Assert.Equal("not_started", evidence["UploadStatus"]);
        Assert.Equal(false, evidence["ForwardingAttempted"]);
    }

    [Fact]
    public async Task Identity_IsStableWithinActivation_AndChangesOnRestart_WithoutInputSecrets()
    {
        string? previousRevision = null;
        for (var activation = 0; activation < 2; activation++)
        {
            await using var harness = await Harness.StartAsync("Monitor");
            string? revision = null;
            for (var index = 0; index < 2; index++)
            {
                using var request = Upload(fileName: "private-filename.txt", content: "private-body");
                request.RequestUri = new Uri("/private-path?key=private-query", UriKind.Relative);
                request.Headers.TryAddWithoutValidation("Authorization", "Bearer private-auth");
                request.Headers.TryAddWithoutValidation("Cookie", "session=private-cookie");
                request.Headers.TryAddWithoutValidation("X-Forwarded-For", "192.0.2.99");
                using var response = await harness.Client.SendAsync(request);
                var evidence = await harness.NextAsync();
                Assert.DoesNotContain("private-", string.Join(' ', evidence.Values), StringComparison.Ordinal);
                Assert.Equal("unknown", evidence["Client"]); // TestServer has no peer; spoofed XFF stays untrusted.
                var current = Assert.IsType<string>(evidence["ConfigurationRevision"]);
                if (revision is not null) Assert.Equal(revision, current);
                revision = current;
            }
            Assert.NotEqual(previousRevision, revision);
            previousRevision = revision;
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task InterruptedRead_PreservesPartialStateAndPropagates(bool cancelled)
    {
        using var limiter = new ConcurrentInspectionLimiter(1);
        var service = new UploadInspectionService(new InspectionEngine([]), new MultipartInspectionReader(), limiter);
        using var stream = new FailingStream(cancelled);
        var context = new DefaultHttpContext();
        var evidence = new RequestEvidence();
        context.Features.Set(evidence);
        context.Request.ContentType = "multipart/form-data; boundary=synthetic";
        context.Request.Body = stream;
        var error = await Record.ExceptionAsync(async () => await service.EvaluateAsync(context,
            new SiteOptions { Id = "one", Hosts = ["one.example"], Destination = new Uri("http://127.0.0.1:0"), Mode = ProtectionMode.Monitor }, new GatewayOptions(),
            new MultipartInspectionOptions(), NullLogger.Instance, new CancellationToken(cancelled)));
        Assert.NotNull(error);
        Assert.Equal("partial", evidence.Upload.Status);
        Assert.Equal(cancelled ? "request_cancelled" : "interrupted", evidence.Upload.Reason);
        Assert.Null(evidence.Upload.Action);
        Assert.Null(evidence.FilesRead);
        Assert.Equal(0, limiter.CurrentCount);
    }

    [Fact]
    public async Task ReadTimeout_RecordsPartialInspectionAndNoForward()
    {
        await using var harness = await Harness.StartAsync("Monitor", settings: new()
        {
            ["Gateway:Multipart:ReadTimeoutSeconds"] = "1"
        });
        using var slow = new SlowStream();
        var result = await harness.SendContextAsync(context =>
        {
            context.Request.Method = "POST";
            context.Request.ContentType = "multipart/form-data; boundary=synthetic";
            context.Request.Body = slow;
        });
        var evidence = await harness.NextAsync();
        Assert.Equal(408, result.Response.StatusCode);
        Assert.Equal("partial", evidence["UploadStatus"]);
        Assert.Equal("read_timeout", evidence["UploadReason"]);
        Assert.Equal("rejected", evidence["Disposition"]);
        Assert.Equal("request_timeout", evidence["Reason"]);
        Assert.Equal(false, evidence["ForwardingAttempted"]);
    }

    [Fact]
    public async Task EvidenceAndForwarder_UseSameTrustedClient()
    {
        var backend = new Backend();
        await using var harness = await Harness.StartAsync("Monitor", backend, new()
        {
            ["Gateway:TrustedProxies:0"] = "127.0.0.1"
        });
        await harness.SendContextAsync(context =>
        {
            context.Connection.RemoteIpAddress = IPAddress.Loopback;
            context.Request.Headers["X-Forwarded-For"] = "192.0.2.99, 192.0.2.10";
        });
        var evidence = await harness.NextAsync();
        Assert.Equal("192.0.2.10", evidence["Client"]);
        Assert.Equal(evidence["Client"], backend.ForwardedClient);
    }

    [Fact]
    public void TooManyRuleIds_AreBoundedAndExplicitlyTruncated()
    {
        var stage = new InspectionEvidence();
        stage.Record(new InspectionResult("one", 90, InspectionAction.Observe,
            Enumerable.Range(0, 40).Select(index => new RuleFinding($"SYNTHETIC-{index:D3}", 1, "synthetic")).ToArray()));
        Assert.Equal(16, stage.RuleIds.Split(',').Length);
        Assert.True(stage.RuleIdsTruncated);
        Assert.Equal(90, stage.Score);
        stage.Record(new InspectionResult("one", 10, InspectionAction.Allow, []));
        Assert.Equal(90, stage.Score);
        Assert.Equal(InspectionAction.Observe, stage.Action);
    }

    [Fact]
    public async Task UnhandledReadFailure_EmitsOneFinalFailureAndPropagates()
    {
        await using var harness = await Harness.StartAsync("Monitor");
        using var stream = new FailingStream(false);
        await Assert.ThrowsAsync<IOException>(() => harness.SendContextAsync(context =>
        {
            context.Request.Method = "POST";
            context.Request.ContentType = "multipart/form-data; boundary=synthetic";
            context.Request.Body = stream;
        }));
        var evidence = await harness.NextAsync();
        Assert.Equal("failed", evidence["Disposition"]);
        Assert.Equal("pipeline_failure", evidence["Reason"]);
        Assert.Equal("partial", evidence["UploadStatus"]);
        Assert.Equal(false, evidence["ForwardingAttempted"]);
        Assert.Null(evidence["StatusCode"]);
        Assert.Single(harness.Logs.Events);
    }

    [Theory]
    [InlineData(true, "not_started")]
    [InlineData(false, "partial")]
    public async Task SizeRefusal_DescribesWhetherInspectionStarted(bool declared, string status)
    {
        await using var harness = await Harness.StartAsync("Monitor", settings: new()
        {
            ["Gateway:MaximumRequestBytes"] = "1024"
        });
        using var stream = new MemoryStream(new byte[2048]);
        var result = await harness.SendContextAsync(context =>
        {
            context.Request.Method = "POST";
            context.Request.ContentType = "multipart/form-data; boundary=synthetic";
            context.Request.ContentLength = declared ? stream.Length : null;
            context.Request.Body = stream;
        });
        var evidence = await harness.NextAsync();
        Assert.Equal(413, result.Response.StatusCode);
        Assert.Equal("rejected", evidence["Disposition"]);
        Assert.Equal("request_too_large", evidence["Reason"]);
        Assert.Equal(status, evidence["UploadStatus"]);
        Assert.Equal(false, evidence["ForwardingAttempted"]);
    }

    [Fact]
    public async Task BackendHttpError_IsACompletedExchange()
    {
        await using var harness = await Harness.StartAsync("Monitor", new Backend(status: HttpStatusCode.ServiceUnavailable));
        using var request = Upload(fileName: "note.txt");
        using var response = await harness.Client.SendAsync(request);
        var evidence = await harness.NextAsync();
        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.Equal("forwarded", evidence["Disposition"]);
        Assert.Equal("exchange_completed", evidence["Reason"]);
        Assert.Equal(503, evidence["StatusCode"]);
    }

    [Theory]
    [InlineData("Monitor", "forwarded", "complete")]
    [InlineData("Block", "rejected", "not_started")]
    public async Task RateBudget_RecordsExcessWithoutInventingInspection(string mode, string disposition, string pathStatus)
    {
        await using var harness = await Harness.StartAsync(mode, settings: new()
        {
            ["Gateway:RateLimit:Enabled"] = "true",
            ["Gateway:RateLimit:Rules:0:Id"] = "synthetic-login",
            ["Gateway:RateLimit:Rules:0:Paths:0"] = "/wp-login.php",
            ["Gateway:RateLimit:Rules:0:PermitLimit"] = "1",
            ["Gateway:RateLimit:Rules:0:WindowSeconds"] = "300"
        });
        using var first = await harness.Client.GetAsync("/wp-login.php");
        var firstEvidence = await harness.NextAsync();
        Assert.Null(firstEvidence["RateLimitRuleId"]);
        using var second = await harness.Client.GetAsync("/wp-login.php");
        var evidence = await harness.NextAsync();
        Assert.Equal("synthetic-login", evidence["RateLimitRuleId"]);
        Assert.Equal(disposition, evidence["Disposition"]);
        Assert.Equal(pathStatus, evidence["PathStatus"]);
    }

    private sealed class SlowStream : MemoryStream
    {
        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return 0;
        }
    }

    private static HttpRequestMessage Upload(bool malformed = false, string fileName = "sample.php",
        string content = "harmless synthetic text", bool secondFile = false)
    {
        var bytes = $"--synthetic\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{fileName}\"\r\n\r\n{content}\r\n";
        if (secondFile) bytes += "--synthetic\r\nContent-Disposition: form-data; name=\"file2\"; filename=\"note.txt\"\r\n\r\nsynthetic\r\n";
        bytes += "--synthetic--\r\n";
        var request = new HttpRequestMessage(HttpMethod.Post, "/wp-admin/async-upload.php") { Content = new ByteArrayContent(Encoding.ASCII.GetBytes(bytes)) };
        request.Content.Headers.TryAddWithoutValidation("Content-Type", malformed ? "multipart/form-data" : "multipart/form-data; boundary=synthetic");
        return request;
    }

    private sealed class FailingStream(bool cancelled) : MemoryStream
    {
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) =>
            cancelled ? ValueTask.FromCanceled<int>(cancellationToken) : ValueTask.FromException<int>(new IOException("synthetic"));
    }

    private sealed class Backend(bool fail = false, bool holdFirst = false, HttpStatusCode status = HttpStatusCode.OK) : HttpMessageHandler
    {
        private int _calls;
        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource Release { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public string? ForwardedClient { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (fail) throw new HttpRequestException("synthetic-exception-secret");
            ForwardedClient = request.Headers.TryGetValues("X-Forwarded-For", out var values) ? string.Join(',', values) : null;
            if (request.Content is not null) await request.Content.CopyToAsync(Stream.Null, cancellationToken);
            if (Interlocked.Increment(ref _calls) == 1 && holdFirst)
            {
                Entered.TrySetResult();
                await Release.Task.WaitAsync(cancellationToken);
            }
            return new HttpResponseMessage(status) { Content = new StringContent("synthetic") };
        }
    }

    private sealed class Harness(WebApplication app, EvidenceLogger logs) : IAsyncDisposable
    {
        public HttpClient Client { get; } = CreateClient(app);
        public EvidenceLogger Logs => logs;
        public EvidenceMetrics Metrics => app.Services.GetRequiredService<EvidenceMetrics>();
        public Task<Dictionary<string, object?>> NextAsync() => logs.Pending.Reader.ReadAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10));
        public Task<HttpContext> SendContextAsync(Action<HttpContext> configure) => app.GetTestServer().SendAsync(context =>
        {
            context.Request.Host = new HostString("one.example");
            configure(context);
        });

        public static async Task<Harness> StartAsync(string mode, Backend? backend = null, Dictionary<string, string?>? settings = null)
        {
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Testing" });
            builder.WebHost.UseTestServer();
            builder.Configuration.Sources.Clear();
            builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Gateway:Urls:0"] = "http://127.0.0.1:0",
                ["Sites:0:Id"] = "one",
                ["Sites:0:Hosts:0"] = "one.example",
                // The injected handler handles all traffic; no socket is opened at this placeholder.
                ["Sites:0:Destination"] = "http://127.0.0.1:51001",
                ["Sites:0:Mode"] = mode
            });
            if (settings is not null) builder.Configuration.AddInMemoryCollection(settings);
            builder.Services.AddSingleton<HttpMessageInvoker>(_ => new HttpMessageInvoker(backend ?? new Backend()));
            var logs = new EvidenceLogger();
            builder.Logging.AddProvider(logs);
            var app = GatewayApplication.Build(builder);
            await app.StartAsync();
            return new Harness(app, logs);
        }

        private static HttpClient CreateClient(WebApplication app)
        {
            var client = app.GetTestClient();
            client.DefaultRequestHeaders.Host = "one.example";
            return client;
        }

        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            await app.DisposeAsync();
        }
    }

    private sealed class EvidenceLogger : ILoggerProvider
    {
        public ConcurrentQueue<Dictionary<string, object?>> Events { get; } = new();
        public ConcurrentQueue<string> Messages { get; } = new();
        public Channel<Dictionary<string, object?>> Pending { get; } = Channel.CreateBounded<Dictionary<string, object?>>(32);
        public ILogger CreateLogger(string categoryName) => new Logger(this, categoryName);
        public void Dispose() { }

        private sealed class Logger(EvidenceLogger owner, string category) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
            public bool IsEnabled(LogLevel logLevel) => true;
            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
            {
                owner.Messages.Enqueue(formatter(state, exception));
                if (category != "WPShield.Gateway.Evidence") return;
                var values = Assert.IsAssignableFrom<IEnumerable<KeyValuePair<string, object?>>>(state).ToDictionary();
                Assert.Equal("request_completed", values["EventType"]);
                owner.Events.Enqueue(values);
                Assert.True(owner.Pending.Writer.TryWrite(values));
            }
        }
    }
}
