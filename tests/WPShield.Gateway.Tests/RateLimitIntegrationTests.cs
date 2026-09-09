using System.Collections.Concurrent;
using System.Net;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace WPShield.Gateway.Tests;

/// <summary>
/// The rate limiter through the real pipeline, where the mode discipline lives.
/// </summary>
/// <remarks>
/// The unit tests prove the budget arithmetic. These prove the thing that actually matters about a
/// security control in this project: that <b>Monitor observes and forwards</b> and only Block
/// refuses. A limiter that quietly refused traffic in Monitor would be the one component here where
/// Monitor is not Monitor, and an operator watching a Monitor rollout would find out from their
/// users.
/// </remarks>
public sealed class RateLimitIntegrationTests
{
    [Fact]
    public async Task Monitor_RecordsWhatItWouldHaveRefusedAndForwardsAnyway()
    {
        var backend = new CountingHandler();
        await using var harness = await Harness.StartAsync(backend, "Monitor", permitLimit: 3);

        for (var attempt = 0; attempt < 6; attempt++)
        {
            using var response = await harness.SendAsync("/wp-login.php");
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        }

        Assert.Equal(6, backend.RequestCount);
        Assert.Contains(harness.Logs, line =>
            line.Contains("Rate limit exceeded", StringComparison.Ordinal) &&
            line.Contains("Action=Observe", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Block_RefusesWithTooManyRequestsOnceTheBudgetIsSpent()
    {
        var backend = new CountingHandler();
        await using var harness = await Harness.StartAsync(backend, "Block", permitLimit: 3);

        for (var attempt = 0; attempt < 3; attempt++)
        {
            using var allowed = await harness.SendAsync("/wp-login.php");
            Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
        }

        using var refused = await harness.SendAsync("/wp-login.php");

        Assert.Equal(HttpStatusCode.TooManyRequests, refused.StatusCode);
        Assert.Equal(3, backend.RequestCount);
        Assert.Equal("300", Assert.Single(refused.Headers.GetValues("Retry-After")));
        Assert.Contains(harness.Logs, line =>
            line.Contains("Rate limit exceeded", StringComparison.Ordinal) &&
            line.Contains("Action=Block", StringComparison.Ordinal));
    }

    /// <summary>
    /// The refusal must not spread. A budget spent on the login form cannot be allowed to take the
    /// rest of the site with it, or the limiter becomes the outage it was meant to prevent.
    /// </summary>
    [Fact]
    public async Task Block_LeavesEveryOtherPathAlone()
    {
        var backend = new CountingHandler();
        await using var harness = await Harness.StartAsync(backend, "Block", permitLimit: 1);

        using (var first = await harness.SendAsync("/wp-login.php")) { Assert.Equal(HttpStatusCode.OK, first.StatusCode); }
        using (var second = await harness.SendAsync("/wp-login.php")) { Assert.Equal(HttpStatusCode.TooManyRequests, second.StatusCode); }

        for (var attempt = 0; attempt < 20; attempt++)
        {
            using var asset = await harness.SendAsync("/wp-content/themes/x/style.css");
            Assert.Equal(HttpStatusCode.OK, asset.StatusCode);
        }
    }

    /// <summary>The startup report prints both states, so a disabled limiter cannot look like a quiet one.</summary>
    [Fact]
    public async Task Startup_ReportsTheRulesItLoaded()
    {
        var backend = new CountingHandler();
        await using var harness = await Harness.StartAsync(backend, "Monitor", permitLimit: 3);

        Assert.Contains(harness.Logs, line =>
            line.Contains("Rate limit rule", StringComparison.Ordinal) &&
            line.Contains("RuleId=wordpress-login", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Startup_SaysSoWhenRateLimitingIsOff()
    {
        var backend = new CountingHandler();
        await using var harness = await Harness.StartAsync(backend, "Monitor", permitLimit: 3, enabled: false);

        Assert.Contains(harness.Logs, line => line.Contains("Rate limiting is off", StringComparison.Ordinal));
    }

    private sealed class Harness : IAsyncDisposable
    {
        private readonly WebApplication _application;
        private readonly RecordingLoggerProvider _loggerProvider;
        private readonly HttpClient _client;

        private Harness(WebApplication application, RecordingLoggerProvider loggerProvider)
        {
            _application = application;
            _loggerProvider = loggerProvider;
            _client = application.GetTestClient();
        }

        public IReadOnlyCollection<string> Logs => _loggerProvider.Messages;

        public Task<HttpResponseMessage> SendAsync(string path)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, path);
            request.Headers.Host = "example.test";
            return _client.SendAsync(request);
        }

        public static async Task<Harness> StartAsync(
            HttpMessageHandler backendHandler,
            string mode,
            int permitLimit,
            bool enabled = true)
        {
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions
            {
                EnvironmentName = "Testing"
            });
            builder.WebHost.UseTestServer();
            builder.Configuration.Sources.Clear();
            builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Gateway:Urls:0"] = "http://127.0.0.1:0",
                ["Gateway:ActivityTimeoutSeconds"] = "10",
                ["Gateway:RateLimit:Enabled"] = enabled ? "true" : "false",
                ["Gateway:RateLimit:Rules:0:Id"] = "wordpress-login",
                ["Gateway:RateLimit:Rules:0:Paths:0"] = "/wp-login.php",
                ["Gateway:RateLimit:Rules:0:Paths:1"] = "/xmlrpc.php",
                ["Gateway:RateLimit:Rules:0:PermitLimit"] = permitLimit.ToString(),
                ["Gateway:RateLimit:Rules:0:WindowSeconds"] = "300",
                ["Sites:0:Id"] = "test-site",
                ["Sites:0:Hosts:0"] = "example.test",
                ["Sites:0:Destination"] = "http://127.0.0.1:51001",
                ["Sites:0:Mode"] = mode,
                ["Sites:0:ObserveThreshold"] = "30",
                ["Sites:0:BlockThreshold"] = "80"
            });
            builder.Services.AddSingleton<HttpMessageInvoker>(_ => new HttpMessageInvoker(backendHandler));
            var loggerProvider = new RecordingLoggerProvider();
            builder.Logging.AddProvider(loggerProvider);

            var application = GatewayApplication.Build(builder);
            await application.StartAsync();
            return new Harness(application, loggerProvider);
        }

        public async ValueTask DisposeAsync()
        {
            _client.Dispose();
            await _application.DisposeAsync();
        }
    }

    // A private copy, following the precedent the other integration suites in this assembly set.
    // Sharing one would couple these tests to whichever file happened to own it.
    private sealed class RecordingLoggerProvider : ILoggerProvider
    {
        private readonly ConcurrentQueue<string> _messages = new();

        public IReadOnlyCollection<string> Messages => _messages;

        public ILogger CreateLogger(string categoryName) => new RecordingLogger(_messages);

        public void Dispose()
        {
        }

        private sealed class RecordingLogger(ConcurrentQueue<string> messages) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                messages.Enqueue(formatter(state, exception));
            }
        }
    }

    private sealed class CountingHandler : HttpMessageHandler
    {
        private int _count;

        public int RequestCount => _count;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _count);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"backend":"synthetic"}""", Encoding.UTF8, "application/json")
            });
        }
    }
}
