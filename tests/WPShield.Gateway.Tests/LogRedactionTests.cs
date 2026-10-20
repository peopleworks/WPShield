using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace WPShield.Gateway.Tests;

/// <summary>
/// M4 — automated redaction tests. Sensitive headers, cookies, nonces, tokens, full query strings
/// and request bodies must never reach a log line. The chokepoint is the call site, so these tests
/// send real requests through the gateway and assert nothing sensitive is written.
/// </summary>
public sealed class LogRedactionTests
{
    private sealed class TestLoggerProvider : ILoggerProvider
    {
        private readonly ConcurrentBag<LogEntry> _entries = new();

        public IReadOnlyList<LogEntry> Entries => _entries.ToArray();

        public ILogger CreateLogger(string categoryName) => new TestLogger(categoryName, _entries);

        public void Dispose()
        {
        }

        private sealed class TestLogger(
            string category,
            ConcurrentBag<LogEntry> entries) : ILogger
        {
            public IDisposable BeginScope<TState>(TState state) where TState : notnull =>
                NullScope.Instance;

            public bool IsEnabled(LogLevel logLevel) => logLevel != LogLevel.None;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                if (!IsEnabled(logLevel))
                {
                    return;
                }

                var message = formatter(state, exception);

                // Capture both the rendered message and every structured state value, because a
                // secret can hide in either one.
                var stateValues = new List<string?>();
                if (state is IEnumerable<KeyValuePair<string, object?>> pairs)
                {
                    foreach (var pair in pairs)
                    {
                        stateValues.Add(pair.Value?.ToString());
                    }
                }

                entries.Add(new LogEntry(
                    Timestamp: DateTimeOffset.UtcNow,
                    Level: logLevel,
                    Category: category,
                    Message: message,
                    StateValues: stateValues,
                    Exception: exception?.ToString()));
            }

            private sealed class NullScope : IDisposable
            {
                public static readonly NullScope Instance = new();
                public void Dispose() { }
            }
        }

        public sealed record LogEntry(
            DateTimeOffset Timestamp,
            LogLevel Level,
            string Category,
            string Message,
            List<string?> StateValues,
            string? Exception);
    }

    [Fact]
    public async Task AuthorizationHeader_NeverAppearsInLogs()
    {
        await using var harness = await RedactionHarness.StartAsync();
        using var request = harness.CreateRequest("site-one.test", HttpMethod.Get, "/wp-login.php");
        request.Headers.TryAddWithoutValidation("Authorization", "Basic dXNlcjpwYXNz");
        request.Headers.TryAddWithoutValidation("Cookie", "wordpress_authcookie=abc123secret");
        request.Headers.TryAddWithoutValidation("X-WP-Nonce", "nonce-value-12345");

        using var response = await harness.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        foreach (var entry in harness.Logger.Entries)
        {
            Assert.DoesNotContain("dXNlcjpwYXNz", entry.Message, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("abc123secret", entry.Message, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("nonce-value-12345", entry.Message, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("wordpress_authcookie", entry.Message, StringComparison.OrdinalIgnoreCase);
            foreach (var state in entry.StateValues)
            {
                if (state is { } text)
                {
                    Assert.DoesNotContain("dXNlcjpwYXNz", text, StringComparison.OrdinalIgnoreCase);
                    Assert.DoesNotContain("abc123secret", text, StringComparison.OrdinalIgnoreCase);
                    Assert.DoesNotContain("nonce-value-12345", text, StringComparison.OrdinalIgnoreCase);
                    Assert.DoesNotContain("wordpress_authcookie", text, StringComparison.OrdinalIgnoreCase);
                }
            }
        }
    }

    [Fact]
    public async Task FullQueryString_NeverAppearsInLogs()
    {
        await using var harness = await RedactionHarness.StartAsync();
        // A password reset token and an API key in the query string — neither may be logged.
        using var request = harness.CreateRequest(
            "site-one.test",
            HttpMethod.Get,
            "/wp-login.php?action=lostpassword&key=reset-token-secret&login=admin");
        request.Headers.TryAddWithoutValidation("X-Api-Key", "api-key-secret-value");

        using var response = await harness.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        foreach (var entry in harness.Logger.Entries)
        {
            Assert.DoesNotContain("reset-token-secret", entry.Message, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("api-key-secret-value", entry.Message, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("action=lostpassword", entry.Message, StringComparison.OrdinalIgnoreCase);
            foreach (var state in entry.StateValues)
            {
                if (state is { } text)
                {
                    Assert.DoesNotContain("reset-token-secret", text, StringComparison.OrdinalIgnoreCase);
                    Assert.DoesNotContain("api-key-secret-value", text, StringComparison.OrdinalIgnoreCase);
                    Assert.DoesNotContain("action=lostpassword", text, StringComparison.OrdinalIgnoreCase);
                }
            }
        }
    }

    [Fact]
    public async Task UploadBodyContent_NeverAppearsInLogs()
    {
        await using var harness = await RedactionHarness.StartAsync();
        // A multipart upload whose file content contains a PHP marker — the content must never be
        // logged, only the normalized name and the finding.
        var boundary = "----WPShieldRedactionTest";
        var body = $$"""
            --{{boundary}}
            Content-Disposition: form-data; name="async-upload"; filename="shell.php"

            <?php eval($_POST['secret']); ?>
            --{{boundary}}--
            """;

        using var request = harness.CreateRequest("site-one.test", HttpMethod.Post, "/wp-admin/async-upload.php");
        request.Content = new StringContent(body);
        request.Content.Headers.TryAddWithoutValidation(
            "Content-Type", $"multipart/form-data; boundary={boundary}");

        using var response = await harness.Client.SendAsync(request);

        // Monitor mode forwards; either 200 or a backend 502 is fine — what matters is the log.
        Assert.True(
            response.StatusCode == HttpStatusCode.OK ||
            response.StatusCode == (HttpStatusCode)502,
            $"Unexpected status: {response.StatusCode}");

        foreach (var entry in harness.Logger.Entries)
        {
            Assert.DoesNotContain("<?php", entry.Message, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("eval", entry.Message, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("secret", entry.Message, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("shell.php", entry.Message, StringComparison.OrdinalIgnoreCase);
            foreach (var state in entry.StateValues)
            {
                if (state is { } text)
                {
                    Assert.DoesNotContain("<?php", text, StringComparison.OrdinalIgnoreCase);
                    Assert.DoesNotContain("eval", text, StringComparison.OrdinalIgnoreCase);
                    Assert.DoesNotContain("secret", text, StringComparison.OrdinalIgnoreCase);
                    Assert.DoesNotContain("shell.php", text, StringComparison.OrdinalIgnoreCase);
                }
            }
        }
    }

    private sealed class RedactionHarness : IAsyncDisposable
    {
        private readonly WebApplication _gateway;
        private readonly HttpClient _client;
        private readonly TestLoggerProvider _loggerProvider;

        public TestLoggerProvider Logger => _loggerProvider;

        public HttpClient Client => _client;

        private RedactionHarness(WebApplication gateway, HttpClient client, TestLoggerProvider loggerProvider)
        {
            _gateway = gateway;
            _client = client;
            _loggerProvider = loggerProvider;
        }

        public static async Task<RedactionHarness> StartAsync()
        {
            var siteOne = await SyntheticBackend.StartAsync("site-one");
            WebApplication? gateway = null;

            try
            {
                var builder = WebApplication.CreateBuilder(new WebApplicationOptions
                {
                    EnvironmentName = "Testing"
                });
                builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0));
                builder.Configuration.Sources.Clear();
                var settings = new Dictionary<string, string?>
                {
                    ["Gateway:Urls:0"] = "http://127.0.0.1:0",
                    ["Gateway:AllowRemoteHealthChecks"] = "false",
                    ["Gateway:ActivityTimeoutSeconds"] = "10",
                    ["Gateway:Multipart:Enabled"] = "true",
                    ["Sites:0:Id"] = "site-one",
                    ["Sites:0:Hosts:0"] = "site-one.test",
                    ["Sites:0:Destination"] = siteOne.Address.ToString(),
                    ["Sites:0:Mode"] = "Monitor",
                    ["Sites:0:ObserveThreshold"] = "30",
                    ["Sites:0:BlockThreshold"] = "80"
                };
                builder.Configuration.AddInMemoryCollection(settings);

                var loggerProvider = new TestLoggerProvider();
                builder.Logging.AddProvider(loggerProvider);

                gateway = GatewayApplication.Build(builder);
                await gateway.StartAsync();
                var address = GetBoundAddress(gateway);
                var client = new HttpClient { BaseAddress = address };

                return new RedactionHarness(gateway, client, loggerProvider);
            }
            catch
            {
                if (gateway is not null)
                {
                    await gateway.DisposeAsync();
                }
                await siteOne.DisposeAsync();
                throw;
            }
        }

        public HttpRequestMessage CreateRequest(string host, HttpMethod method, string pathAndQuery)
        {
            var request = new HttpRequestMessage(method, pathAndQuery);
            request.Headers.Host = host;
            return request;
        }

        public async ValueTask DisposeAsync()
        {
            _client.Dispose();
            await _gateway.DisposeAsync();
            _loggerProvider.Dispose();
        }
    }

    private static Uri GetBoundAddress(WebApplication application)
    {
        var addresses = application.Services
            .GetRequiredService<IServer>()
            .Features
            .Get<IServerAddressesFeature>()?
            .Addresses;
        var address = Assert.Single(addresses ?? []);
        var uri = new Uri(address);
        Assert.DoesNotContain(uri.Port, new[] { 80, 443, 8081, 8082, 10000 });
        Assert.True(IPAddress.TryParse(uri.Host, out var ipAddress));
        Assert.True(IPAddress.IsLoopback(ipAddress));
        return uri;
    }

    /// <summary>
    /// Minimal synthetic backend that answers 200 to every request and records nothing sensitive.
    /// </summary>
    private sealed class SyntheticBackend : IAsyncDisposable
    {
        private readonly WebApplication _application;

        private SyntheticBackend(WebApplication application, Uri address)
        {
            _application = application;
            Address = address;
        }

        public Uri Address { get; }

        public static async Task<SyntheticBackend> StartAsync(string name)
        {
            var builder = WebApplication.CreateSlimBuilder();
            builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0));
            var application = builder.Build();
            application.MapFallback("{*path}", async context =>
            {
                await context.Response.WriteAsJsonAsync(new { backend = name }, context.RequestAborted);
            });
            await application.StartAsync();
            var address = GetBoundAddress(application);
            return new SyntheticBackend(application, address);
        }

        public ValueTask DisposeAsync() => _application.DisposeAsync();

        private static Uri GetBoundAddress(WebApplication application)
        {
            var addresses = application.Services
                .GetRequiredService<IServer>()
                .Features
                .Get<IServerAddressesFeature>()?
                .Addresses;
            var address = Assert.Single(addresses ?? []);
            return new Uri(address);
        }
    }
}
