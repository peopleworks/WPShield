using System.Net;
using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace WPShield.Gateway.Tests;

public sealed class GatewayIntegrationTests
{
    [Fact]
    public async Task ConfiguredHost_ForwardsRequestAndTrustedRequestId()
    {
        var backend = new RecordingHandler();
        await using var harness = await GatewayHarness.StartAsync(backend);
        using var request = new HttpRequestMessage(HttpMethod.Post, "/wp-json/example?value=preserved")
        {
            Content = new StringContent("safe synthetic body", Encoding.UTF8, "text/plain")
        };
        request.Headers.Host = "example.test";

        using var response = await harness.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(1, backend.RequestCount);
        Assert.Equal("/wp-json/example?value=preserved", backend.RequestUri?.PathAndQuery);
        Assert.NotNull(backend.RequestId);
        Assert.Equal(response.Headers.GetValues("X-WPShield-Request-ID").Single(), backend.RequestId);
    }

    [Fact]
    public async Task UnknownHost_Returns421WithoutReachingBackend()
    {
        var backend = new RecordingHandler();
        await using var harness = await GatewayHarness.StartAsync(backend);
        using var request = new HttpRequestMessage(HttpMethod.Get, "/");
        request.Headers.Host = "unknown.test";

        using var response = await harness.Client.SendAsync(request);

        Assert.Equal((HttpStatusCode)421, response.StatusCode);
        Assert.Equal(0, backend.RequestCount);
    }

    [Fact]
    public async Task HealthNamespace_IsAlwaysHandledLocally()
    {
        var backend = new RecordingHandler();
        await using var harness = await GatewayHarness.StartAsync(backend);

        using var live = await harness.Client.GetAsync("/_wpshield/health/live");
        using var unsupportedMethod = await harness.Client.PostAsync("/_wpshield/health/live", content: null);
        using var unknownHealthPath = await harness.Client.GetAsync("/_wpshield/health/unknown");
        using var healthRoot = await harness.Client.GetAsync("/_wpshield/health");

        Assert.Equal(HttpStatusCode.OK, live.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, unsupportedMethod.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, unknownHealthPath.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, healthRoot.StatusCode);
        Assert.Equal(0, backend.RequestCount);
    }

    [Fact]
    public async Task UnavailableBackend_ReturnsPrivacySafe502()
    {
        await using var harness = await GatewayHarness.StartAsync(new FailingHandler());
        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            "/private?code=oauth-code-secret&_wpnonce=nonce-secret")
        {
            Content = new StringContent("body-secret", Encoding.UTF8, "text/plain")
        };
        request.Headers.Host = "example.test";
        request.Headers.Authorization = new("Bearer", "authorization-secret");
        request.Headers.Add("Cookie", "session=cookie-secret");
        request.Headers.Add("X-WP-Nonce", "header-nonce-secret");

        using var response = await harness.Client.SendAsync(request);
        var content = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(content);

        Assert.Equal(HttpStatusCode.BadGateway, response.StatusCode);
        Assert.Equal("backend_unavailable", document.RootElement.GetProperty("error").GetString());
        Assert.False(string.IsNullOrWhiteSpace(document.RootElement.GetProperty("requestId").GetString()));
        Assert.DoesNotContain("oauth-code-secret", content, StringComparison.Ordinal);
        Assert.DoesNotContain("nonce-secret", content, StringComparison.Ordinal);
        Assert.DoesNotContain("body-secret", content, StringComparison.Ordinal);
        Assert.DoesNotContain("authorization-secret", content, StringComparison.Ordinal);
        Assert.DoesNotContain("cookie-secret", content, StringComparison.Ordinal);
        Assert.DoesNotContain("127.0.0.1", content, StringComparison.Ordinal);
        Assert.DoesNotContain(@"C:\private", content, StringComparison.Ordinal);
        Assert.DoesNotContain("exception", content, StringComparison.OrdinalIgnoreCase);

        var logs = string.Join(Environment.NewLine, harness.Logs);
        Assert.DoesNotContain("oauth-code-secret", logs, StringComparison.Ordinal);
        Assert.DoesNotContain("nonce-secret", logs, StringComparison.Ordinal);
        Assert.DoesNotContain("body-secret", logs, StringComparison.Ordinal);
        Assert.DoesNotContain("authorization-secret", logs, StringComparison.Ordinal);
        Assert.DoesNotContain("cookie-secret", logs, StringComparison.Ordinal);
    }

    [Fact]
    public async Task BackendSetCookie_IsNotLogged()
    {
        await using var harness = await GatewayHarness.StartAsync(new SetCookieHandler());
        using var request = new HttpRequestMessage(HttpMethod.Get, "/");
        request.Headers.Host = "example.test";

        using var response = await harness.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("response-cookie-secret", response.Headers.GetValues("Set-Cookie").Single());
        Assert.DoesNotContain(
            "response-cookie-secret",
            string.Join(Environment.NewLine, harness.Logs),
            StringComparison.Ordinal);
    }

    [Fact]
    public async Task ApplicationShutdown_DisposesProxyClient()
    {
        var backend = new DisposableHandler();
        var harness = await GatewayHarness.StartAsync(backend);
        using var request = new HttpRequestMessage(HttpMethod.Get, "/");
        request.Headers.Host = "example.test";
        using var response = await harness.Client.SendAsync(request);

        await harness.DisposeAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(backend.IsDisposed);
    }

    [Fact]
    public async Task DeclaredOversizedBody_Returns413WithoutReachingBackend()
    {
        var backend = new ConsumingHandler();
        await using var harness = await GatewayHarness.StartAsync(backend, maximumRequestBytes: 16);
        using var request = new HttpRequestMessage(HttpMethod.Post, "/upload")
        {
            Content = new ByteArrayContent(new byte[17])
        };
        request.Headers.Host = "example.test";

        using var response = await harness.Client.SendAsync(request);
        var content = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
        Assert.Contains("\"error\":\"request_too_large\"", content, StringComparison.Ordinal);
        Assert.Equal(0, backend.RequestCount);
    }

    [Fact]
    public async Task BodyAtConfiguredLimit_IsForwarded()
    {
        var backend = new ConsumingHandler();
        await using var harness = await GatewayHarness.StartAsync(backend, maximumRequestBytes: 16);
        using var request = new HttpRequestMessage(HttpMethod.Post, "/upload")
        {
            Content = new UnknownLengthContent(new byte[16])
        };
        request.Headers.Host = "example.test";

        using var response = await harness.Client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(1, backend.RequestCount);
        Assert.Equal(16, backend.BytesRead);
    }

    [Fact]
    public async Task UnknownLengthBodyOverLimit_ReturnsPrivacySafe413()
    {
        var backend = new ConsumingHandler();
        await using var harness = await GatewayHarness.StartAsync(backend, maximumRequestBytes: 16);
        using var request = new HttpRequestMessage(HttpMethod.Post, "/upload?secret=query-marker")
        {
            Content = new UnknownLengthContent(Encoding.UTF8.GetBytes("safe-marker-12345"))
        };
        request.Headers.Host = "example.test";
        request.Headers.Authorization = new("Bearer", "authorization-marker");
        request.Headers.Add("Cookie", "session=cookie-marker");

        using var response = await harness.Client.SendAsync(request);
        var content = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
        Assert.Contains("\"error\":\"request_too_large\"", content, StringComparison.Ordinal);
        Assert.DoesNotContain("query-marker", content, StringComparison.Ordinal);
        Assert.DoesNotContain("authorization-marker", content, StringComparison.Ordinal);
        Assert.DoesNotContain("cookie-marker", content, StringComparison.Ordinal);
        Assert.Equal(1, backend.RequestCount);
        Assert.InRange(backend.BytesRead, 0, 16);

        var logs = string.Join(Environment.NewLine, harness.Logs);
        Assert.DoesNotContain("query-marker", logs, StringComparison.Ordinal);
        Assert.DoesNotContain("authorization-marker", logs, StringComparison.Ordinal);
        Assert.DoesNotContain("cookie-marker", logs, StringComparison.Ordinal);
    }

    [Fact]
    public async Task UnknownHostWithOversizedBody_StillReturns421WithoutReachingBackend()
    {
        var backend = new ConsumingHandler();
        await using var harness = await GatewayHarness.StartAsync(backend, maximumRequestBytes: 16);
        using var request = new HttpRequestMessage(HttpMethod.Post, "/upload")
        {
            Content = new ByteArrayContent(new byte[17])
        };
        request.Headers.Host = "unknown.test";

        using var response = await harness.Client.SendAsync(request);

        Assert.Equal((HttpStatusCode)421, response.StatusCode);
        Assert.Equal(0, backend.RequestCount);
    }

    private sealed class GatewayHarness : IAsyncDisposable
    {
        private readonly WebApplication _application;
        private readonly RecordingLoggerProvider _loggerProvider;

        private GatewayHarness(WebApplication application, RecordingLoggerProvider loggerProvider)
        {
            _application = application;
            _loggerProvider = loggerProvider;
            Client = application.GetTestClient();
        }

        public HttpClient Client { get; }
        public IReadOnlyCollection<string> Logs => _loggerProvider.Messages;

        public static async Task<GatewayHarness> StartAsync(
            HttpMessageHandler backendHandler,
            long maximumRequestBytes = 6L * 1024 * 1024)
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
                ["Gateway:AllowRemoteHealthChecks"] = "true",
                ["Gateway:ActivityTimeoutSeconds"] = "10",
                ["Gateway:MaximumRequestBytes"] = maximumRequestBytes.ToString(),
                ["Sites:0:Id"] = "test-site",
                ["Sites:0:Hosts:0"] = "example.test",
                ["Sites:0:Destination"] = "http://127.0.0.1:51001",
                ["Sites:0:Mode"] = "Monitor",
                ["Sites:0:ObserveThreshold"] = "30",
                ["Sites:0:BlockThreshold"] = "80"
            });
            builder.Services.AddSingleton<HttpMessageInvoker>(_ => new HttpMessageInvoker(backendHandler));
            var loggerProvider = new RecordingLoggerProvider();
            builder.Logging.AddProvider(loggerProvider);

            var application = GatewayApplication.Build(builder);
            await application.StartAsync();
            return new GatewayHarness(application, loggerProvider);
        }

        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            await _application.DisposeAsync();
        }
    }

    private sealed class RecordingHandler : HttpMessageHandler
    {
        public int RequestCount { get; private set; }
        public Uri? RequestUri { get; private set; }
        public string? RequestId { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            RequestCount++;
            RequestUri = request.RequestUri;
            RequestId = request.Headers.GetValues("X-WPShield-Request-ID").Single();
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"backend":"synthetic"}""", Encoding.UTF8, "application/json")
            });
        }
    }

    private sealed class FailingHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            throw new HttpRequestException(
                @"Synthetic backend C:\private\backend at http://127.0.0.1:51001 is unavailable.");
        }
    }

    private sealed class SetCookieHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var response = new HttpResponseMessage(HttpStatusCode.OK);
            response.Headers.TryAddWithoutValidation("Set-Cookie", "session=response-cookie-secret");
            return Task.FromResult(response);
        }
    }

    private sealed class DisposableHandler : HttpMessageHandler
    {
        public bool IsDisposed { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }

        protected override void Dispose(bool disposing)
        {
            IsDisposed = true;
            base.Dispose(disposing);
        }
    }

    private sealed class ConsumingHandler : HttpMessageHandler
    {
        public int RequestCount { get; private set; }
        public int BytesRead { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            RequestCount++;
            if (request.Content is not null)
            {
                await using var destination = new CountingWriteStream(
                    count => BytesRead += count);
                await request.Content.CopyToAsync(destination, cancellationToken);
            }

            return new HttpResponseMessage(HttpStatusCode.OK);
        }
    }

    private sealed class CountingWriteStream(Action<int> recordWrite) : Stream
    {
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush()
        {
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            recordWrite(count);
        }

        public override ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            recordWrite(buffer.Length);
            return ValueTask.CompletedTask;
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }
    }

    private sealed class UnknownLengthContent(byte[] content) : HttpContent
    {
        protected override Task SerializeToStreamAsync(
            Stream stream,
            TransportContext? context)
        {
            return stream.WriteAsync(content).AsTask();
        }

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }
    }

    private sealed class RecordingLoggerProvider : ILoggerProvider
    {
        private readonly ConcurrentQueue<string> _messages = new();

        public IReadOnlyCollection<string> Messages => _messages;

        public ILogger CreateLogger(string categoryName)
        {
            return new RecordingLogger(_messages);
        }

        public void Dispose()
        {
        }

        private sealed class RecordingLogger(ConcurrentQueue<string> messages) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull
            {
                return null;
            }

            public bool IsEnabled(LogLevel logLevel)
            {
                return true;
            }

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                messages.Enqueue(formatter(state, exception));
                if (exception is not null)
                {
                    messages.Enqueue(exception.ToString());
                }
            }
        }
    }
}
