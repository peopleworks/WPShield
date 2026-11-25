using System.Collections.Concurrent;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using WPShield.Evidence;

namespace WPShield.Gateway.Tests;

/// <summary>
/// The evidence collector as the gateway hosts it: configured by the <c>Evidence</c> section, off in
/// code and on in the shipped file, and never able to take the gateway down.
/// </summary>
public sealed class EvidenceCollectionTests : IDisposable
{
    private readonly string root = Path.Combine(Path.GetTempPath(), "wpshield-gateway-evidence-tests", Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        try { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    /// <summary>
    /// Off in code, so a test host that supplies its configuration in memory never subscribes to the
    /// real Security log or opens the real store; on in the shipped file, which a deployment reads.
    /// </summary>
    [Fact]
    public void Enabled_IsOffInCodeAndOnInTheShippedConfiguration()
    {
        Assert.False(new EvidenceCollectionOptions().Enabled);

        var shipped = new ConfigurationBuilder()
            .SetBasePath(AppContext.BaseDirectory)
            .AddJsonFile("appsettings.json", optional: false)
            .Build()
            .GetSection(EvidenceCollectionOptions.SectionName)
            .Get<EvidenceCollectionOptions>();

        Assert.NotNull(shipped);
        Assert.True(shipped.Enabled);
        Assert.Equal(EvidenceStore.DefaultPath, shipped.Path);
        EvidenceCollectionOptions.Validate(shipped);
    }

    [Theory]
    [InlineData(@"evidence\wpshield-evidence.db")]
    [InlineData("")]
    [InlineData(@"C:\ProgramData\WPShield\evidence\")]
    public void Validate_RefusesAPathThatIsNotAnAbsoluteFile(string path)
    {
        var exception = Assert.Throws<InvalidOperationException>(
            () => EvidenceCollectionOptions.Validate(new EvidenceCollectionOptions { Enabled = true, Path = path }));

        Assert.Contains("Evidence:Path", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AnInvalidPathStopsStartupLikeAnyOtherConfiguration()
    {
        var exception = Assert.Throws<InvalidOperationException>(
            () => Build(new() { ["Evidence:Enabled"] = "true", ["Evidence:Path"] = "relative.db" }, new Logs()));

        Assert.Contains("Evidence:Path", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task WhenDisabledNoCollectorIsRegisteredAndStartupSaysSo()
    {
        var logs = new Logs();
        await using var app = Build(new(), logs);

        Assert.DoesNotContain(app.Services.GetServices<IHostedService>(), service => service.GetType().Name == "EvidenceCollectorService");
        Assert.Contains(logs.Messages, message => message.StartsWith("Evidence collection is off", StringComparison.Ordinal));
    }

    /// <summary>
    /// Enabled, against a directory that does not exist: the collector says so, creates nothing, and
    /// the gateway keeps answering. Run on Windows only, where the collector is registered.
    /// </summary>
    [Fact]
    public async Task WhenEnabledTheCollectorRunsBesideTheGatewayAndNeverCreatesTheDirectory()
    {
        if (!OperatingSystem.IsWindows()) return;

        var missing = Path.Combine(root, "missing");
        var logs = new Logs();
        await using var app = Build(new()
        {
            ["Evidence:Enabled"] = "true",
            ["Evidence:Path"] = Path.Combine(missing, EvidenceStore.FileName)
        }, logs);

        Assert.Contains(app.Services.GetServices<IHostedService>(), service => service.GetType().Name == "EvidenceCollectorService");

        await app.StartAsync();
        var deadline = DateTime.UtcNow.AddSeconds(20);
        while (!logs.Messages.Any(message => message.Contains("does not exist", StringComparison.Ordinal)))
        {
            Assert.True(DateTime.UtcNow < deadline, "The collector never reported the missing directory.");
            await Task.Delay(20);
        }

        Assert.False(Directory.Exists(missing));
        using var client = app.GetTestClient();
        Assert.Equal(System.Net.HttpStatusCode.OK, (await client.GetAsync("/_wpshield/health/live")).StatusCode);
        await app.StopAsync();
    }

    private static WebApplication Build(Dictionary<string, string?> settings, Logs logs)
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions { EnvironmentName = "Testing" });
        builder.WebHost.UseTestServer();
        builder.Configuration.Sources.Clear();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Gateway:Urls:0"] = "http://127.0.0.1:0",
            ["Gateway:AllowRemoteHealthChecks"] = "true",
            ["Sites:0:Id"] = "one",
            ["Sites:0:Hosts:0"] = "one.example",
            ["Sites:0:Destination"] = "http://127.0.0.1:51001",
            ["Sites:0:Mode"] = "Monitor"
        });
        builder.Configuration.AddInMemoryCollection(settings);
        builder.Logging.AddProvider(logs);
        return GatewayApplication.Build(builder);
    }

    private sealed class Logs : ILoggerProvider
    {
        private readonly ConcurrentQueue<string> messages = new();

        public IReadOnlyCollection<string> Messages => messages;

        public ILogger CreateLogger(string categoryName) => new Logger(messages);

        public void Dispose()
        {
        }

        private sealed class Logger(ConcurrentQueue<string> messages) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter) => messages.Enqueue(formatter(state, exception));
        }
    }
}
