using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using WPShield.Logging;

namespace WPShield.Gateway.Tests;

/// <summary>
/// Covers the destination Monitor mode depends on. In Monitor the gateway forwards everything and
/// produces exactly one artefact — this file — so a defect here is indistinguishable from the gateway
/// having observed nothing at all.
/// </summary>
public sealed class JsonLinesFileLoggingTests : IDisposable
{
    /// <summary>
    /// Rooted at the test binary's own directory, deliberately not at
    /// <see cref="Path.GetTempPath"/>.
    /// </summary>
    /// <remarks>
    /// <c>MultipartInspectionReaderTests.ReadingBodiesOfEveryShape_CreatesNoFileOnDisk</c> proves the
    /// reader writes nothing to disk by redirecting <c>TMP</c> and <c>TEMP</c> to a probe directory
    /// and asserting that the probe stays empty. Those variables are process-wide, and xUnit runs
    /// test classes in parallel, so a logging test that resolved the temporary directory while that
    /// redirection was in force wrote its files straight into the probe — and the disk-freedom guard
    /// failed, intermittently, blaming the multipart reader for something these tests did. Reading a
    /// path that no other test can move is what keeps the two independent.
    /// </remarks>
    private readonly string _root = Path.Combine(
        AppContext.BaseDirectory,
        "log-tests",
        Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task Log_WritesOneJsonObjectPerLine()
    {
        var provider = CreateProvider();
        var logger = provider.CreateLogger("WPShield.Gateway.Request");

        logger.LogInformation("First.");
        logger.LogWarning("Second.");
        await provider.DisposeAsync();

        var lines = ReadLines();
        Assert.Equal(2, lines.Length);
        Assert.Equal("First.", lines[0].GetProperty("message").GetString());
        Assert.Equal("Information", lines[0].GetProperty("level").GetString());
        Assert.Equal("WPShield.Gateway.Request", lines[0].GetProperty("category").GetString());
        Assert.Equal("Warning", lines[1].GetProperty("level").GetString());
    }

    [Fact]
    public async Task Log_RecordsStructuredStateAndOmitsTheMessageTemplate()
    {
        var provider = CreateProvider();
        var logger = provider.CreateLogger("WPShield.Gateway.Request");

        logger.LogInformation(
            "Request forwarding. RequestId={RequestId} SiteId={SiteId} Client={Client}",
            "abc123",
            "site-one",
            "203.0.113.5");
        await provider.DisposeAsync();

        var state = Assert.Single(ReadLines()).GetProperty("state");
        Assert.Equal("abc123", state.GetProperty("RequestId").GetString());
        Assert.Equal("site-one", state.GetProperty("SiteId").GetString());
        Assert.Equal("203.0.113.5", state.GetProperty("Client").GetString());
        Assert.False(
            state.TryGetProperty("{OriginalFormat}", out _),
            "The message template doubles the size of every line and the rendered message is already present.");
    }

    [Fact]
    public async Task Log_WritesNumbersAndBooleansWithTheirOwnJsonType()
    {
        var provider = CreateProvider();
        var logger = provider.CreateLogger("WPShield.Gateway.Request");

        logger.LogWarning(
            "Limit breached. LimitBytes={LimitBytes} Blocked={Blocked}",
            6291456L,
            true);
        await provider.DisposeAsync();

        var state = Assert.Single(ReadLines()).GetProperty("state");
        Assert.Equal(JsonValueKind.Number, state.GetProperty("LimitBytes").ValueKind);
        Assert.Equal(6291456L, state.GetProperty("LimitBytes").GetInt64());
        Assert.Equal(JsonValueKind.True, state.GetProperty("Blocked").ValueKind);
    }

    [Fact]
    public async Task Log_RecordsTheExceptionTypeMessageAndStack()
    {
        var provider = CreateProvider();
        var logger = provider.CreateLogger("WPShield.Gateway");

        try
        {
            throw new InvalidOperationException("Backend unreachable.");
        }
        catch (InvalidOperationException exception)
        {
            logger.LogError(exception, "Proxy failure.");
        }

        await provider.DisposeAsync();

        var recorded = Assert.Single(ReadLines()).GetProperty("exception");
        Assert.Equal("System.InvalidOperationException", recorded.GetProperty("type").GetString());
        Assert.Equal("Backend unreachable.", recorded.GetProperty("message").GetString());
        Assert.Contains(
            nameof(Log_RecordsTheExceptionTypeMessageAndStack),
            recorded.GetProperty("stackTrace").GetString(),
            StringComparison.Ordinal);
    }

    /// <summary>
    /// A newline in a logged value must stay inside the JSON string rather than becoming a second
    /// line. Otherwise anything that can influence a logged value can forge whole log entries.
    /// </summary>
    [Fact]
    public async Task Log_CannotBeSplitIntoTwoEntriesByAValueContainingNewlines()
    {
        var provider = CreateProvider();
        var logger = provider.CreateLogger("WPShield.Gateway.Request");

        logger.LogWarning(
            "Unknown host rejected. Host={Host}",
            "evil.test\n{\"level\":\"Information\",\"message\":\"forged\"}");
        await provider.DisposeAsync();

        var lines = ReadLines();
        Assert.Single(lines);
        Assert.Equal("Warning", lines[0].GetProperty("level").GetString());
    }

    [Fact]
    public async Task Writer_RotatesWhenTheFileReachesItsSizeLimit()
    {
        var provider = CreateProvider(maximumFileBytes: FileLogOptions.MinimumMaximumFileBytes);
        var logger = provider.CreateLogger("WPShield.Gateway.Request");

        for (var index = 0; index < 2000; index++)
        {
            logger.LogInformation("Entry {Index} with enough text to make the file grow at a useful rate.", index);
        }

        await provider.DisposeAsync();

        var files = LogFiles();
        Assert.True(files.Length > 1, $"Expected rotation, found {files.Length} file(s).");
        Assert.All(
            files,
            file => Assert.True(
                new FileInfo(file).Length <= FileLogOptions.MinimumMaximumFileBytes * 2,
                $"'{Path.GetFileName(file)}' grew past its rotation size."));
    }

    /// <summary>
    /// The ordering trap this naming scheme exists to avoid: with a <c>-</c> separator the rotated
    /// files sort <i>before</i> the base file, so retention would delete the newest entries of a busy
    /// day and keep the oldest.
    /// </summary>
    [Fact]
    public async Task Writer_RetainsTheNewestFilesAndDeletesTheOldest()
    {
        var provider = CreateProvider(
            maximumFileBytes: FileLogOptions.MinimumMaximumFileBytes,
            retainedFileCount: 2);
        var logger = provider.CreateLogger("WPShield.Gateway.Request");

        for (var index = 0; index < 6000; index++)
        {
            logger.LogInformation("Entry {Index} with enough text to make the file grow at a useful rate.", index);
        }

        await provider.DisposeAsync();

        var files = LogFiles();
        Assert.Equal(2, files.Length);

        // The survivors must be the rotated files, not the base file that preceded them.
        Assert.All(
            files,
            file => Assert.Contains("_", Path.GetFileName(file), StringComparison.Ordinal));
    }

    [Fact]
    public async Task Writer_ReopensTheSameFileOnRestartRatherThanTruncatingIt()
    {
        var first = CreateProvider();
        first.CreateLogger("WPShield.Gateway").LogInformation("Before restart.");
        await first.DisposeAsync();

        var second = CreateProvider();
        second.CreateLogger("WPShield.Gateway").LogInformation("After restart.");
        await second.DisposeAsync();

        var lines = ReadLines();
        Assert.Equal(2, lines.Length);
        Assert.Equal("Before restart.", lines[0].GetProperty("message").GetString());
        Assert.Equal("After restart.", lines[1].GetProperty("message").GetString());
    }

    [Fact]
    public async Task Writer_CreatesTheDirectoryItWasPointedAt()
    {
        var nested = Path.Combine("nested", "logs");
        var provider = CreateProvider(directory: nested);

        provider.CreateLogger("WPShield.Gateway").LogInformation("Created.");
        await provider.DisposeAsync();

        Assert.True(Directory.Exists(Path.Combine(_root, nested)));
    }

    [Fact]
    public void ResolveDirectory_TreatsARelativePathAsRelativeToTheContentRoot()
    {
        var options = new FileLogOptions { Directory = "logs" };

        Assert.Equal(
            Path.Combine(_root, "logs"),
            JsonLinesLogWriter.ResolveDirectory(options, _root));
    }

    [Fact]
    public void ResolveDirectory_LeavesAnAbsolutePathAlone()
    {
        var absolute = Path.Combine(AppContext.BaseDirectory, "wpshield-absolute");
        var options = new FileLogOptions { Directory = absolute };

        Assert.Equal(absolute, JsonLinesLogWriter.ResolveDirectory(options, _root));
    }

    /// <summary>
    /// A gap in a security log that nobody is told about is worse than the gap itself.
    /// </summary>
    [Fact]
    public void DroppedNotice_SaysHowManyEntriesWereLost()
    {
        var notice = LogEntryFormatter.FormatDroppedNotice(DateTimeOffset.UtcNow, droppedEntries: 42);

        var parsed = JsonDocument.Parse(Encoding.UTF8.GetString(notice)).RootElement;
        Assert.Equal("Warning", parsed.GetProperty("level").GetString());
        Assert.Equal(42, parsed.GetProperty("state").GetProperty("DroppedEntries").GetInt32());
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public void Validate_RejectsAnEmptyDirectory(string directory)
    {
        var exception = Assert.Throws<InvalidOperationException>(
            () => FileLogOptionsValidator.Validate(new FileLogOptions { Directory = directory }));

        Assert.Contains("Logging:File:Directory", exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("")]
    [InlineData("wp/shield")]
    [InlineData("wp:shield")]
    public void Validate_RejectsAPrefixThatIsNotValidInAFileName(string prefix)
    {
        var exception = Assert.Throws<InvalidOperationException>(
            () => FileLogOptionsValidator.Validate(new FileLogOptions { FileNamePrefix = prefix }));

        Assert.Contains("Logging:File:FileNamePrefix", exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(FileLogOptions.MinimumMaximumFileBytes - 1)]
    [InlineData(FileLogOptions.AbsoluteMaximumFileBytes + 1)]
    public void Validate_RejectsAnOutOfRangeRotationSize(long maximumFileBytes)
    {
        var exception = Assert.Throws<InvalidOperationException>(
            () => FileLogOptionsValidator.Validate(new FileLogOptions { MaximumFileBytes = maximumFileBytes }));

        Assert.Contains("Logging:File:MaximumFileBytes", exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(FileLogOptions.AbsoluteMaximumRetainedFileCount + 1)]
    public void Validate_RejectsAnOutOfRangeRetentionCount(int retainedFileCount)
    {
        var exception = Assert.Throws<InvalidOperationException>(
            () => FileLogOptionsValidator.Validate(new FileLogOptions { RetainedFileCount = retainedFileCount }));

        Assert.Contains("Logging:File:RetainedFileCount", exception.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(FileLogOptions.MinimumQueuedEntries - 1)]
    [InlineData(FileLogOptions.AbsoluteMaximumQueuedEntries + 1)]
    public void Validate_RejectsAnOutOfRangeQueueSize(int maximumQueuedEntries)
    {
        var exception = Assert.Throws<InvalidOperationException>(
            () => FileLogOptionsValidator.Validate(
                new FileLogOptions { MaximumQueuedEntries = maximumQueuedEntries }));

        Assert.Contains("Logging:File:MaximumQueuedEntries", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_AcceptsTheShippedDefaults()
    {
        FileLogOptionsValidator.Validate(new FileLogOptions { Enabled = true });
    }

    /// <summary>
    /// The code default is off so that the test host, which supplies its configuration in memory,
    /// never opens a log file in a shared output directory. The shipped <c>appsettings.json</c> turns
    /// it on, which is what a deployment reads.
    /// </summary>
    [Fact]
    public void Enabled_DefaultsToOffInCode()
    {
        Assert.False(new FileLogOptions().Enabled);
    }

    private JsonLinesFileLoggerProvider CreateProvider(
        long? maximumFileBytes = null,
        int? retainedFileCount = null,
        string? directory = null)
    {
        var defaults = new FileLogOptions();
        var options = new FileLogOptions
        {
            Enabled = true,
            Directory = directory ?? defaults.Directory,
            MaximumFileBytes = maximumFileBytes ?? defaults.MaximumFileBytes,
            RetainedFileCount = retainedFileCount ?? defaults.RetainedFileCount
        };

        return new JsonLinesFileLoggerProvider(options, _root);
    }

    private string[] LogFiles()
    {
        var directory = Path.Combine(_root, "logs");
        return Directory.Exists(directory)
            ? [.. Directory.GetFiles(directory, "*.jsonl").OrderBy(path => path, StringComparer.Ordinal)]
            : [];
    }

    private JsonElement[] ReadLines()
    {
        return [.. LogFiles()
            .SelectMany(File.ReadAllLines)
            .Where(line => !string.IsNullOrWhiteSpace(line))
            .Select(line => JsonDocument.Parse(line).RootElement)];
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_root))
            {
                Directory.Delete(_root, recursive: true);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }
}
