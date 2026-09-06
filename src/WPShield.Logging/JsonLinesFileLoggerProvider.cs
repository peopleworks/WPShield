using Microsoft.Extensions.Logging;

namespace WPShield.Logging;

/// <summary>
/// Attaches the JSON Lines file destination to the logging pipeline.
/// </summary>
/// <remarks>
/// The provider alias is <c>File</c>, so the standard
/// <c>Logging:File:LogLevel:&lt;Category&gt;</c> configuration filters this destination exactly as it
/// filters the console. Nothing about level filtering is reimplemented here.
/// </remarks>
[ProviderAlias("File")]
public sealed class JsonLinesFileLoggerProvider : ILoggerProvider, IAsyncDisposable
{
    private readonly JsonLinesLogWriter _writer;
    private readonly TimeProvider _timeProvider;

    public JsonLinesFileLoggerProvider(
        FileLogOptions options,
        string contentRootPath,
        TimeProvider? timeProvider = null)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
        _writer = new JsonLinesLogWriter(options, contentRootPath, _timeProvider);
    }

    /// <summary>Where the files are being written, for the startup report.</summary>
    public string Directory => _writer.Directory;

    public ILogger CreateLogger(string categoryName)
    {
        return new JsonLinesFileLogger(categoryName, _writer, _timeProvider);
    }

    public void Dispose()
    {
        // ILoggerProvider is disposed synchronously by the host. Blocking here is correct rather than
        // sloppy: this runs during shutdown, after the last request, and its whole purpose is to let
        // the queued tail of the log reach disk before the process exits. The writer bounds the wait
        // itself, so this cannot hang a service stop.
        _writer.DisposeAsync().AsTask().GetAwaiter().GetResult();
    }

    public ValueTask DisposeAsync()
    {
        return _writer.DisposeAsync();
    }

    private sealed class JsonLinesFileLogger(
        string category,
        JsonLinesLogWriter writer,
        TimeProvider timeProvider) : ILogger
    {
        public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;

        /// <summary>
        /// Always enabled, because the level filtering that matters has already happened.
        /// </summary>
        /// <remarks>
        /// <c>ILoggerFactory</c> applies the configured <c>Logging:File:LogLevel</c> rules before a
        /// call reaches here. Repeating a level check would be a second, quieter filter that
        /// configuration cannot see, and the first time the two disagreed an operator would be
        /// looking for a line that was silently dropped by the destination they had configured to
        /// record it.
        /// </remarks>
        public bool IsEnabled(LogLevel logLevel) => logLevel != LogLevel.None;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            ArgumentNullException.ThrowIfNull(formatter);

            if (!IsEnabled(logLevel))
            {
                return;
            }

            // Rendered here, on the calling thread, and never deferred. A logging state object may be
            // pooled or mutated the moment this method returns, so anything captured by reference
            // could reach disk meaning something other than what was logged.
            var entry = LogEntryFormatter.Format(
                timeProvider.GetUtcNow(),
                logLevel,
                category,
                eventId,
                formatter(state, exception),
                state as IReadOnlyList<KeyValuePair<string, object?>>,
                exception);

            writer.Write(entry);
        }
    }

    private sealed class NullScope : IDisposable
    {
        public static readonly NullScope Instance = new();

        private NullScope()
        {
        }

        public void Dispose()
        {
        }
    }
}
