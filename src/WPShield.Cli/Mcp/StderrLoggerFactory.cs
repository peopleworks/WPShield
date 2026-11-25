using Microsoft.Extensions.Logging;
using WPShield.Evidence;

namespace WPShield.Cli.Mcp;

/// <summary>
/// The SDK's log, on stderr and nowhere else. stdout carries the protocol, so a logger that wrote there
/// would corrupt it; the assistant's host (Claude Desktop, Claude Code) keeps stderr in its MCP log.
/// </summary>
/// <remarks>
/// Messages are cleaned and bounded like any other text that reaches a terminal, and an exception is
/// reported by type only: a stack trace in a log the operator may attach to an issue says more about the
/// host than it says about the failure.
/// </remarks>
internal sealed class StderrLoggerFactory(TextWriter writer, LogLevel minimum) : ILoggerFactory
{
    public ILogger CreateLogger(string categoryName) => new Logger(writer, minimum);

    public void AddProvider(ILoggerProvider provider)
    {
    }

    public void Dispose()
    {
    }

    private sealed class Logger(TextWriter writer, LogLevel minimum) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => logLevel != LogLevel.None && logLevel >= minimum;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel)) return;
            var message = EvidenceText.Clean(formatter(state, exception), 500);
            writer.WriteLine(exception is null
                ? $"wpshield mcp: {logLevel}: {message}"
                : $"wpshield mcp: {logLevel}: {message} ({exception.GetType().Name})");
        }
    }
}
