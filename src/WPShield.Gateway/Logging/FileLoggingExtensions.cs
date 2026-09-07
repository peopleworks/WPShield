using Microsoft.Extensions.Logging;
using WPShield.Logging;

namespace WPShield.Gateway.Logging;

/// <summary>
/// Wires the JSON Lines file destination into a <see cref="WebApplicationBuilder"/>.
/// </summary>
/// <remarks>
/// Configuration binding and dependency registration only. Everything that opens, writes, rotates or
/// deletes a file lives in <c>WPShield.Logging</c>, so this assembly still names no file API and the
/// structural disk-freedom guard over <c>WPShield.Gateway</c> keeps its original strictness — see the
/// comment in <c>WPShield.Logging.csproj</c>.
/// </remarks>
internal static class FileLoggingExtensions
{
    public const string ConfigurationSection = "Logging:File";

    /// <summary>
    /// Binds <c>Logging:File</c>, validates it, and attaches the destination when it is enabled.
    /// </summary>
    /// <returns>
    /// The directory files will be written to, or <see langword="null"/> when file logging is off.
    /// The caller reports it at startup.
    /// </returns>
    /// <exception cref="InvalidOperationException">
    /// File logging is enabled and the resolved directory cannot be written to. Reported here rather
    /// than at the first log line, because the first log line cannot report anything.
    /// </exception>
    /// <remarks>
    /// The provider is registered through a factory rather than as a ready-made instance, and that is
    /// load-bearing rather than stylistic. A logger provider handed to the container as an existing
    /// object is disposed by nobody - the container does not dispose instances it did not create, and
    /// <c>LoggerFactory</c> does not dispose providers the container injected - so the queued tail of
    /// the log would never reach disk on shutdown and the drain task would outlive the host. Letting
    /// the container construct it puts disposal back where it belongs.
    /// </remarks>
    public static string? AddJsonLinesFileLogging(this WebApplicationBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        var options = builder.Configuration.GetSection(ConfigurationSection).Get<FileLogOptions>()
                      ?? new FileLogOptions();

        // Registered whether or not the destination is attached, so the caller can wire it up without
        // first asking whether file logging happens to be on.
        var reporter = new LogWriteFailureReporter();
        builder.Services.AddSingleton(reporter);

        if (!options.Enabled)
        {
            return null;
        }

        FileLogOptionsValidator.Validate(options);

        var contentRoot = builder.Environment.ContentRootPath;
        var directory = JsonLinesLogWriter.ResolveDirectory(options, contentRoot);

        // Before the provider is registered, so the failure is a refusal to start rather than a
        // gateway that runs perfectly and records nothing. An operator reads "cannot write its log"
        // and fixes it; nobody reads an empty directory, because an empty security log is exactly
        // what a quiet night looks like.
        JsonLinesLogWriter.EnsureDirectoryIsWritable(directory);

        builder.Services.AddSingleton<ILoggerProvider>(
            _ => new JsonLinesFileLoggerProvider(options, contentRoot, timeProvider: null, reporter.Report));

        return directory;
    }
}
