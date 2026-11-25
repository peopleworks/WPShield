using System.Runtime.Versioning;
using WPShield.Evidence;
using WPShield.SecurityMonitor;

namespace WPShield.Gateway;

/// <summary>
/// The <c>Evidence</c> section: whether the service records failed Windows logons into the local
/// evidence store (ADR 0007), and where that store is.
/// </summary>
/// <remarks>
/// <para>
/// <b><see cref="Enabled"/> defaults to <see langword="false"/> in code and to <see langword="true"/>
/// in the shipped <c>appsettings.json</c></b>, the split <c>Logging:File:Enabled</c> already makes
/// and for the same reason. A deployment reads the shipped file and collects. The test host clears
/// its configuration sources and supplies settings in memory, so it gets the code default and never
/// subscribes to the real Security log or opens the real store - without that, any test run on a
/// machine where the evidence directory exists would become a second writer to it.
/// </para>
/// <para>
/// <b>Read once, at start.</b> Like every other section, a change applies when the service restarts.
/// </para>
/// </remarks>
public sealed class EvidenceCollectionOptions
{
    public const string SectionName = "Evidence";

    public bool Enabled { get; init; }

    /// <summary>
    /// The database file. The default is the one <c>wpshield install</c> creates the directory for;
    /// a different path must point into a directory with the same replaced permissions, because the
    /// collector never creates one.
    /// </summary>
    public string Path { get; init; } = EvidenceStore.DefaultPath;

    /// <summary>Refuses a value the collector would otherwise have to reinterpret. Throws, never clamps.</summary>
    public static void Validate(EvidenceCollectionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (string.IsNullOrWhiteSpace(options.Path) || !System.IO.Path.IsPathFullyQualified(options.Path))
        {
            throw new InvalidOperationException(
                "Evidence:Path must be an absolute path to the database file, for example " +
                @"C:\ProgramData\WPShield\evidence\wpshield-evidence.db. A relative path would resolve against " +
                "the installation directory, which the service account can only read.");
        }

        if (options.Path.AsSpan().IndexOfAny(System.IO.Path.GetInvalidPathChars()) >= 0 ||
            string.IsNullOrEmpty(System.IO.Path.GetFileName(options.Path)))
        {
            throw new InvalidOperationException(
                "Evidence:Path must name the database file, not a directory, and contain only characters valid in a path.");
        }
    }
}

/// <summary>
/// Runs the evidence collector inside the gateway's process, the one WPShield service.
/// </summary>
/// <remarks>
/// A <see cref="BackgroundService"/> that throws stops the whole host by default, and here the host
/// is the gateway every protected site is forwarded to. <see cref="EvidenceCollector.RunAsync"/>
/// already logs and retries its own failures; the catch below is the last line, so a defect in it
/// costs the evidence, never the sites.
/// </remarks>
[SupportedOSPlatform("windows")]
internal sealed class EvidenceCollectorService(EvidenceCollectionOptions options, ILoggerFactory loggerFactory) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Host start must not wait for the catch-up read.
        await Task.Yield();
        var logger = loggerFactory.CreateLogger(EvidenceCollector.LoggerCategory);
        try
        {
            await new EvidenceCollector(options.Path, logger).RunAsync(stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            logger.LogError(exception,
                "The evidence collector stopped unexpectedly. The gateway keeps serving; failed logons are not recorded until the service restarts.");
        }
    }
}
