using System.Globalization;

namespace WPShield.WebEvidence;

/// <summary>One IIS site, as the IIS configuration describes its logging. Read by the CLI, read-only.</summary>
/// <param name="Id">The site ID: the number in its <c>W3SVC</c> log folder.</param>
/// <param name="LogDirectory">The site's log directory with environment variables expanded, or <see langword="null"/>.</param>
/// <param name="LogFormat">The configured format: <c>W3C</c> is the only one read.</param>
/// <param name="ServesHttp">The site has an <c>http</c> or <c>https</c> binding. An FTP-only site logs no HTTP request.</param>
public sealed record IisLogSite(long Id, string Name, string? LogDirectory, bool LoggingEnabled, string LogFormat, bool ServesHttp)
{
    /// <summary>The folder this site's W3C files are written to: <c>W3SVC</c> and the site ID, under the log directory.</summary>
    public string? Folder => string.IsNullOrWhiteSpace(LogDirectory) ? null
        : Path.Combine(LogDirectory, "W3SVC" + Id.ToString(CultureInfo.InvariantCulture));
}

/// <summary>The sites and how IIS logs them, or why that could not be read.</summary>
/// <param name="Problem">Why the IIS configuration could not be read; <see langword="null"/> when it was.</param>
/// <param name="CentralLogging">
/// <c>CentralW3C</c> or <c>CentralBinary</c> when IIS writes one file for every site, which this phase does
/// not read; <see langword="null"/> for one file per site, the default.
/// </param>
public sealed record IisLogConfiguration(IReadOnlyList<IisLogSite> Sites, string? Problem, string? CentralLogging)
{
    public static IisLogConfiguration Unreadable(string problem) => new([], problem, null);
}
