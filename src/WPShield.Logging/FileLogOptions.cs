namespace WPShield.Logging;

/// <summary>
/// Bounds for the JSON Lines log file, bound from <c>Logging:File</c>.
/// </summary>
/// <remarks>
/// <para>
/// <b><see cref="Enabled"/> defaults to <see langword="false"/> in code and to <see langword="true"/>
/// in the shipped <c>appsettings.json</c>.</b> That split is deliberate rather than inconsistent. A
/// deployment reads the shipped file and gets a log, which is the only thing a Windows service - with
/// no console attached - can be observed through. The test host clears its configuration sources and
/// supplies settings in memory, so it gets the code default and never writes a file; without that,
/// every integration test in this repository would open a log file in a shared output directory and
/// contend with the others for it.
/// </para>
/// <para>
/// Every bound here is a ceiling on disk or memory, because the gateway must not be the reason a
/// server runs out of either. Rotation bounds one file, retention bounds the set of files, and the
/// queue bounds what is held in memory while the disk keeps up.
/// </para>
/// </remarks>
public sealed class FileLogOptions
{
    /// <summary>The smallest rotation size that is not effectively "a file per line".</summary>
    public const long MinimumMaximumFileBytes = 64L * 1024;

    /// <summary>
    /// The largest single file WPShield will grow before rotating. A file larger than this is one no
    /// ordinary text editor on the server will open, which makes it evidence nobody can read.
    /// </summary>
    public const long AbsoluteMaximumFileBytes = 1024L * 1024 * 1024;

    public const int AbsoluteMaximumRetainedFileCount = 1000;
    public const int MinimumQueuedEntries = 16;
    public const int AbsoluteMaximumQueuedEntries = 1_000_000;

    /// <summary>
    /// Whether the JSON Lines file destination is attached at all. See the remarks on this type for
    /// why the code default and the shipped configuration disagree.
    /// </summary>
    public bool Enabled { get; init; }

    /// <summary>
    /// Where log files are written. A relative path resolves against the content root, which for a
    /// Windows service is the installation directory rather than <c>C:\Windows\System32</c>.
    /// </summary>
    public string Directory { get; init; } = "logs";

    /// <summary>
    /// The leading part of every file name. The date, the rotation ordinal and the extension are
    /// appended by the writer.
    /// </summary>
    public string FileNamePrefix { get; init; } = "wpshield";

    /// <summary>Size at which the current file is closed and a new one started. Default 32 MiB.</summary>
    public long MaximumFileBytes { get; init; } = 32L * 1024 * 1024;

    /// <summary>
    /// How many files to keep. The oldest beyond this are deleted when a new file is opened.
    /// Default 14.
    /// </summary>
    public int RetainedFileCount { get; init; } = 14;

    /// <summary>
    /// How many rendered entries may wait in memory while the disk catches up. Default 10,000.
    /// </summary>
    /// <remarks>
    /// When the queue is full an entry is dropped rather than made to wait, and the count of dropped
    /// entries is reported into the log itself once the pressure clears. Blocking the request path on
    /// disk I/O would let a slow or full disk become an outage, and an unbounded queue would let it
    /// become an out-of-memory failure instead. Losing log lines is the least bad of the three, and
    /// it is the only one that can say so afterwards.
    /// </remarks>
    public int MaximumQueuedEntries { get; init; } = 10_000;
}
