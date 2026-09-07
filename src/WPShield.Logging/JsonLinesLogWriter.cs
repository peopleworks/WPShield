using System.Globalization;
using System.Threading.Channels;

namespace WPShield.Logging;

/// <summary>
/// Owns the log file: the queue in front of it, the rotation that bounds one file, and the retention
/// that bounds the set of them.
/// </summary>
/// <remarks>
/// <para>
/// Entries arrive already rendered to UTF-8 bytes. That is a correctness requirement rather than a
/// performance choice: a logging state object may be pooled or mutated the moment the logging call
/// returns, so anything queued by reference could be written after it stopped meaning what it meant.
/// </para>
/// <para>
/// <b>A full queue drops rather than waits.</b> Blocking the request path on disk I/O lets a slow or
/// full disk become an outage; an unbounded queue lets it become an out-of-memory failure. Dropping
/// is the only one of the three that the log can afterwards admit to, and it does - the count is
/// written into the file as soon as the pressure clears.
/// </para>
/// <para>
/// <b>Nothing on the write path is allowed to throw into the gateway.</b> A security gateway that
/// cannot write its log has a serious problem, but refusing to serve traffic that is already flowing
/// is a worse one, so write failures during a run are counted and retried on the next batch rather
/// than propagated.
/// </para>
/// <para>
/// <b>Startup is the exception, and <see cref="EnsureDirectoryIsWritable"/> is where it lives.</b>
/// The two failures are not the same failure. A disk that fills at three in the morning is a
/// condition that arrives while the gateway is the only thing standing in front of a site, and
/// dropping log lines is the least bad response to it. A directory the service account was never
/// granted write access to is a deployment mistake that is true before the first request arrives,
/// deterministic, and invisible from the outside - the gateway would inspect traffic, report itself
/// healthy, and produce no evidence at all. Refusing to start is the only way that mistake is ever
/// noticed, so it is checked once, up front, and it throws.
/// </para>
/// <para>
/// The first failure of each runtime streak is handed to the reporter supplied by the host, which
/// routes it to the remaining log destinations - under a Windows service that means the Windows
/// Event Log. It defaults to the standard error stream, which is right for a console run and is
/// <b>not</b> right for a service: a service has no console attached, so a notice written there
/// reaches nobody. An earlier version of this comment claimed the service host captured it. It does
/// not, and that claim is why a gateway that could not write its log stayed silent about it.
/// </para>
/// </remarks>
public sealed class JsonLinesLogWriter : IAsyncDisposable
{
    private const string FileExtension = ".jsonl";

    /// <summary>
    /// The ceiling on same-day rotation ordinals. Reaching it means the day produced more than this
    /// many full files, which is a volume problem rather than a naming one. It is 9999 because the
    /// ordinal is zero-padded to four digits so that names sort chronologically, and a fifth digit
    /// would break that ordering.
    /// </summary>
    private const int AbsoluteMaximumOrdinal = 9_999;

    /// <summary>How long <see cref="DisposeAsync"/> waits for the queue to drain before giving up.</summary>
    private static readonly TimeSpan DrainTimeout = TimeSpan.FromSeconds(5);

    private readonly FileLogOptions _options;
    private readonly string _directory;
    private readonly Channel<byte[]> _queue;
    private readonly Task _drain;
    private readonly TimeProvider _timeProvider;
    private readonly Action<string> _reportFailure;

    private FileStream? _file;
    private long _currentFileBytes;
    private DateOnly _currentFileDate;
    private int _droppedSinceLastReport;
    private bool _failing;

    /// <param name="reportFailure">
    /// Where the first failure of each write streak is announced. Defaults to the standard error
    /// stream, which is the right answer for a console run and reaches nobody under a Windows
    /// service; a host that has other log destinations should supply one that uses them.
    /// </param>
    public JsonLinesLogWriter(
        FileLogOptions options,
        string contentRootPath,
        TimeProvider? timeProvider = null,
        Action<string>? reportFailure = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(contentRootPath);

        _options = options;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _reportFailure = reportFailure ?? Console.Error.WriteLine;
        _directory = ResolveDirectory(options, contentRootPath);

        _queue = Channel.CreateBounded<byte[]>(new BoundedChannelOptions(options.MaximumQueuedEntries)
        {
            SingleReader = true,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.DropWrite
        });

        _drain = Task.Run(DrainAsync);
    }

    /// <summary>
    /// The directory log files are written to, resolved against the content root. Exposed so the
    /// gateway can report it at startup: an operator who cannot find the log cannot use it.
    /// </summary>
    public string Directory => _directory;

    /// <summary>
    /// Resolves the configured directory against the content root, so that startup reporting and the
    /// writer itself cannot name two different places.
    /// </summary>
    /// <remarks>
    /// The content root, not the current directory. A Windows service starts in
    /// <c>C:\Windows\System32</c>, so a relative path resolved against the current directory would
    /// put a security log somewhere no operator would look and somewhere the service account should
    /// not be writing.
    /// </remarks>
    public static string ResolveDirectory(FileLogOptions options, string contentRootPath)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(contentRootPath);

        return Path.IsPathRooted(options.Directory)
            ? options.Directory
            : Path.Combine(contentRootPath, options.Directory);
    }

    /// <summary>
    /// Creates the log directory if it does not exist and proves a file can be written in it, or
    /// throws. Called once at startup, before the host is built.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// The directory could not be created, or a file could not be written in it.
    /// </exception>
    /// <remarks>
    /// <para>
    /// This is the one place in this type that throws, and the asymmetry is deliberate - see the
    /// remarks on the class. The failure it catches is the one that cannot announce itself: an
    /// installation whose service account holds read-and-execute on the directory the log resolves
    /// to. Nothing about that is visible from outside the process. The gateway starts, reports its
    /// configuration, forwards traffic, applies every rule, and writes down none of it.
    /// </para>
    /// <para>
    /// Creating the directory is part of the proof rather than a convenience. A permission that
    /// allows writing a file inside an existing directory is not the same permission as the one that
    /// allows creating the directory, and checking only the second would pass on a machine where the
    /// first fails on the very first log line.
    /// </para>
    /// <para>
    /// The probe file is opened with <see cref="FileOptions.DeleteOnClose"/> and named for this
    /// process, so a run leaves nothing behind and two runs cannot collide over one name.
    /// </para>
    /// </remarks>
    public static void EnsureDirectoryIsWritable(string directory)
    {
        ArgumentNullException.ThrowIfNull(directory);

        try
        {
            System.IO.Directory.CreateDirectory(directory);

            var probe = Path.Combine(
                directory,
                FormattableString.Invariant($".wpshield-write-probe-{Environment.ProcessId}.tmp"));

            using var stream = new FileStream(
                probe,
                FileMode.Create,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 1,
                FileOptions.DeleteOnClose);

            stream.WriteByte((byte)'\n');
        }
        catch (Exception exception) when (
            exception is IOException
                or UnauthorizedAccessException
                or NotSupportedException
                or ArgumentException
                or System.Security.SecurityException)
        {
            throw new InvalidOperationException(
                $"WPShield cannot write its log in '{directory}', so it would run with nowhere to " +
                "record what it did. Startup is refused rather than leaving a gateway that inspects " +
                "traffic and produces no evidence of having done so. Point Logging:File:Directory at " +
                "a directory the account running this service can write to, and grant that account " +
                "Modify on it. Install-WPShield.ps1 creates C:\\ProgramData\\WPShield\\logs for this " +
                "and grants exactly that; the installation directory is deliberately read-only for " +
                "the service account, so a relative path that resolves next to the binaries will " +
                $"always fail here. Underlying failure: {exception.Message}",
                exception);
        }
    }

    /// <summary>
    /// Queues one rendered entry, or drops it if the queue is full. Never blocks and never throws.
    /// </summary>
    public void Write(byte[] entry)
    {
        if (!_queue.Writer.TryWrite(entry))
        {
            Interlocked.Increment(ref _droppedSinceLastReport);
        }
    }

    private async Task DrainAsync()
    {
        var batch = new List<byte[]>(capacity: 64);

        while (await _queue.Reader.WaitToReadAsync().ConfigureAwait(false))
        {
            batch.Clear();
            while (batch.Count < 1024 && _queue.Reader.TryRead(out var entry))
            {
                batch.Add(entry);
            }

            WriteBatch(batch);
        }

        // One last pass with nothing to write, so a drop that happened after the final batch is still
        // recorded before the file closes.
        batch.Clear();
        WriteBatch(batch);
        Close();
    }

    private void WriteBatch(List<byte[]> batch)
    {
        try
        {
            ReportDroppedEntries();

            foreach (var entry in batch)
            {
                WriteEntry(entry);
            }

            _file?.Flush();
            _failing = false;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            // Close the handle so the next batch reopens rather than writing through a stream that is
            // already broken. The streak flag keeps a failing disk from producing one stderr line per
            // batch, which would be its own denial of service against whoever is reading.
            Close();

            if (!_failing)
            {
                // Set before reporting, not after. The reporter supplied by the host writes through
                // ILogger, which fans out to every destination including this one, so the notice
                // comes straight back down into Write and through this catch on the next batch. The
                // flag is what makes that re-entry terminate instead of repeating forever.
                _failing = true;
                _reportFailure(
                    $"WPShield could not write its log file in '{_directory}': {exception.Message}");
            }
        }
    }

    private void WriteEntry(byte[] entry)
    {
        EnsureFile(entry.Length + 1);
        _file!.Write(entry);
        _file.WriteByte((byte)'\n');
        _currentFileBytes += entry.Length + 1;
    }

    /// <summary>
    /// Reports entries lost to a full queue, into the log itself.
    /// </summary>
    /// <remarks>
    /// A gap in a security log that nobody is told about is worse than the gap. This runs at the
    /// start of a batch, which is exactly when the pressure has cleared enough for the line to be
    /// written and to be true.
    /// </remarks>
    private void ReportDroppedEntries()
    {
        var dropped = Interlocked.Exchange(ref _droppedSinceLastReport, 0);
        if (dropped == 0)
        {
            return;
        }

        var notice = LogEntryFormatter.FormatDroppedNotice(_timeProvider.GetUtcNow(), dropped);
        EnsureFile(notice.Length + 1);
        _file!.Write(notice);
        _file.WriteByte((byte)'\n');
        _currentFileBytes += notice.Length + 1;
    }

    private void EnsureFile(int incomingBytes)
    {
        var today = DateOnly.FromDateTime(_timeProvider.GetUtcNow().UtcDateTime);

        if (_file is not null &&
            _currentFileDate == today &&
            _currentFileBytes + incomingBytes <= _options.MaximumFileBytes)
        {
            return;
        }

        Close();
        System.IO.Directory.CreateDirectory(_directory);

        var path = NextFilePath(today);
        _file = new FileStream(
            path,
            FileMode.Append,
            FileAccess.Write,
            // Read sharing is what lets an operator tail the file while the gateway is running, which
            // is how a Monitor-mode rollout is actually watched. Delete sharing lets retention remove
            // an old file even if something else has it open.
            FileShare.Read | FileShare.Delete);

        _currentFileBytes = _file.Length;
        _currentFileDate = today;
        ApplyRetention();
    }

    /// <summary>
    /// Picks the next file name for a date, appending an ordinal when earlier files for that date
    /// have already reached the size limit.
    /// </summary>
    /// <remarks>
    /// <b>The ordinal separator is <c>_</c> and not <c>-</c>, and the ordinal is zero-padded.</b> That
    /// looks arbitrary and is not: <see cref="ApplyRetention"/> orders files by name, and <c>-</c>
    /// (0x2D) sorts <i>before</i> <c>.</c> (0x2E), so <c>wpshield-20260906-1.jsonl</c> would compare
    /// as older than the <c>wpshield-20260906.jsonl</c> it actually succeeds. Retention would then
    /// have deleted the newest files of the day and kept the oldest — silently, and only on the days
    /// busy enough to rotate. <c>_</c> (0x5F) sorts after <c>.</c>, and the padding keeps
    /// <c>_0002</c> below <c>_0010</c>, so name order really is chronological order.
    /// </remarks>
    private string NextFilePath(DateOnly date)
    {
        var stamp = date.ToString("yyyyMMdd", CultureInfo.InvariantCulture);
        var basePath = Path.Combine(_directory, $"{_options.FileNamePrefix}-{stamp}{FileExtension}");

        if (!File.Exists(basePath) || new FileInfo(basePath).Length < _options.MaximumFileBytes)
        {
            return basePath;
        }

        for (var ordinal = 1; ordinal <= AbsoluteMaximumOrdinal; ordinal++)
        {
            var candidate = Path.Combine(
                _directory,
                $"{_options.FileNamePrefix}-{stamp}_{ordinal:D4}{FileExtension}");

            if (!File.Exists(candidate) || new FileInfo(candidate).Length < _options.MaximumFileBytes)
            {
                return candidate;
            }
        }

        // Every ordinal for the day is full. Appending past the limit is the least bad answer: the
        // alternatives are to stop logging or to overwrite evidence, and retention will remove this
        // file in the ordinary way.
        return basePath;
    }

    /// <summary>
    /// Deletes the oldest files beyond <see cref="FileLogOptions.RetainedFileCount"/>.
    /// </summary>
    /// <remarks>
    /// The date stamp is fixed-width and the ordinal is zero-padded behind a separator that sorts
    /// after the extension dot, so ordinal name order is also chronological order and no file
    /// timestamp has to be trusted — see <see cref="NextFilePath"/> for why that separator is not the
    /// obvious one. A file that cannot be deleted, held open by a log viewer most likely, is skipped
    /// rather than retried, because retention is housekeeping and must never become the reason
    /// logging stops.
    /// </remarks>
    private void ApplyRetention()
    {
        try
        {
            var files = System.IO.Directory
                .GetFiles(_directory, $"{_options.FileNamePrefix}-*{FileExtension}")
                .OrderByDescending(path => path, StringComparer.OrdinalIgnoreCase)
                .Skip(_options.RetainedFileCount)
                .ToArray();

            foreach (var path in files)
            {
                try
                {
                    File.Delete(path);
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                {
                }
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or DirectoryNotFoundException)
        {
        }
    }

    private void Close()
    {
        try
        {
            _file?.Flush();
            _file?.Dispose();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
        finally
        {
            _file = null;
            _currentFileBytes = 0;
        }
    }

    public async ValueTask DisposeAsync()
    {
        _queue.Writer.TryComplete();

        // A bounded wait, because shutdown must finish. The drain closes the file itself on the way
        // out; if it does not finish in time the file is closed here instead, which can lose the tail
        // of the queue but cannot hang a service stop.
        var completed = await Task.WhenAny(_drain, Task.Delay(DrainTimeout)).ConfigureAwait(false);
        if (completed != _drain)
        {
            Close();
        }
    }
}
