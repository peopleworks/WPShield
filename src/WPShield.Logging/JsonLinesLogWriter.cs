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
/// <b>Nothing here is allowed to throw into the gateway.</b> A security gateway that cannot write its
/// log has a serious problem, but refusing to serve traffic is a worse one, so write failures are
/// counted and retried on the next batch rather than propagated. The first failure of each streak is
/// reported to the standard error stream, which under a Windows service is captured by the service
/// host and is the one channel still available when the file destination is exactly what is broken.
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

    private FileStream? _file;
    private long _currentFileBytes;
    private DateOnly _currentFileDate;
    private int _droppedSinceLastReport;
    private bool _failing;

    public JsonLinesLogWriter(FileLogOptions options, string contentRootPath, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(contentRootPath);

        _options = options;
        _timeProvider = timeProvider ?? TimeProvider.System;
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
                _failing = true;
                Console.Error.WriteLine(
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
