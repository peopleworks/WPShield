using System.Text;

namespace WPShield.Cli.Watch;

/// <summary>
/// Follows the gateway's newest JSON Lines file the way <c>tail -f</c> would, and steps to the next
/// file when the gateway rotates.
/// </summary>
/// <remarks>
/// <para>
/// The gateway is appending to this file from another process, on a host that may be under attack,
/// so the read side assumes nothing. It shares the file for reading, writing and deletion so it can
/// never be the reason a rotation or a retention delete fails. It advances a byte position and
/// carries an incomplete trailing line between polls, so a line caught half-written is never handed
/// on as a torn record — it is completed on the next poll.
/// </para>
/// <para>
/// <b>Rotation is read from the newest file name, and the old file is drained first.</b> The writer
/// names files so that name order is chronological (see <c>JsonLinesLogWriter</c>), so a newer name
/// appearing is the signal. When it does, whatever complete lines remain in the file being left are
/// returned before the reader moves on, so the last few events before a rotation are never skipped.
/// </para>
/// <para>
/// This does no waiting of its own. It returns the lines available now and is called again on an
/// interval by the command loop, which keeps it synchronous and makes what it returns for a given
/// sequence of file states exactly testable.
/// </para>
/// </remarks>
internal sealed class JsonlTailReader
{
    private const byte NewLine = (byte)'\n';

    private readonly string _directory;
    private readonly string _searchPattern;
    private readonly bool _fromStart;

    private string? _currentPath;
    private long _position;
    private byte[] _carry = [];
    private bool _started;

    public JsonlTailReader(string directory, bool fromStart, string searchPattern = "wpshield-*.jsonl")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        ArgumentException.ThrowIfNullOrWhiteSpace(searchPattern);

        _directory = directory;
        _searchPattern = searchPattern;
        _fromStart = fromStart;
    }

    /// <summary>The file currently being followed, for the console to show. Null until the first read.</summary>
    public string? CurrentFile => _currentPath is null ? null : Path.GetFileName(_currentPath);

    /// <summary>
    /// The complete lines that have become available since the last call, in order. Empty when
    /// nothing new has arrived, or when the directory holds no log file yet.
    /// </summary>
    public IReadOnlyList<string> ReadNewLines()
    {
        var newest = NewestFile();
        if (newest is null)
        {
            return [];
        }

        var lines = new List<string>();

        if (!_started)
        {
            _started = true;
            _currentPath = newest;
            // From the end by default: an operator running this wants to see what happens next, not
            // replay the whole day. --from-start rewinds to the top of the current file instead.
            _position = _fromStart ? 0 : SafeLength(newest);
            DrainInto(lines);
            return lines;
        }

        if (!string.Equals(newest, _currentPath, StringComparison.OrdinalIgnoreCase))
        {
            // A rotation happened. Finish the file being left, then start the new one from the top so
            // none of its opening lines are missed.
            DrainInto(lines);
            _currentPath = newest;
            _position = 0;
            _carry = [];
            DrainInto(lines);
            return lines;
        }

        DrainInto(lines);
        return lines;
    }

    private void DrainInto(List<string> lines)
    {
        if (_currentPath is null)
        {
            return;
        }

        byte[] appended;
        try
        {
            using var stream = new FileStream(
                _currentPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);

            var length = stream.Length;

            // The file got shorter than where we were reading — it was truncated or replaced under
            // the same name. Start it over rather than seeking past its end.
            if (length < _position)
            {
                _position = 0;
                _carry = [];
            }

            if (length == _position)
            {
                return;
            }

            stream.Seek(_position, SeekOrigin.Begin);
            appended = new byte[length - _position];
            var read = ReadFully(stream, appended);
            if (read < appended.Length)
            {
                appended = appended[..read];
            }

            _position += read;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // A momentary sharing or access hiccup. Leave the position where it was and try again on
            // the next poll rather than losing our place or throwing out of the console.
            return;
        }

        SplitInto(lines, appended);
    }

    private void SplitInto(List<string> lines, byte[] appended)
    {
        var buffer = _carry.Length == 0 ? appended : Concat(_carry, appended);

        var start = 0;
        for (var index = 0; index < buffer.Length; index++)
        {
            if (buffer[index] != NewLine)
            {
                continue;
            }

            var lineLength = index - start;
            // Tolerate CRLF: drop a trailing carriage return before decoding.
            if (lineLength > 0 && buffer[start + lineLength - 1] == (byte)'\r')
            {
                lineLength--;
            }

            if (lineLength > 0)
            {
                lines.Add(Encoding.UTF8.GetString(buffer, start, lineLength));
            }

            start = index + 1;
        }

        _carry = start >= buffer.Length ? [] : buffer[start..];
    }

    private string? NewestFile()
    {
        try
        {
            return new DirectoryInfo(_directory)
                .GetFiles(_searchPattern)
                .Select(file => file.FullName)
                .OrderByDescending(path => path, StringComparer.OrdinalIgnoreCase)
                .FirstOrDefault();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or DirectoryNotFoundException)
        {
            return null;
        }
    }

    private static long SafeLength(string path)
    {
        try
        {
            return new FileInfo(path).Length;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return 0;
        }
    }

    private static int ReadFully(Stream stream, byte[] destination)
    {
        var total = 0;
        while (total < destination.Length)
        {
            var read = stream.Read(destination, total, destination.Length - total);
            if (read == 0)
            {
                break;
            }

            total += read;
        }

        return total;
    }

    private static byte[] Concat(byte[] first, byte[] second)
    {
        var combined = new byte[first.Length + second.Length];
        Buffer.BlockCopy(first, 0, combined, 0, first.Length);
        Buffer.BlockCopy(second, 0, combined, first.Length, second.Length);
        return combined;
    }
}
