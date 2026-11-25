namespace WPShield.WebEvidence;

/// <summary>What one bounded read of a log file did.</summary>
/// <param name="Offset">
/// Where the next read starts: just past the last whole line consumed, or past the bytes of a line being
/// discarded (see <see cref="InsideDiscardedLine"/>). A partial last line is left for the next read.
/// </param>
/// <param name="Lines">Whole lines handed over.</param>
/// <param name="LongLinesSkipped">Lines longer than the bound, skipped whole and never parsed in part.</param>
/// <param name="Length">The file's length when it was opened.</param>
/// <param name="AtEnd">The read reached the end of the file: nothing is waiting but a partial line, if any.</param>
/// <param name="InsideDiscardedLine">
/// The read stopped inside a line it is discarding. The next read must pass <c>resync: true</c>, so the
/// rest of that line is dropped and the line is counted once.
/// </param>
public sealed record LogReadResult(long Offset, int Lines, int LongLinesSkipped, long Length, bool AtEnd, bool InsideDiscardedLine);

/// <summary>
/// Reads whole lines from a log file IIS is still writing, from an offset, with the bounds ADR 0011
/// sets: a line longer than <see cref="MaxLineBytes"/> is skipped and counted, never parsed in part, and
/// at most a given number of lines is read per call.
/// </summary>
/// <remarks>
/// The file is opened for reading only, sharing read, write and delete, because IIS holds it open for
/// writing and rotates it. A line is handed over as bytes and only while it is being read: nothing here
/// keeps one, and the caller decodes only the fields it maps.
/// </remarks>
public static class LogFileReader
{
    public const int MaxLineBytes = 16 * 1024;
    private const int BufferBytes = 64 * 1024;

    public delegate void LineHandler(ReadOnlySpan<byte> line);

    /// <summary>
    /// Reads from <paramref name="offset"/>. With <paramref name="resync"/>, the offset is inside a line -
    /// the catch-up starts from a byte position near the end, or the previous read stopped inside a long
    /// line - so everything up to the first line break is discarded first, uncounted.
    /// </summary>
    public static LogReadResult Read(string path, long offset, int maxLines, LineHandler onLine, bool resync = false)
    {
        ArgumentException.ThrowIfNullOrEmpty(path);
        ArgumentNullException.ThrowIfNull(onLine);
        ArgumentOutOfRangeException.ThrowIfNegative(offset);
        ArgumentOutOfRangeException.ThrowIfNegative(maxLines);
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, bufferSize: 1,
            FileOptions.SequentialScan);
        var length = stream.Length;
        if (offset > length) offset = length;
        stream.Seek(offset, SeekOrigin.Begin);

        var buffer = new byte[BufferBytes];
        var bufferOffset = offset; // the file offset of buffer[0]
        var filled = 0;
        var start = 0;
        var consumed = offset;
        var lines = 0;
        var skipped = 0;
        var discarding = resync && offset > 0;
        var end = false;

        while (lines < maxLines)
        {
            var newline = start < filled ? Array.IndexOf(buffer, (byte)'\n', start, filled - start) : -1;
            if (newline >= 0)
            {
                if (discarding)
                {
                    // The line the read started inside, or a long one, ends here. Nothing of it is handed over.
                    discarding = false;
                }
                else if (newline - start > MaxLineBytes)
                {
                    // A whole long line arrived in one read: skipped and counted, never parsed in part.
                    skipped++;
                }
                else
                {
                    onLine(buffer.AsSpan(start, newline - start));
                    lines++;
                }
                start = newline + 1;
                consumed = bufferOffset + start;
                continue;
            }

            // No line break in what is buffered. A line already past the bound is skipped whole: its bytes
            // are dropped as they arrive, and it is counted once.
            if (!discarding && filled - start > MaxLineBytes)
            {
                skipped++;
                discarding = true;
            }
            if (discarding)
            {
                bufferOffset += filled;
                consumed = bufferOffset;
                filled = start = 0;
            }
            else if (start > 0)
            {
                Buffer.BlockCopy(buffer, start, buffer, 0, filled - start);
                bufferOffset += start;
                filled -= start;
                start = 0;
            }

            var read = stream.Read(buffer, filled, buffer.Length - filled);
            if (read == 0)
            {
                end = true;
                break;
            }
            filled += read;
        }

        // A last line with no line break yet is IIS mid-write: its start stays the offset, so the next read
        // takes it whole. A discarded line in progress moves the offset past its bytes instead.
        return new LogReadResult(consumed, lines, skipped, length, end, discarding);
    }
}
