namespace WPShield.NetworkSensor;

/// <summary>
/// Handles rotation and retention for the NetworkSensor JSON Lines output file.
/// Rotation is triggered by file size; retention purges files older than the configured days.
/// </summary>
public sealed class LogRotation : IDisposable
{
    private readonly string _outputPath;
    private readonly long _maxFileSizeBytes;
    private readonly int _retentionDays;
    private FileStream? _stream;
    private StreamWriter? _writer;

    public LogRotation(string outputPath, long maxFileSizeBytes, int retentionDays)
    {
        _outputPath = outputPath;
        _maxFileSizeBytes = maxFileSizeBytes;
        _retentionDays = retentionDays;
    }

    /// <summary>
    /// Writes a single JSON line to the current output file, rotating if the size limit is reached.
    /// </summary>
    public void Write(string jsonLine)
    {
        EnsureWriter();

        if (_stream is not null && _stream.Length >= _maxFileSizeBytes)
        {
            Rotate();
        }

        _writer!.WriteLine(jsonLine);
        _writer.Flush();
    }

    /// <summary>
    /// Purges rotated files older than <see cref="RetentionDays"/>.
    /// </summary>
    public void EnforceRetention()
    {
        var directory = Path.GetDirectoryName(_outputPath);
        if (string.IsNullOrEmpty(directory))
        {
            return;
        }

        var cutoff = DateTimeOffset.UtcNow.AddDays(-_retentionDays);

        foreach (var file in Directory.GetFiles(directory, "*.ndjson*"))
        {
            try
            {
                var lastWrite = File.GetLastWriteTimeUtc(file);
                if (lastWrite < cutoff)
                {
                    File.Delete(file);
                }
            }
            catch
            {
                // Retention is best-effort. A locked or inaccessible file is skipped.
            }
        }
    }

    private void EnsureWriter()
    {
        if (_writer is not null)
        {
            return;
        }

        var directory = Path.GetDirectoryName(_outputPath);
        if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
        {
            Directory.CreateDirectory(directory);
        }

        _stream = new FileStream(_outputPath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
        _writer = new StreamWriter(_stream, leaveOpen: true) { AutoFlush = true };
    }

    private void Rotate()
    {
        _writer?.Flush();
        _stream?.Close();
        _stream?.Dispose();
        _writer?.Dispose();

        var timestamp = DateTimeOffset.UtcNow.ToString("yyyyMMddTHHmmssZ");
        var rotatedPath = $"{_outputPath}.{timestamp}";
        File.Move(_outputPath, rotatedPath);

        _stream = new FileStream(_outputPath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
        _writer = new StreamWriter(_stream, leaveOpen: true) { AutoFlush = true };

        EnforceRetention();
    }

    public void Dispose()
    {
        _writer?.Dispose();
        _stream?.Dispose();
        _writer = null;
        _stream = null;
        GC.SuppressFinalize(this);
    }
}
