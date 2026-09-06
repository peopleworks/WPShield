namespace WPShield.Logging;

/// <summary>
/// Rejects log bounds the writer would otherwise have to silently reinterpret.
/// </summary>
/// <remarks>
/// Same rule the multipart bounds follow: throw, do not clamp. Every value here caps disk or memory,
/// and an operator who asks for a 1 KiB rotation size or a retention of zero and quietly receives
/// something else has been told nothing. The failure happens at startup, where it is attributable,
/// rather than at the first moment the log was needed.
/// </remarks>
public static class FileLogOptionsValidator
{
    public static void Validate(FileLogOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (string.IsNullOrWhiteSpace(options.Directory))
        {
            throw new InvalidOperationException(
                "Logging:File:Directory must name a directory. A relative path resolves against the " +
                "content root, which for a Windows service is the installation directory.");
        }

        if (string.IsNullOrWhiteSpace(options.FileNamePrefix) ||
            options.FileNamePrefix.AsSpan().IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
        {
            throw new InvalidOperationException(
                "Logging:File:FileNamePrefix must be a non-empty value that is valid in a file name.");
        }

        if (options.MaximumFileBytes < FileLogOptions.MinimumMaximumFileBytes ||
            options.MaximumFileBytes > FileLogOptions.AbsoluteMaximumFileBytes)
        {
            throw new InvalidOperationException(
                $"Logging:File:MaximumFileBytes must be between {FileLogOptions.MinimumMaximumFileBytes} " +
                $"and {FileLogOptions.AbsoluteMaximumFileBytes} bytes.");
        }

        if (options.RetainedFileCount < 1 ||
            options.RetainedFileCount > FileLogOptions.AbsoluteMaximumRetainedFileCount)
        {
            throw new InvalidOperationException(
                "Logging:File:RetainedFileCount must be between 1 and " +
                $"{FileLogOptions.AbsoluteMaximumRetainedFileCount}. A retention of zero would delete " +
                "the file the gateway is writing to.");
        }

        if (options.MaximumQueuedEntries < FileLogOptions.MinimumQueuedEntries ||
            options.MaximumQueuedEntries > FileLogOptions.AbsoluteMaximumQueuedEntries)
        {
            throw new InvalidOperationException(
                $"Logging:File:MaximumQueuedEntries must be between {FileLogOptions.MinimumQueuedEntries} " +
                $"and {FileLogOptions.AbsoluteMaximumQueuedEntries}.");
        }
    }
}
