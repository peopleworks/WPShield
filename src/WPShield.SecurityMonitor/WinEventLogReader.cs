using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;

namespace WPShield.SecurityMonitor;

/// <summary>
/// Read-only reader for the Windows Security event log.
///
/// The Security log requires Administrator privileges. This reader never modifies,
/// clears, or archives the log; it only reads matching events.
/// </summary>
internal sealed class WinEventLogReader : IDisposable
{
    private readonly EventLogReader _reader;
    private bool _disposed;

    public WinEventLogReader(string logName, IEnumerable<int> eventIds)
    {
        if (string.IsNullOrWhiteSpace(logName))
            throw new ArgumentException("Log name cannot be empty.", nameof(logName));

        var idList = string.Join(" or ", eventIds.Select(id => $"EventID={id}"));
        var query = new EventLogQuery(logName, PathType.LogName, $"*[System[{idList}]]");

        try
        {
            _reader = new EventLogReader(query);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                $"Failed to open Security event log '{logName}'. " +
                "Ensure the process runs with Administrator privileges. " +
                $"Underlying error: {ex.Message}", ex);
        }
    }

    public IEnumerable<EventLogRecord> ReadAvailable()
    {
        var records = new List<EventLogRecord>();
        EventRecord? record;

        while ((record = _reader.ReadEvent()) is not null)
        {
            if (record is EventLogRecord logRecord)
            {
                records.Add(logRecord);
            }
        }

        return records;
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _reader.Dispose();
            _disposed = true;
        }
    }
}
