using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Security;

namespace WPShield.SecurityMonitor;

internal static class RecentEventLog
{
    internal const int MaxRecords = 256;
    internal static readonly TimeSpan Lookback = TimeSpan.FromMinutes(1);

    internal static string TimeFilter(DateTimeOffset end)
    {
        var start = (end - Lookback).UtcDateTime.ToString("O", CultureInfo.InvariantCulture);
        var stop = end.UtcDateTime.ToString("O", CultureInfo.InvariantCulture);
        return $"TimeCreated[@SystemTime >= '{start}' and @SystemTime <= '{stop}']";
    }

    internal static (string Status, IReadOnlyList<T> Events, string? UnavailableReason) Read<T>(
        string channel, string filter, Func<EventRecord, T?> project) where T : class
    {
        var events = new List<T>();
        var timer = Stopwatch.StartNew();
        var budget = TimeSpan.FromMilliseconds(500);
        try
        {
            var query = new EventLogQuery(channel, PathType.LogName, filter) { ReverseDirection = true };
            using var reader = new EventLogReader(query) { BatchSize = 16 };
            for (var i = 0; i <= MaxRecords; i++)
            {
                var remaining = budget - timer.Elapsed;
                if (remaining <= TimeSpan.Zero) break;
                using var record = reader.ReadEvent(remaining);
                if (record is null) return ("read", events, null);
                if (i == MaxRecords) break;
                if (project(record) is { } item) events.Add(item);
            }
            return ("limited", events, null);
        }
        catch (Exception ex) when (UnavailableReason(ex) is string reason)
        {
            return ("unavailable", [], reason);
        }
    }

    internal static string? UnavailableReason(Exception error) => error switch
    {
        UnauthorizedAccessException or SecurityException => "access-denied",
        EventLogException => "query-failed",
        _ => null
    };
}
