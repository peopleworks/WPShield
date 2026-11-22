using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Net;
using System.Security;

namespace WPShield.SecurityMonitor;

public sealed record RemoteLogon(int EventId, long RecordId, DateTimeOffset Timestamp, IPEndPoint Source);

public sealed record RdpAuditWindow(string Status, IReadOnlyList<RemoteLogon> Events);

public static class RdpAuditReader
{
    internal const int MaxRecords = 256;
    internal static readonly TimeSpan Lookback = TimeSpan.FromMinutes(1);

    internal static string Query(DateTimeOffset end)
    {
        var start = (end - Lookback).UtcDateTime.ToString("O", CultureInfo.InvariantCulture);
        var stop = end.UtcDateTime.ToString("O", CultureInfo.InvariantCulture);
        return $"*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and (EventID=4624 or EventID=4625) and TimeCreated[@SystemTime >= '{start}' and @SystemTime <= '{stop}']] and EventData[Data[@Name='LogonType']='10']]";
    }

    public static RdpAuditWindow Read(DateTimeOffset end)
    {
        var events = new List<RemoteLogon>();
        var timer = Stopwatch.StartNew();
        var budget = TimeSpan.FromMilliseconds(500);
        try
        {
            var query = new EventLogQuery("Security", PathType.LogName, Query(end)) { ReverseDirection = true };
            using var reader = new EventLogReader(query) { BatchSize = 16 };
            using var fields = new EventLogPropertySelector(["Event/EventData/Data[@Name='IpAddress']", "Event/EventData/Data[@Name='IpPort']"]);
            for (var i = 0; i <= MaxRecords; i++)
            {
                var remaining = budget - timer.Elapsed;
                if (remaining <= TimeSpan.Zero) break;
                using var record = reader.ReadEvent(remaining);
                if (record is null) return new("read", events);
                if (i == MaxRecords) break;
                if (record is not EventLogRecord native || native.RecordId is not long id || native.TimeCreated is not DateTime time)
                    continue;

                var values = native.GetPropertyValues(fields);
                if (values.Count == 2 && ParseSource(values[0] as string, Convert.ToString(values[1], CultureInfo.InvariantCulture)) is { } source)
                    events.Add(new(native.Id, id, time.ToUniversalTime(), source));
            }
            return new("limited", events);
        }
        catch (Exception ex) when (ex is EventLogException or UnauthorizedAccessException or SecurityException)
        {
            return new("unavailable", []);
        }
    }

    internal static IPEndPoint? ParseSource(string? address, string? port)
    {
        if (!IPAddress.TryParse(address, out var ip) ||
            !ushort.TryParse(port, NumberStyles.None, CultureInfo.InvariantCulture, out var number) || number == 0)
            return null;
        // IPAddress also accepts legacy numeric IPv4 spellings (e.g. "1" or octal).
        if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && address != ip.ToString()) return null;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any)) return null;
        return new(ip, number);
    }
}
