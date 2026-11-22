using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Net;

namespace WPShield.SecurityMonitor;

public sealed record RemoteLogon(int EventId, long RecordId, DateTimeOffset Timestamp, IPEndPoint Source);

public sealed record RdpAuditWindow(string Status, IReadOnlyList<RemoteLogon> Events);

public static class RdpAuditReader
{
    public static RdpAuditWindow Read(DateTimeOffset end)
    {
        var filter = $"*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and (EventID=4624 or EventID=4625) and {RecentEventLog.TimeFilter(end)}] and EventData[Data[@Name='LogonType']='10']]";
        EventLogPropertySelector? fields = null;
        try
        {
            var window = RecentEventLog.Read<RemoteLogon>("Security", filter, record =>
            {
                if (record is not EventLogRecord native || native.RecordId is not long id || native.TimeCreated is not DateTime time)
                    return null;
                fields ??= new EventLogPropertySelector(["Event/EventData/Data[@Name='IpAddress']", "Event/EventData/Data[@Name='IpPort']"]);
                var values = native.GetPropertyValues(fields);
                if (values.Count == 2 && ParseSource(values[0] as string, Convert.ToString(values[1], CultureInfo.InvariantCulture)) is { } source)
                    return new(native.Id, id, time.ToUniversalTime(), source);
                return null;
            });
            return new(window.Status, window.Events);
        }
        finally
        {
            fields?.Dispose();
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
