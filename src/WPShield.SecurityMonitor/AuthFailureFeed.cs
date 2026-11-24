using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security;
using System.Text;

namespace WPShield.SecurityMonitor;

/// <summary>One failed Windows authentication, as the event log recorded it.</summary>
/// <param name="Channel">
/// <c>security-4625</c> (Security log, any logon type) or <c>rdpcorets-140</c> (Remote Desktop's own
/// record of a wrong user name or password, which carries the client address when NLA left 4625
/// without one).
/// </param>
/// <param name="Address">The source address, or <see langword="null"/> when the record has none.</param>
/// <param name="Account">
/// The account name the client tried, cleaned of control and format characters and bounded. The
/// attacker chose this text; it is evidence, never a label to trust.
/// </param>
/// <param name="Reason">A stable code: <c>unknown-account</c>, <c>bad-password</c>, <c>locked-out</c>...</param>
public sealed record AuthFailure(DateTimeOffset Timestamp, string Channel, IPAddress? Address, int? Port,
    string Account, string Reason, int? LogonType, long RecordId);

/// <summary>What one channel could be read for, so an empty list is never mistaken for a quiet host.</summary>
/// <param name="Status"><c>read</c>, <c>limited</c> (a bound stopped the read) or <c>unavailable</c>.</param>
/// <param name="OldestRead">The oldest record read. Before it, this read knows nothing.</param>
/// <param name="LogStartsAt">The oldest record still in the log. A window that starts earlier is not covered.</param>
public sealed record ChannelCoverage(string Channel, string Status, string? Reason, DateTimeOffset? OldestRead,
    DateTimeOffset? LogStartsAt, int Count);

public sealed record AuthFailureSnapshot(DateTimeOffset WindowStart, DateTimeOffset WindowEnd,
    IReadOnlyList<AuthFailure> Failures, IReadOnlyList<ChannelCoverage> Coverage);

/// <summary>
/// Reads recent failed logons and then follows new ones as Windows writes them.
/// </summary>
/// <remarks>
/// <para>
/// History is read newest first and bounded by a record count and a time budget, because a host under
/// brute force writes thousands of 4625 records an hour. Coverage says how far back the read reached
/// and how far back the log itself reaches; the caller must show both.
/// </para>
/// <para>
/// Live records arrive through an <see cref="EventLogWatcher"/> subscription. Nothing here replays the
/// log into a decision: this feed is for showing attacks, and a decision engine that consumes it must
/// start from "now".
/// </para>
/// </remarks>
public static class AuthFailureFeed
{
    public const string SecurityChannel = "Security";
    public const string RdpCoreChannel = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational";
    public const int MaxRecordsPerChannel = 20_000;
    internal const int MaxAccountLength = 64;

    private static readonly string[] Fields4625 =
        ["TargetUserName", "Status", "SubStatus", "LogonType", "IpAddress", "IpPort"];

    public static AuthFailureSnapshot ReadRecent(DateTimeOffset end, TimeSpan window,
        int maxRecordsPerChannel = MaxRecordsPerChannel, TimeSpan? budgetPerChannel = null)
    {
        var start = end - window;
        var budget = budgetPerChannel ?? TimeSpan.FromSeconds(10);
        var failures = new List<AuthFailure>();
        var coverage = new List<ChannelCoverage>
        {
            ReadChannel(SecurityChannel, 4625, start, maxRecordsPerChannel, budget, failures),
            ReadChannel(RdpCoreChannel, 140, start, maxRecordsPerChannel, budget, failures)
        };
        failures.Sort((a, b) => a.Timestamp.CompareTo(b.Timestamp));
        return new(start, end, failures, coverage);
    }

    /// <summary>Follows both channels. Errors are reported per channel and never thrown.</summary>
    public static IDisposable Watch(Action<AuthFailure> onFailure, Action<string, string> onError)
    {
        var subscription = new Subscription();
        subscription.Add(SecurityChannel, "*[System[(EventID=4625)]]", onFailure, onError);
        subscription.Add(RdpCoreChannel, "*[System[(EventID=140)]]", onFailure, onError);
        return subscription;
    }

    private static ChannelCoverage ReadChannel(string channel, int eventId, DateTimeOffset start, int max,
        TimeSpan budget, List<AuthFailure> into)
    {
        var timer = Stopwatch.StartNew();
        var since = start.UtcDateTime.ToString("O", CultureInfo.InvariantCulture);
        var filter = $"*[System[(EventID={eventId}) and TimeCreated[@SystemTime >= '{since}']]]";
        var count = 0;
        DateTimeOffset? oldest = null;
        try
        {
            var logStart = OldestInLog(channel);
            var query = new EventLogQuery(channel, PathType.LogName, filter) { ReverseDirection = true };
            using var reader = new EventLogReader(query) { BatchSize = 64 };
            using var selector = eventId == 4625 ? Selector() : null;
            while (true)
            {
                var remaining = budget - timer.Elapsed;
                if (remaining <= TimeSpan.Zero || count >= max) return new(channel, "limited", null, oldest, logStart, count);
                using var record = reader.ReadEvent(remaining);
                if (record is null) return new(channel, "read", null, oldest, logStart, count);
                if (Project(record, eventId, selector) is not { } failure) continue;
                into.Add(failure);
                count++;
                oldest = failure.Timestamp;
            }
        }
        catch (Exception ex) when (UnavailableReason(ex) is string reason)
        {
            return new(channel, "unavailable", reason, oldest, null, count);
        }
    }

    private static DateTimeOffset? OldestInLog(string channel)
    {
        using var reader = new EventLogReader(new EventLogQuery(channel, PathType.LogName));
        using var first = reader.ReadEvent(TimeSpan.FromSeconds(2));
        return first?.TimeCreated is DateTime time ? new DateTimeOffset(time.ToUniversalTime(), TimeSpan.Zero) : null;
    }

    private static EventLogPropertySelector Selector() =>
        new(Fields4625.Select(name => $"Event/EventData/Data[@Name='{name}']"));

    private static AuthFailure? Project(EventRecord record, int eventId, EventLogPropertySelector? selector)
    {
        if (record is not EventLogRecord native || native.RecordId is not long id || native.TimeCreated is not DateTime time)
            return null;
        if (eventId == 4625 && selector is not null)
            return From4625(id, time, native.GetPropertyValues(selector));
        return From140(id, time, record.Properties.Select(p => p.Value).ToArray());
    }

    /// <summary>Values in the order of <see cref="Fields4625"/>.</summary>
    internal static AuthFailure? From4625(long recordId, DateTime timeCreated, IList<object?> values)
    {
        if (values.Count < Fields4625.Length) return null;
        var address = ParseAddress(values[4] as string);
        int? port = int.TryParse(Convert.ToString(values[5], CultureInfo.InvariantCulture), NumberStyles.None,
            CultureInfo.InvariantCulture, out var p) && p is > 0 and <= 65535 ? p : null;
        var type = ToCode(values[3]);
        int? logonType = type is > 0 and < 100 ? (int)type : null;
        return new(Utc(timeCreated), "security-4625", address, address is null ? null : port,
            CleanAccount(values[0] as string), Reason(ToCode(values[1]), ToCode(values[2])), logonType, recordId);
    }

    internal static AuthFailure? From140(long recordId, DateTime timeCreated, IList<object?> properties)
    {
        if (properties.Count == 0 || ParseAddress(properties[0] as string) is not { } address) return null;
        return new(Utc(timeCreated), "rdpcorets-140", address, null, "", "bad-credentials", 10, recordId);
    }

    internal static string Reason(uint status, uint subStatus) => (subStatus != 0 ? subStatus : status) switch
    {
        0xC0000064 => "unknown-account",
        0xC000006A => "bad-password",
        0xC0000234 => "locked-out",
        0xC0000072 => "disabled",
        0xC0000193 => "account-expired",
        0xC0000071 => "password-expired",
        0xC0000224 => "password-must-change",
        0xC000006F => "outside-hours",
        0xC0000070 => "workstation-restricted",
        0xC000015B => "logon-type-denied",
        0xC0000133 => "clock-skew",
        0xC000006D => "bad-credentials",
        _ => "other"
    };

    internal static IPAddress? ParseAddress(string? text)
    {
        if (string.IsNullOrWhiteSpace(text) || !IPAddress.TryParse(text.Trim(), out var ip)) return null;
        // IPAddress also accepts legacy numeric IPv4 spellings such as "1" or octal parts.
        if (ip.AddressFamily == AddressFamily.InterNetwork && text.Trim() != ip.ToString()) return null;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any) || ip.Equals(IPAddress.None)) return null;
        return ip;
    }

    internal static string CleanAccount(string? name)
    {
        if (string.IsNullOrEmpty(name) || name == "-") return "";
        var builder = new StringBuilder(Math.Min(name.Length, MaxAccountLength));
        foreach (var rune in name.EnumerateRunes())
        {
            if (builder.Length >= MaxAccountLength) break;
            var category = Rune.GetUnicodeCategory(rune);
            builder.Append(category is UnicodeCategory.Control or UnicodeCategory.Format or UnicodeCategory.LineSeparator
                or UnicodeCategory.ParagraphSeparator or UnicodeCategory.Surrogate or UnicodeCategory.PrivateUse
                or UnicodeCategory.OtherNotAssigned ? "�" : rune.ToString());
        }
        return builder.ToString();
    }

    private static uint ToCode(object? value) => value switch
    {
        uint u => u,
        int i => unchecked((uint)i),
        long l => unchecked((uint)l),
        ulong ul => unchecked((uint)ul),
        ushort s => s,
        byte b => b,
        string s when s.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
            uint.TryParse(s.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var hex) => hex,
        string s when uint.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out var number) => number,
        _ => 0
    };

    private static DateTimeOffset Utc(DateTime time) => new(time.Kind == DateTimeKind.Utc ? time : time.ToUniversalTime(), TimeSpan.Zero);

    internal static string? UnavailableReason(Exception error) => error switch
    {
        UnauthorizedAccessException or SecurityException => "access-denied",
        EventLogNotFoundException => "channel-missing",
        EventLogException => "query-failed",
        _ => null
    };

    private sealed class Subscription : IDisposable
    {
        private readonly List<IDisposable> owned = [];

        internal void Add(string channel, string filter, Action<AuthFailure> onFailure, Action<string, string> onError)
        {
            var eventId = channel == SecurityChannel ? 4625 : 140;
            var selector = eventId == 4625 ? Selector() : null;
            EventLogWatcher? watcher = null;
            try
            {
                watcher = new EventLogWatcher(new EventLogQuery(channel, PathType.LogName, filter));
                watcher.EventRecordWritten += (_, args) =>
                {
                    if (args.EventException is { } error)
                    {
                        onError(channel, UnavailableReason(error) ?? "query-failed");
                        return;
                    }
                    using var record = args.EventRecord;
                    if (record is not null && Project(record, eventId, selector) is { } failure) onFailure(failure);
                };
                watcher.Enabled = true;
                // Disposed in reverse: the watcher stops before the selector it uses goes away.
                if (selector is not null) owned.Add(selector);
                owned.Add(watcher);
            }
            catch (Exception ex) when (UnavailableReason(ex) is string reason)
            {
                watcher?.Dispose();
                selector?.Dispose();
                onError(channel, reason);
            }
        }

        public void Dispose()
        {
            for (var i = owned.Count - 1; i >= 0; i--)
            {
                if (owned[i] is EventLogWatcher watcher) watcher.Enabled = false;
                owned[i].Dispose();
            }
            owned.Clear();
        }
    }
}
