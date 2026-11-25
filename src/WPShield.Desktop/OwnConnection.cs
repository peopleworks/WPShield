using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Net;
using System.Security;
using WPShield.Evidence.Decisions;
using WPShield.SecurityMonitor;

namespace WPShield.Desktop;

/// <summary>One LocalSessionManager logon (21) or reconnection (25) record: which session, from where, when.</summary>
/// <param name="Address">The record's text as written: an address, or <c>LOCAL</c> for a console logon.</param>
internal sealed record SessionRecord(int EventId, uint SessionId, string Address, DateTimeOffset At);

/// <summary>
/// The address the settings window may offer as "My current connection", or why it offers none.
/// <see cref="Code"/> is a stable English code the window words in the operator's language.
/// </summary>
/// <param name="Address">The address offered, as canonical text; <see langword="null"/> when none is.</param>
/// <param name="Peers">The remote addresses this server sees on its Remote Desktop port now; empty when unread.</param>
/// <param name="Recorded">The address this session's newest logon or reconnection record names, when it names one.</param>
/// <param name="ClientReported">What the Remote Desktop client reports about itself. Shown for information; never offered.</param>
/// <param name="Problem">Why a fact could not be read: the connection table, the session log, or the session type.</param>
internal sealed record OwnConnection(string? Address, string Code, IReadOnlyList<string> Peers, string? Recorded, string? ClientReported,
    string? Problem, DateTimeOffset ReadAt)
{
    /// <summary>This session's newest logon record names an address that is connected now.</summary>
    internal const string ThisSession = "this-session";
    /// <summary>No record names this session's address, and exactly one connection exists.</summary>
    internal const string OnlyConnection = "only-connection";
    internal const string NotRemote = "not-remote";
    /// <summary>Several connections, and nothing says which one is this session.</summary>
    internal const string Ambiguous = "ambiguous";
    /// <summary>The record names an address that is not connected now: a Remote Desktop Gateway, or an older record.</summary>
    internal const string RecordNotConnected = "record-not-connected";
    /// <summary>This server sees no Remote Desktop connection at all.</summary>
    internal const string NoConnection = "no-connection";
    /// <summary>The connection table, or whether this is a Remote Desktop session, could not be read.</summary>
    internal const string Unknown = "unknown";

    internal static OwnConnection None(string code, string? problem = null) => new(null, code, [], null, null, problem, DateTimeOffset.UtcNow);
}

/// <summary>
/// Decides which address "My current connection" offers: the address <b>this server</b> sees for the
/// operator's own Remote Desktop session, never the one the client reports about itself.
/// </summary>
/// <remarks>
/// <para>
/// The client-reported address (<c>WTSClientAddress</c>) is what the Remote Desktop client says about
/// itself; behind NAT it is a private address that never matches anything this server sees. The
/// server's own view is the established connections to its Remote Desktop port
/// (<see cref="HostProbes.RemoteDesktop"/>). When several people are connected, the session's newest
/// LocalSessionManager logon or reconnection record says which of them is this session - and only if
/// that address is among the connections now.
/// </para>
/// <para>
/// Never a guess: with several connections and no record that matches one, nothing is offered and the
/// connections are listed so the operator can type the right one. A record whose address is not
/// connected now (a Remote Desktop Gateway, or an older record) is not offered either.
/// </para>
/// </remarks>
internal static class ConnectionResolver
{
    internal static OwnConnection Resolve(bool? remote, SessionRecord? record, string? recordProblem, RemoteDesktopSnapshot snapshot,
        string? clientReported, DateTimeOffset readAt)
    {
        if (remote is false) return new(null, OwnConnection.NotRemote, [], null, null, null, readAt);
        if (remote is null) return new(null, OwnConnection.Unknown, [], null, null, "session-type-unknown", readAt);
        if (snapshot.Clients is null)
            return new(null, OwnConnection.Unknown, [], null, clientReported, snapshot.Problem ?? "connections-unreadable", readAt);

        var peers = snapshot.Clients.Select(Canonical).Distinct().ToArray();
        var shown = peers.Select(p => p.ToString()).ToArray();
        var recorded = record is null ? null : Address(record.Address);
        if (recorded is not null)
        {
            var text = recorded.ToString();
            return peers.Contains(recorded)
                ? new(text, OwnConnection.ThisSession, shown, text, clientReported, null, readAt)
                : new(null, OwnConnection.RecordNotConnected, shown, text, clientReported, null, readAt);
        }
        return peers.Length switch
        {
            0 => new(null, OwnConnection.NoConnection, shown, null, clientReported, recordProblem, readAt),
            1 => new(shown[0], OwnConnection.OnlyConnection, shown, null, clientReported, recordProblem, readAt),
            _ => new(null, OwnConnection.Ambiguous, shown, null, clientReported, recordProblem, readAt)
        };
    }

    /// <summary>A record's address, or <see langword="null"/> for <c>LOCAL</c>, empty or anything that is not an IP address.</summary>
    internal static IPAddress? Address(string? text) =>
        IPAddress.TryParse(text?.Trim(), out var address) ? Canonical(address) : null;

    /// <summary>IPv4-mapped IPv6 as IPv4, and no IPv6 scope, so a record and a table row compare equal.</summary>
    private static IPAddress Canonical(IPAddress address) => new(AddressRanges.Canonical(address).GetAddressBytes());
}

/// <summary>
/// Reads the newest LocalSessionManager logon (21) or reconnection (25) record of one session.
/// </summary>
/// <remarks>
/// <para>
/// Both events use one template, checked against the provider's published manifest and against real
/// records: <c>User</c> (string), <c>SessionID</c> (UInt32), <c>Address</c> (string), in that order. The
/// user name is never read.
/// </para>
/// <para>
/// Newest first, at most <see cref="MaxRecords"/> records and <see cref="Budget"/> of time. A record
/// written before the last boot cannot belong to a session that exists now - session numbers start
/// again after a restart - so the search stops there. An unreadable channel is a reason, not an
/// exception.
/// </para>
/// </remarks>
internal static class SessionLog
{
    internal const string Channel = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";
    internal const string Filter = "*[System[(EventID=21 or EventID=25)]]";
    internal const int MaxRecords = 500;
    internal static readonly TimeSpan Budget = TimeSpan.FromSeconds(2);

    /// <summary>A record from its event ID, properties in template order, and creation time; <see langword="null"/> when it does not fit.</summary>
    internal static SessionRecord? Parse(int eventId, IReadOnlyList<object?> properties, DateTime? created)
    {
        if (eventId is not (21 or 25) || properties.Count < 3 || created is not DateTime time) return null;
        uint? session = properties[1] switch
        {
            uint value => value,
            int value when value >= 0 => (uint)value,
            _ => null
        };
        if (session is null || properties[2] is not string address) return null;
        var at = new DateTimeOffset(time.Kind == DateTimeKind.Utc ? time : time.ToUniversalTime(), TimeSpan.Zero);
        return new(eventId, session.Value, address, at);
    }

    /// <summary>The first record of <paramref name="sessionId"/> in newest-first order, not older than the last boot.</summary>
    internal static SessionRecord? Newest(IEnumerable<SessionRecord> newestFirst, uint sessionId, DateTimeOffset bootedAt)
    {
        foreach (var record in newestFirst)
        {
            if (record.At < bootedAt) return null;
            if (record.SessionId == sessionId) return record;
        }
        return null;
    }

    /// <summary>The newest record of this session, or why the log could not be read. Never throws for an unreadable log.</summary>
    internal static (SessionRecord? Record, string? Problem) Read(uint sessionId, DateTimeOffset bootedAt)
    {
        try
        {
            var (records, limited) = ReadNewest();
            var newest = Newest(records, sessionId, bootedAt);
            return (newest, newest is null && limited ? "log-limit" : null);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or SecurityException)
        {
            return (null, "access-denied");
        }
        catch (EventLogNotFoundException)
        {
            return (null, "channel-missing");
        }
        catch (EventLogException)
        {
            return (null, "query-failed");
        }
    }

    private static (List<SessionRecord> Records, bool Limited) ReadNewest()
    {
        var timer = Stopwatch.StartNew();
        var records = new List<SessionRecord>();
        using var reader = new EventLogReader(new EventLogQuery(Channel, PathType.LogName, Filter) { ReverseDirection = true }) { BatchSize = 64 };
        for (var read = 0; read < MaxRecords; read++)
        {
            var remaining = Budget - timer.Elapsed;
            if (remaining <= TimeSpan.Zero) return (records, true);
            using var record = reader.ReadEvent(remaining);
            if (record is null) return (records, false);
            if (Parse(record.Id, record.Properties.Select(p => p.Value).ToArray(), record.TimeCreated) is { } parsed) records.Add(parsed);
        }
        return (records, true);
    }

    /// <summary>When this host last started, from the milliseconds since boot (sleep included).</summary>
    internal static DateTimeOffset BootedAt(DateTimeOffset now) => now - TimeSpan.FromMilliseconds(Environment.TickCount64);
}

/// <summary>Reads the facts <see cref="ConnectionResolver"/> needs, on the calling thread. Call it off the interface thread.</summary>
internal static class OwnConnectionReader
{
    internal static OwnConnection Read()
    {
        var now = DateTimeOffset.UtcNow;
        var remote = RemoteSession.IsRemote();
        if (remote is not true) return ConnectionResolver.Resolve(remote, null, null, RemoteDesktopSnapshot.Unreadable("not-read"), null, now);
        uint session;
        using (var process = Process.GetCurrentProcess()) session = (uint)process.SessionId;
        var (record, problem) = SessionLog.Read(session, SessionLog.BootedAt(now));
        var snapshot = HostProbes.RemoteDesktop();
        return ConnectionResolver.Resolve(true, record, problem, snapshot, RemoteSession.Current().Address, now);
    }
}
