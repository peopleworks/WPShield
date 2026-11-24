using System.Globalization;
using System.Net;
using System.Net.Sockets;
using WPShield.SecurityMonitor;

namespace WPShield.Desktop;

internal enum AttackRange { Hour, SixHours, Day }

/// <summary>One bar of the timeline. <c>Covered</c> is false where the log could not be read.</summary>
internal sealed record AttackBucket(DateTimeOffset Start, DateTimeOffset End, int UnknownAccount, int Other, bool Covered)
{
    internal int Total => UnknownAccount + Other;
}

internal sealed record AttackSource(string Address, int Attempts, DateTimeOffset First, DateTimeOffset Last,
    int Accounts, string TopAccounts, double UnknownShare, string LogonTypes, string Network, int Neighbors)
{
    internal bool Matches(string query) => query.Length == 0 ||
        Address.Contains(query, StringComparison.OrdinalIgnoreCase) ||
        TopAccounts.Contains(query, StringComparison.OrdinalIgnoreCase) ||
        Network.StartsWith(query, StringComparison.OrdinalIgnoreCase);
}

internal sealed record AttackView(int Attempts, int Sources, int WithoutAddress, double UnknownShare, int LastHour,
    string TopAccount, IReadOnlyList<AttackBucket> Buckets, IReadOnlyList<AttackSource> Rows, int MatchingRows,
    DateTimeOffset? CoveredFrom);

internal sealed record AttackDetail(AttackSource Source, IReadOnlyList<(string Account, int Count)> Accounts,
    IReadOnlyList<AttackBucket> Timeline, IReadOnlyList<AuthFailure> Recent, IReadOnlyList<(string Address, int Attempts)> Neighbors);

/// <summary>
/// Turns failed logons into what the attacks view shows: totals, a timeline, one row per source and
/// the detail of one source.
/// </summary>
/// <remarks>
/// <para>
/// The same attempt can be recorded twice. With NLA, Windows writes 4625 without a client address and
/// Remote Desktop writes event 140 with it; without NLA both may carry the address. Within
/// <see cref="SameAttempt"/> the two are counted once, and the one with the address is kept.
/// </para>
/// <para>
/// Memory is bounded: past <see cref="Capacity"/> records the oldest are dropped, and the coverage
/// moves forward with them so the timeline never shows a dropped interval as a quiet one.
/// </para>
/// </remarks>
internal sealed class AttackBoard
{
    internal const int Capacity = 100_000;
    internal static readonly TimeSpan SameAttempt = TimeSpan.FromSeconds(2);
    private readonly List<AuthFailure> failures = [];
    private DateTimeOffset? coveredFrom;

    internal int Count => failures.Count;

    internal DateTimeOffset? CoveredFrom => coveredFrom;

    /// <summary>Replaces the contents with a fresh read. Nothing before <paramref name="coveredFrom"/> is known.</summary>
    internal void Reset(IEnumerable<AuthFailure> read, DateTimeOffset? coveredFrom)
    {
        failures.Clear();
        this.coveredFrom = coveredFrom;
        foreach (var failure in read.OrderBy(f => f.Timestamp)) Add(failure);
    }

    internal void Add(AuthFailure failure)
    {
        var index = InsertionPoint(failure.Timestamp);
        // One record from the other channel settles it, one to one, so a burst is never collapsed.
        var partner = FindPartner(failure, index);
        if (partner >= 0)
        {
            if (!KeepIncoming(failure, failures[partner])) return;
            failures.RemoveAt(partner);
            if (partner < index) index--;
        }
        failures.Insert(index, failure);
        if (failures.Count > Capacity)
        {
            failures.RemoveRange(0, failures.Count - Capacity);
            var oldest = failures[0].Timestamp;
            if (coveredFrom is null || coveredFrom < oldest) coveredFrom = oldest;
        }
    }

    private int FindPartner(AuthFailure incoming, int index)
    {
        for (var i = index - 1; i >= 0 && incoming.Timestamp - failures[i].Timestamp <= SameAttempt; i--)
            if (IsSameAttempt(failures[i], incoming)) return i;
        for (var i = index; i < failures.Count && failures[i].Timestamp - incoming.Timestamp <= SameAttempt; i++)
            if (IsSameAttempt(failures[i], incoming)) return i;
        return -1;
    }

    private static bool IsSameAttempt(AuthFailure a, AuthFailure b)
    {
        if (a.Channel == b.Channel) return false;
        var rdp = a.Channel == "rdpcorets-140" ? a : b;
        var security = ReferenceEquals(rdp, a) ? b : a;
        // NLA: 4625 type 3 without an address, 140 with it. Otherwise both name the same address.
        return security.Address is null ? security.LogonType == 3 : security.Address.Equals(rdp.Address);
    }

    /// <summary>
    /// Of a pair, the record with the address survives; when both carry it, the 4625 does, because it
    /// also names the account.
    /// </summary>
    private static bool KeepIncoming(AuthFailure incoming, AuthFailure partner)
    {
        var incomingIsSecurity = incoming.Channel == "security-4625";
        var security = incomingIsSecurity ? incoming : partner;
        return incomingIsSecurity ? security.Address is not null : security.Address is null;
    }

    private int InsertionPoint(DateTimeOffset time)
    {
        int low = 0, high = failures.Count;
        while (low < high)
        {
            var mid = (low + high) / 2;
            if (failures[mid].Timestamp <= time) low = mid + 1; else high = mid;
        }
        return low;
    }

    internal static (int Count, TimeSpan Size) Layout(AttackRange range) => range switch
    {
        AttackRange.Hour => (60, TimeSpan.FromMinutes(1)),
        AttackRange.SixHours => (72, TimeSpan.FromMinutes(5)),
        _ => (96, TimeSpan.FromMinutes(15))
    };

    internal AttackView View(DateTimeOffset now, AttackRange range, string query, int maxRows = 500)
    {
        var (count, size) = Layout(range);
        var start = now - size * count;
        var inRange = Between(start, now);
        var sourced = inRange.Where(f => f.Address is not null).ToArray();
        var networks = NetworkCounts(sourced);
        var rows = sourced.GroupBy(f => f.Address!.ToString())
            .Select(g => Source(g.Key, g.ToArray(), networks))
            .OrderByDescending(s => s.Attempts).ThenByDescending(s => s.Last).ToArray();
        var matching = rows.Where(r => r.Matches(query)).ToArray();
        var unknown = inRange.Count(f => f.Reason == "unknown-account");
        var top = inRange.Where(f => f.Account.Length > 0).GroupBy(f => f.Account, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(g => g.Count()).FirstOrDefault()?.Key ?? "";
        return new(inRange.Count, rows.Length, inRange.Count - sourced.Length,
            inRange.Count == 0 ? 0 : (double)unknown / inRange.Count, Between(now - TimeSpan.FromHours(1), now).Count, top,
            Buckets(inRange, start, size, count), matching.Take(maxRows).ToArray(), matching.Length, coveredFrom);
    }

    internal AttackDetail? Detail(string address, DateTimeOffset now, AttackRange range)
    {
        var (count, size) = Layout(range);
        var start = now - size * count;
        var inRange = Between(start, now);
        var mine = inRange.Where(f => f.Address?.ToString() == address).ToArray();
        if (mine.Length == 0) return null;
        var sourced = inRange.Where(f => f.Address is not null).ToArray();
        var source = Source(address, mine, NetworkCounts(sourced));
        var accounts = mine.Where(f => f.Account.Length > 0).GroupBy(f => f.Account, StringComparer.OrdinalIgnoreCase)
            .Select(g => (g.Key, g.Count())).OrderByDescending(a => a.Item2).Take(15).ToArray();
        var network = Network(mine[0].Address!);
        var neighbors = sourced.Where(f => f.Address!.ToString() != address && Network(f.Address!) == network)
            .GroupBy(f => f.Address!.ToString()).Select(g => (g.Key, g.Count()))
            .OrderByDescending(n => n.Item2).Take(20).ToArray();
        var recent = mine.OrderByDescending(f => f.Timestamp).Take(100).ToArray();
        return new(source, accounts, Buckets(mine, start, size, count), recent, neighbors);
    }

    private List<AuthFailure> Between(DateTimeOffset start, DateTimeOffset end)
    {
        var from = InsertionPoint(start - TimeSpan.FromTicks(1));
        var result = new List<AuthFailure>();
        for (var i = from; i < failures.Count && failures[i].Timestamp <= end; i++)
            if (failures[i].Timestamp >= start) result.Add(failures[i]);
        return result;
    }

    private IReadOnlyList<AttackBucket> Buckets(IReadOnlyList<AuthFailure> events, DateTimeOffset start, TimeSpan size, int count)
    {
        var unknown = new int[count];
        var other = new int[count];
        foreach (var failure in events)
        {
            var index = (int)((failure.Timestamp - start).Ticks / size.Ticks);
            if (index < 0 || index >= count) continue;
            if (failure.Reason == "unknown-account") unknown[index]++; else other[index]++;
        }
        return Enumerable.Range(0, count).Select(i =>
        {
            var bucketStart = start + size * i;
            return new AttackBucket(bucketStart, bucketStart + size, unknown[i], other[i],
                coveredFrom is null || bucketStart >= coveredFrom);
        }).ToArray();
    }

    private static AttackSource Source(string address, IReadOnlyList<AuthFailure> events, Dictionary<string, int> networks)
    {
        var accounts = events.Where(f => f.Account.Length > 0).GroupBy(f => f.Account, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(g => g.Count()).Select(g => g.Key).ToArray();
        var types = events.Where(f => f.LogonType is not null).Select(f => f.LogonType!.Value).Distinct().Order()
            .Select(t => t.ToString(CultureInfo.InvariantCulture));
        var network = Network(events[0].Address!);
        return new(address, events.Count, events.Min(f => f.Timestamp), events.Max(f => f.Timestamp), accounts.Length,
            string.Join(", ", accounts.Take(3)), (double)events.Count(f => f.Reason == "unknown-account") / events.Count,
            string.Join(", ", types), network, Math.Max(0, networks.GetValueOrDefault(network) - 1));
    }

    private static Dictionary<string, int> NetworkCounts(IEnumerable<AuthFailure> sourced) =>
        sourced.Select(f => f.Address!).Distinct().GroupBy(Network).ToDictionary(g => g.Key, g => g.Count());

    /// <summary>The /24 of an IPv4 address or the /64 of an IPv6 one, as text.</summary>
    internal static string Network(IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            bytes[3] = 0;
            return new IPAddress(bytes) + "/24";
        }
        for (var i = 8; i < bytes.Length; i++) bytes[i] = 0;
        return new IPAddress(bytes) + "/64";
    }
}
