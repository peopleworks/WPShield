using System.Text;
using WPShield.NetworkFilter.Native;

namespace WPShield.NetworkFilter;

/// <summary>
/// Writes the WinDivert filter strings. Every address in them comes from a parsed
/// <see cref="IpRange"/>, never from text, so nothing a rule or an operator typed reaches the filter
/// language verbatim.
/// </summary>
public static class DivertFilterBuilder
{
    /// <summary>
    /// The observer's filter: new inbound TCP connection attempts and nothing else. Counting SYNs
    /// rather than packets is what makes a rate threshold mean "connections per minute"; counting every
    /// packet is how one WordPress page load crossed the 2026-10-20 threshold.
    /// </summary>
    public const string ObserverFilter = "inbound and !loopback and tcp.Syn and !tcp.Ack";

    /// <summary>
    /// The object budget per DROP filter, below WinDivert's 256 (<c>WINDIVERT_FILTER_MAXLEN</c>) so a
    /// miscount here is not a failure there.
    /// </summary>
    public const int ObjectBudget = 200;

    private const string Prefix = "inbound and !loopback and (";
    private const int PrefixObjects = 2;

    static DivertFilterBuilder()
    {
        if (ObjectBudget >= WinDivertNative.FilterMaxObjects)
        {
            throw new InvalidOperationException("The DROP filter budget must stay below WINDIVERT_FILTER_MAXLEN.");
        }
    }

    /// <summary>
    /// Builds the DROP filters for <paramref name="blocked"/>, skipping anything that overlaps the
    /// allow-list. An empty plan means no DROP handle at all.
    /// </summary>
    public static DropFilterPlan BuildDropFilters(IEnumerable<IpRange> blocked, IReadOnlyList<IpRange> allowList)
    {
        ArgumentNullException.ThrowIfNull(blocked);
        ArgumentNullException.ThrowIfNull(allowList);

        var filters = new List<string>();
        var excluded = new List<IpRange>();
        var current = new StringBuilder();
        var objects = 0;
        var terms = 0;

        foreach (var range in blocked.Distinct().OrderBy(range => range, Comparer<IpRange>.Create(IpRange.Compare)))
        {
            if (allowList.Any(allowed => allowed.Overlaps(range)))
            {
                excluded.Add(range);
                continue;
            }

            var cost = range.IsSingleAddress ? 1 : 2;
            if (terms > 0 && PrefixObjects + objects + cost > ObjectBudget)
            {
                filters.Add(Close(current));
                current.Clear();
                objects = 0;
                terms = 0;
            }

            current.Append(terms == 0 ? Prefix : " or ");
            current.Append(Term(range));
            objects += cost;
            terms++;
        }

        if (terms > 0)
        {
            filters.Add(Close(current));
        }

        return new DropFilterPlan(filters, excluded);
    }

    private static string Term(IpRange range)
    {
        var field = range.IsIpv6 ? "ipv6.SrcAddr" : "ip.SrcAddr";
        return range.IsSingleAddress
            ? $"{field} == {range.First}"
            : $"({field} >= {range.First} and {field} <= {range.Last})";
    }

    private static string Close(StringBuilder filter) => filter.Append(')').ToString();
}

/// <summary>The DROP filters for one block set, and the entries left out because they are allow-listed.</summary>
public sealed record DropFilterPlan(IReadOnlyList<string> Filters, IReadOnlyList<IpRange> Excluded)
{
    public static DropFilterPlan Empty { get; } = new([], []);
}
