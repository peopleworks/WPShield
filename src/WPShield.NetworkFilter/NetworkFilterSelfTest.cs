using System.Net;

namespace WPShield.NetworkFilter;

public sealed record SelfTestReport(bool Passed, string Detail);

internal static class NetworkFilterSelfTest
{
    private static readonly IPAddress[] DocumentationNetworks =
    [
        IPAddress.Parse("192.0.2.0"),
        IPAddress.Parse("198.51.100.0"),
        IPAddress.Parse("203.0.113.0"),
    ];

    internal static SelfTestReport Run(IWfpSession session, IReadOnlyList<IpRange> allowList)
    {
        // Add a synthetic allow-list entry and exercise both the admission and filter-builder guards.
        var excluded = IpRange.Single(IPAddress.Parse("192.0.2.255"));
        var testAllowList = allowList.Append(excluded).ToArray();
        var probe = FindProbe(testAllowList);
        if (probe is null)
        {
            return new SelfTestReport(false, "No RFC 5737 probe address is outside the allow-list.");
        }

        var blockSet = new BlockSet(testAllowList);
        var filters = WfpFilterBuilder.SelectBlocks([probe, excluded], testAllowList);
        if (blockSet.TryAdd(excluded, "self-test", null) != BlockAddOutcome.RefusedAllowListed ||
            filters.Length != 1 || !filters[0].Equals(probe))
        {
            return new SelfTestReport(false, "The allow-list exclusion check failed.");
        }

        var id = session.Add(filters[0]);
        bool found;
        try
        {
            found = session.Contains(id, probe);
        }
        finally
        {
            session.Delete(id);
        }

        return found
            ? new SelfTestReport(true, "Opened a dynamic WFP session and added, enumerated and deleted a block filter. Both allow-list guards passed.")
            : new SelfTestReport(false, "WFP enumeration did not return the expected probe filter.");
    }

    private static IpRange? FindProbe(IReadOnlyList<IpRange> allowList)
    {
        foreach (var network in DocumentationNetworks)
        {
            var bytes = network.GetAddressBytes();
            for (var host = 1; host < 255; host++)
            {
                bytes[3] = (byte)host;
                var range = IpRange.Single(new IPAddress(bytes));
                if (WfpFilterBuilder.SelectBlocks([range], allowList).Length == 1)
                {
                    return range;
                }
            }
        }

        return null;
    }
}
