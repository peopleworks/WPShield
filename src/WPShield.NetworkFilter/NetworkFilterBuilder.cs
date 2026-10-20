using System.Collections.Generic;
using WPShield.Abstractions;
using WPShield.NetworkFilter.Rules;

namespace WPShield.NetworkFilter;

/// <summary>
/// Convenience builder that assembles a <see cref="NetworkFilterEngine"/> with the default
/// rule set (rate limit, block list, port scan).
/// </summary>
public static class NetworkFilterBuilder
{
    public static NetworkFilterEngine Build(NetworkFilterConfiguration? configuration = null)
    {
        configuration ??= new NetworkFilterConfiguration();

        IEnumerable<INetworkInspectionRule> rules = new List<INetworkInspectionRule>
        {
            new BlockListRule(configuration.BlockList),
            new RateLimitRule(configuration.MaxConnectionsPerMinute),
            new PortScanRule(configuration.MaxDistinctPortsPerMinute)
        };

        return new NetworkFilterEngine(
            rules,
            configuration.Filter,
            configuration.MaxInspectionTime);
    }
}
