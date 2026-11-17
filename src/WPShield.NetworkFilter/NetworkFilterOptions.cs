using WPShield.NetworkFilter.Rules;

namespace WPShield.NetworkFilter;

public enum NetworkFilterMode
{
    /// <summary>The default. Observes and reports who would be blocked; never opens a DROP handle.</summary>
    Monitor,

    /// <summary>Drops packets from addresses on the block set. Requires an allow-list.</summary>
    Block,
}

/// <summary>Configuration for <see cref="NetworkFilterService"/>. Every limit has a ceiling.</summary>
public sealed record NetworkFilterOptions
{
    public NetworkFilterMode Mode { get; init; } = NetworkFilterMode.Monitor;

    /// <summary>Addresses that can never be blocked, whatever asks.</summary>
    public IReadOnlyList<IpRange> AllowList { get; init; } = [];

    /// <summary>Operator-named blocks. They last for the life of the process.</summary>
    public IReadOnlyList<IpRange> Blocks { get; init; } = [];

    /// <summary>How long a block added by a rule lasts. A repeat finding extends it.</summary>
    public TimeSpan DynamicBlockLifetime { get; init; } = TimeSpan.FromMinutes(60);

    public int MaximumBlocks { get; init; } = BlockSet.DefaultCapacity;

    /// <summary>
    /// Whether <c>WP-NET-002</c> and <c>WP-NET-003</c> may add blocks. Off by default: their evidence
    /// is a SYN, whose source address anyone can forge (ADR 0006, section 5).
    /// </summary>
    public bool SynRulesMayBlock { get; init; }

    public int MaxConnectionsPerMinute { get; init; } = RateLimitRule.DefaultThreshold;

    public int MaxDistinctPortsPerMinute { get; init; } = PortScanRule.DefaultThreshold;

    public int MaximumTrackedSources { get; init; } = RateLimitRule.DefaultMaximumSources;

    /// <summary>DROP handles see packets first, so a blocked address never reaches user mode at all.</summary>
    public short EnforcerPriority { get; init; } = 1000;

    public short ObserverPriority { get; init; }

    /// <summary>How often expired blocks are removed and the DROP filters rebuilt if the set changed.</summary>
    public TimeSpan MaintenanceInterval { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>Returns a reason when the options are out of bounds, or null.</summary>
    public string? Validate()
    {
        if (MaximumBlocks is < 1 or > BlockSet.MaximumCapacity)
        {
            return $"--max-blocks must be between 1 and {BlockSet.MaximumCapacity}.";
        }

        if (Blocks.Count > MaximumBlocks)
        {
            return $"{Blocks.Count} operator blocks exceed --max-blocks ({MaximumBlocks}).";
        }

        if (DynamicBlockLifetime < TimeSpan.FromMinutes(1) || DynamicBlockLifetime > TimeSpan.FromDays(7))
        {
            return "--block-ttl-minutes must be between 1 and 10080 (seven days).";
        }

        if (MaxConnectionsPerMinute is < 1 or > 100_000 || MaxDistinctPortsPerMinute is < 1 or > 65_535)
        {
            return "The rule thresholds must be positive and below 100,000 connections and 65,535 ports.";
        }

        if (MaximumTrackedSources is < 1 or > 1_000_000)
        {
            return "The tracked-source limit must be between 1 and 1,000,000.";
        }

        var overlapping = Blocks.Where(block => AllowList.Any(allowed => allowed.Overlaps(block))).ToList();
        if (overlapping.Count > 0)
        {
            return "These --block entries overlap the allow-list and would never be enforced: " +
                string.Join(", ", overlapping) + ".";
        }

        return null;
    }
}
