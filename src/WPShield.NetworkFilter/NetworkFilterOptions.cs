namespace WPShield.NetworkFilter;

public enum NetworkFilterMode
{
    Monitor,
    Block,
}

/// <summary>Configuration for <see cref="NetworkFilterService"/>.</summary>
public sealed record NetworkFilterOptions
{
    public const int MaximumAllowEntries = 1_000;

    public NetworkFilterMode Mode { get; init; } = NetworkFilterMode.Monitor;

    public IReadOnlyList<IpRange> AllowList { get; init; } = [];

    public IReadOnlyList<IpRange> Blocks { get; init; } = [];

    public TimeSpan DynamicBlockLifetime { get; init; } = TimeSpan.FromMinutes(60);

    public int MaximumBlocks { get; init; } = BlockSet.DefaultCapacity;

    public string? Validate()
    {
        if (!Enum.IsDefined(Mode))
        {
            return "--mode must be Monitor or Block.";
        }

        if (AllowList.Count > MaximumAllowEntries)
        {
            return $"--allow supports at most {MaximumAllowEntries} entries.";
        }

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

        foreach (var block in Blocks)
        {
            if (!IpRange.TryParseBlock(block.ToString(), out _, out var error))
            {
                return error;
            }

            if (AllowList.Any(allowed => allowed.Overlaps(block)))
            {
                return $"The --block entry {block} overlaps the allow-list.";
            }
        }

        return null;
    }
}
