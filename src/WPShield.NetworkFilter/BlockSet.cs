using System.Net;

namespace WPShield.NetworkFilter;

/// <summary>
/// The addresses WPShield is currently dropping, and the only place a block can be created.
/// </summary>
/// <remarks>
/// <para>
/// The allow-list is applied here, at insertion: an entry that contains an allow-listed address is
/// refused, whatever asked for it. <see cref="DivertFilterBuilder"/> excludes allow-listed addresses
/// again when it writes the filters, so one defect is not enough to block the operator (ADR 0006,
/// section 3).
/// </para>
/// <para>
/// Operator-named entries never expire and are never evicted. Dynamic entries carry a TTL that a
/// repeat finding extends. When the set is full a new dynamic entry is refused, never made room for.
/// Nothing here is persisted: the set lives and dies with the process.
/// </para>
/// </remarks>
public sealed class BlockSet
{
    public const int DefaultCapacity = 1_000;
    public const int MaximumCapacity = 10_000;

    private readonly object _gate = new();
    private readonly Dictionary<IpRange, BlockEntry> _entries = [];
    private readonly IReadOnlyList<IpRange> _allowList;
    private readonly TimeProvider _time;
    private long _version;

    public BlockSet(IReadOnlyList<IpRange> allowList, int capacity = DefaultCapacity, TimeProvider? time = null)
    {
        ArgumentNullException.ThrowIfNull(allowList);
        ArgumentOutOfRangeException.ThrowIfLessThan(capacity, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(capacity, MaximumCapacity);
        _allowList = [.. allowList];
        Capacity = capacity;
        _time = time ?? TimeProvider.System;
    }

    public int Capacity { get; }

    /// <summary>Changes whenever the set of blocked ranges changes; a TTL extension does not count.</summary>
    public long Version => Interlocked.Read(ref _version);

    public int Count
    {
        get
        {
            lock (_gate)
            {
                return _entries.Count;
            }
        }
    }

    public IReadOnlyList<IpRange> AllowList => _allowList;

    public bool IsAllowListed(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        return _allowList.Any(entry => entry.Contains(address));
    }

    /// <summary>Whether an entry already blocks <paramref name="address"/>.</summary>
    public bool IsBlocked(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        lock (_gate)
        {
            return _entries.Keys.Any(range => range.Contains(address));
        }
    }

    /// <summary>
    /// Adds a block. <paramref name="lifetime"/> null means for the life of the process, which only an
    /// operator-named block should use.
    /// </summary>
    public BlockAddOutcome TryAdd(IpRange range, string source, TimeSpan? lifetime)
    {
        ArgumentNullException.ThrowIfNull(range);
        ArgumentException.ThrowIfNullOrWhiteSpace(source);
        if (lifetime is { } span && span <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(lifetime), lifetime, "A block lifetime must be positive.");
        }

        if (_allowList.Any(allowed => allowed.Overlaps(range)))
        {
            return BlockAddOutcome.RefusedAllowListed;
        }

        var now = _time.GetUtcNow();
        DateTimeOffset? expiresAt = lifetime is { } ttl ? now + ttl : null;

        lock (_gate)
        {
            if (_entries.TryGetValue(range, out var existing))
            {
                if (existing.ExpiresAt is null || (expiresAt is { } newExpiry && newExpiry <= existing.ExpiresAt))
                {
                    return BlockAddOutcome.AlreadyBlocked;
                }

                _entries[range] = existing with { ExpiresAt = expiresAt };
                return BlockAddOutcome.Extended;
            }

            if (_entries.Values.Any(entry => entry.Range.Covers(range) && entry.ExpiresAt is null))
            {
                return BlockAddOutcome.AlreadyBlocked;
            }

            if (_entries.Count >= Capacity)
            {
                return BlockAddOutcome.RefusedFull;
            }

            _entries[range] = new BlockEntry(range, source, now, expiresAt);
            Interlocked.Increment(ref _version);
            return BlockAddOutcome.Added;
        }
    }

    /// <summary>Removes expired dynamic entries and returns them.</summary>
    public IReadOnlyList<BlockEntry> RemoveExpired()
    {
        var now = _time.GetUtcNow();
        lock (_gate)
        {
            var expired = _entries.Values.Where(entry => entry.ExpiresAt is { } at && at <= now).ToList();
            foreach (var entry in expired)
            {
                _entries.Remove(entry.Range);
            }

            if (expired.Count > 0)
            {
                Interlocked.Increment(ref _version);
            }

            return expired;
        }
    }

    /// <summary>The current entries, ordered by address.</summary>
    public IReadOnlyList<BlockEntry> Snapshot()
    {
        lock (_gate)
        {
            var entries = _entries.Values.ToList();
            entries.Sort((left, right) => IpRange.Compare(left.Range, right.Range));
            return entries;
        }
    }
}

/// <summary>One blocked address or range. <see cref="Source"/> is a rule ID or <c>operator</c>.</summary>
public sealed record BlockEntry(IpRange Range, string Source, DateTimeOffset AddedAt, DateTimeOffset? ExpiresAt);

public enum BlockAddOutcome
{
    Added,
    Extended,
    AlreadyBlocked,
    RefusedAllowListed,
    RefusedFull,
}
