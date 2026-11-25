namespace WPShield.Evidence.Decisions;

/// <summary>
/// A map that holds at most <see cref="MaxEntries"/> entries and <see cref="MaxWeight"/> items inside
/// them, and evicts the least recently seen entry to stay within both. Forgetting the oldest state only
/// ever makes the engine slower to decide, which is the safe direction for a bound to fail in.
/// </summary>
/// <remarks>
/// The weight bound exists because the entry bound alone does not bound memory: 100,000 addresses each
/// holding a full window of timestamps is a different amount of memory from 100,000 addresses seen once.
/// </remarks>
internal sealed class BoundedMap<TKey, TValue> where TKey : notnull
{
    private readonly Dictionary<TKey, LinkedListNode<Entry>> index;
    private readonly LinkedList<Entry> order = new();

    internal BoundedMap(int maxEntries, long maxWeight, IEqualityComparer<TKey>? comparer = null)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maxEntries, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxWeight, 1);
        MaxEntries = maxEntries;
        MaxWeight = maxWeight;
        index = new Dictionary<TKey, LinkedListNode<Entry>>(comparer);
    }

    internal int MaxEntries { get; }

    internal long MaxWeight { get; }

    internal int Count => index.Count;

    internal long Weight { get; private set; }

    /// <summary>Entries dropped to stay within the bounds.</summary>
    internal long Evicted { get; private set; }

    internal IEnumerable<(TKey Key, TValue Value)> Items => order.Select(e => (e.Key, e.Value));

    internal bool TryGet(TKey key, out TValue value)
    {
        if (index.TryGetValue(key, out var node))
        {
            value = node.Value.Value;
            return true;
        }
        value = default!;
        return false;
    }

    /// <summary>The entry for <paramref name="key"/>, created when absent, marked as the most recently seen.</summary>
    internal TValue Touch(TKey key, Func<TValue> create)
    {
        if (index.TryGetValue(key, out var node))
        {
            order.Remove(node);
            order.AddLast(node);
            return node.Value.Value;
        }
        node = order.AddLast(new Entry(key, create()));
        index[key] = node;
        Shrink(node);
        return node.Value.Value;
    }

    /// <summary>Records how many items <paramref name="key"/> now holds, and evicts others if that is too many.</summary>
    internal void Reweigh(TKey key, int weight)
    {
        if (!index.TryGetValue(key, out var node)) return;
        Weight += weight - node.Value.Weight;
        node.Value.Weight = weight;
        Shrink(node);
    }

    internal bool Remove(TKey key)
    {
        if (!index.Remove(key, out var node)) return false;
        Weight -= node.Value.Weight;
        order.Remove(node);
        return true;
    }

    private void Shrink(LinkedListNode<Entry> keep)
    {
        while ((index.Count > MaxEntries || Weight > MaxWeight) && order.First is { } oldest && oldest != keep)
        {
            Remove(oldest.Value.Key);
            Evicted++;
        }
    }

    private sealed class Entry(TKey key, TValue value)
    {
        internal TKey Key { get; } = key;
        internal TValue Value { get; } = value;
        internal int Weight { get; set; }
    }
}
