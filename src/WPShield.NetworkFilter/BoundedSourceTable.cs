namespace WPShield.NetworkFilter;

/// <summary>
/// Per-source state with a hard ceiling, evicting the least recently seen source.
/// </summary>
internal sealed class BoundedSourceTable<TState>
    where TState : class
{
    private readonly int _capacity;
    private readonly Dictionary<string, LinkedListNode<(string Key, TState State)>> _index;
    private readonly LinkedList<(string Key, TState State)> _recency = new();

    public BoundedSourceTable(int capacity)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(capacity, 1);
        _capacity = capacity;
        _index = new Dictionary<string, LinkedListNode<(string, TState)>>(StringComparer.Ordinal);
    }

    public int Count => _index.Count;

    public TState GetOrAdd(string key, Func<TState> create)
    {
        if (_index.TryGetValue(key, out var node))
        {
            _recency.Remove(node);
            _recency.AddFirst(node);
            return node.Value.State;
        }

        if (_index.Count >= _capacity && _recency.Last is { } oldest)
        {
            _index.Remove(oldest.Value.Key);
            _recency.RemoveLast();
        }

        var created = _recency.AddFirst((key, create()));
        _index[key] = created;
        return created.Value.State;
    }
}
