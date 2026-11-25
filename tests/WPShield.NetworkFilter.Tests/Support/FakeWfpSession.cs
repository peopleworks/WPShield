namespace WPShield.NetworkFilter.Tests.Support;

internal sealed class FakeWfpSession : IWfpSession
{
    private ulong _nextId;
    internal Dictionary<ulong, IpRange> Filters { get; private set; } = [];
    internal List<IpRange> Added { get; } = [];
    internal List<ulong> Deleted { get; } = [];
    internal bool Disposed { get; private set; }
    internal bool EnumerationSucceeds { get; init; } = true;
    internal bool RejectDeletes { get; set; }
    internal Func<IpRange, bool> RejectAdd { get; set; } = _ => false;

    public ulong Add(IpRange range)
    {
        if (RejectAdd(range))
        {
            throw new WfpException("Add filter was denied.");
        }

        Added.Add(range);
        Filters.Add(++_nextId, range);
        return _nextId;
    }

    public bool Contains(ulong id, IpRange range) =>
        EnumerationSucceeds && Filters.TryGetValue(id, out var actual) && actual.Equals(range);

    public void Delete(ulong id)
    {
        if (RejectDeletes)
        {
            throw new WfpException("Delete filter was denied.");
        }

        Deleted.Add(id);
        _ = Filters.Remove(id);
    }

    public void Update(Action update)
    {
        var previous = new Dictionary<ulong, IpRange>(Filters);
        try
        {
            update();
        }
        catch
        {
            Filters = previous;
            throw;
        }
    }

    public void Dispose()
    {
        Disposed = true;
        Filters.Clear();
    }
}
