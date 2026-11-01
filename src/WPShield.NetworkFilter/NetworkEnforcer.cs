namespace WPShield.NetworkFilter;

/// <summary>
/// Owns the DROP handles. Exists only in Block mode: Monitor never constructs one, so Monitor cannot
/// drop a packet however it is misconfigured (ADR 0006, section 4).
/// </summary>
/// <remarks>
/// <see cref="Apply"/> is make-before-break. Every new filter is compiled first, then every new handle
/// is opened, and only then are the old ones closed. If anything fails along the way, whatever was
/// newly opened is closed and the previous handles stay exactly as they were: a failed update never
/// leaves the host with fewer blocks than before, nor with a half-applied set.
/// </remarks>
public sealed class NetworkEnforcer : IDisposable
{
    private readonly IDivertDriver _driver;
    private readonly short _priority;
    private readonly object _gate = new();
    private List<(string Filter, IDivertHandle Handle)> _active = [];
    private bool _disposed;

    public NetworkEnforcer(IDivertDriver driver, short priority)
    {
        ArgumentNullException.ThrowIfNull(driver);
        _driver = driver;
        _priority = priority;
    }

    public int ActiveHandleCount
    {
        get
        {
            lock (_gate)
            {
                return _active.Count;
            }
        }
    }

    public EnforcementResult Apply(DropFilterPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);

        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            if (plan.Filters.SequenceEqual(_active.Select(entry => entry.Filter), StringComparer.Ordinal))
            {
                return new EnforcementResult(EnforcementStatus.Unchanged, _active.Count, null);
            }

            foreach (var filter in plan.Filters)
            {
                var compiled = _driver.Compile(filter);
                if (!compiled.Succeeded)
                {
                    return new EnforcementResult(
                        EnforcementStatus.Failed,
                        _active.Count,
                        $"WinDivert rejected a generated filter ({compiled.Error} at position {compiled.ErrorPosition}). The previous blocks stay in force.");
                }
            }

            var opened = new List<(string Filter, IDivertHandle Handle)>(plan.Filters.Count);
            try
            {
                foreach (var filter in plan.Filters)
                {
                    opened.Add((filter, _driver.Open(filter, DivertHandleKind.Drop, _priority)));
                }
            }
            catch (DivertDriverException exception)
            {
                foreach (var entry in opened)
                {
                    entry.Handle.Dispose();
                }

                return new EnforcementResult(
                    EnforcementStatus.Failed,
                    _active.Count,
                    exception.Message + " The previous blocks stay in force.");
            }

            var previous = _active;
            _active = opened;
            foreach (var entry in previous)
            {
                entry.Handle.Dispose();
            }

            return new EnforcementResult(EnforcementStatus.Applied, _active.Count, null);
        }
    }

    /// <summary>Closes every DROP handle, which lifts every block at once.</summary>
    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            foreach (var entry in _active)
            {
                entry.Handle.Dispose();
            }

            _active = [];
            _disposed = true;
        }
    }
}

public sealed record EnforcementResult(EnforcementStatus Status, int HandleCount, string? Error);

public enum EnforcementStatus
{
    Applied,
    Unchanged,
    Failed,
}
