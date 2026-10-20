namespace WPShield.Gateway;

/// <summary>
/// Bounds how many <c>multipart/form-data</b> inspections may hold a body buffer at once.
/// </summary>
/// <remarks>
/// <para>
/// Before M3 nothing bounded how many multipart bodies could be buffered concurrently. A burst of
/// simultaneous uploads — or an attacker opening many slow connections — could pin roughly
/// <see cref="GatewayOptions.MaximumRequestBytes"/> per inspection for up to
/// <see cref="MultipartInspectionOptions.ReadTimeoutSeconds"/> each, which on a shared host is
/// memory exhaustion by request volume. This limiter is the M3 control that closes that gap.
/// </para>
/// <para>
/// <b>Try, never block.</b> <see cref="TryEnter"/> returns immediately with <see langword="true"/>
/// when a slot is free and <see langword="false"/> when every slot is taken. The caller decides
/// what <see langword="false"/> means: <see cref="ProtectionMode.Monitor"/> forwards without
/// inspecting and logs a warning; <see cref="ProtectionMode.Block"/> refuses with HTTP 429. Blocking
/// the request path on a semaphore wait turns a defence into a way to hold connections open, which
/// is exactly what this limit exists to prevent.
/// </para>
/// <para>
/// A disabled site never reaches this limiter, because it never buffers.
/// </para>
/// </remarks>
public sealed class ConcurrentInspectionLimiter : IDisposable
{
    private readonly SemaphoreSlim _semaphore;
    private int _entered;

    /// <summary>
    /// Creates a limiter with the given maximum number of concurrent inspections.
    /// </summary>
    public ConcurrentInspectionLimiter(int maxConcurrentInspections)
    {
        if (maxConcurrentInspections < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(maxConcurrentInspections), maxConcurrentInspections,
                "Must be at least 1.");
        }

        _semaphore = new SemaphoreSlim(maxConcurrentInspections, maxConcurrentInspections);
        MaxConcurrentInspections = maxConcurrentInspections;
    }

    /// <summary>
    /// The maximum number of inspections that may hold a buffer at once.
    /// </summary>
    public int MaxConcurrentInspections { get; }

    /// <summary>
    /// How many inspections currently hold a buffer.
    /// </summary>
    public int CurrentCount => _entered;

    /// <summary>
    /// How many slots remain.
    /// </summary>
    public int AvailableCount => MaxConcurrentInspections - CurrentCount;

    /// <summary>
    /// Attempts to enter the limiter. Returns <see langword="true"/> if a slot was taken,
    /// <see langword="false"/> if every slot is taken. Never blocks.
    /// </summary>
    public bool TryEnter()
    {
        if (!_semaphore.Wait(0))
        {
            return false;
        }

        Interlocked.Increment(ref _entered);
        return true;
    }

    /// <summary>
    /// Releases one slot. Call this exactly once for every successful <see cref="TryEnter"/>,
    /// in a <c>finally</c> block so a cancelled or failed read cannot leak a slot.
    /// </summary>
    public void Release()
    {
        Interlocked.Decrement(ref _entered);
        _semaphore.Release();
    }

    /// <summary>
    /// Disposes the underlying semaphore. Must not be called while inspections are in progress.
    /// </summary>
    public void Dispose()
    {
        _semaphore.Dispose();
        GC.SuppressFinalize(this);
    }
}
