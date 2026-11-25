using WPShield.Evidence;

namespace WPShield.SecurityMonitor;

/// <summary>
/// Where host facts come from (ADR 0013). The collector calls it on its cadences, on a background thread,
/// and writes what it returns; <c>wpshield host --live</c> calls it directly and writes nothing.
/// </summary>
/// <remarks>
/// The CLI supplies the implementation, the way it supplies the IIS site list to the web sensor: reading IIS,
/// the firewall, the service control manager and the task scheduler is the CLI's, not this library's. Every
/// method reads and never changes anything, honours the cancellation token as its time budget, bounds what
/// it returns, and reports what it could not read as a status with a reason and a remedy - never as empty.
/// </remarks>
public interface IHostFactSource
{
    /// <param name="storePath">The evidence store, whose size is part of the health fact; may be <see langword="null"/>.</param>
    HostFactReading ReadHealth(string? storePath, CancellationToken cancellationToken);

    /// <summary>System log records 41, 6008 and 1001 written since <paramref name="since"/>.</summary>
    HostRestartReading ReadRestarts(DateTimeOffset since, CancellationToken cancellationToken);

    HostFactReading ReadSites(CancellationToken cancellationToken);

    HostFactReading ReadPosture(CancellationToken cancellationToken);

    HostFactReading ReadPorts(CancellationToken cancellationToken);

    /// <summary>Current sessions, and the RDP logons and reconnections since <paramref name="since"/>.</summary>
    HostFactReading ReadSessions(DateTimeOffset since, CancellationToken cancellationToken);

    /// <param name="kind"><c>accounts</c>, <c>services</c> or <c>tasks</c>.</param>
    HostInventoryReading ReadInventory(string kind, CancellationToken cancellationToken);
}

/// <summary>
/// An inventory reading, and - for accounts only - the local accounts' full names, held in memory for the
/// full-name indicator and never written, logged or shown. <see cref="ToString"/> leaves them out.
/// </summary>
public sealed class HostInventoryReading(HostFactReading reading, IReadOnlyList<string>? fullNames = null)
{
    public HostFactReading Reading { get; } = reading ?? throw new ArgumentNullException(nameof(reading));

    private readonly IReadOnlyList<string>? fullNames = fullNames;

    /// <summary>
    /// How many local full names appear among <paramref name="attemptedNames"/>, or <see langword="null"/> when the
    /// full names were not read. The names themselves never leave this object.
    /// </summary>
    public int? CountFullNamesAttempted(IEnumerable<string> attemptedNames) =>
        fullNames is null ? null : FullNameIndicator.Matches(fullNames, attemptedNames);

    /// <summary>The reading with the full-name indicator set on an accounts payload; anything else unchanged.</summary>
    public HostFactReading WithFullNameIndicator(IEnumerable<string>? attemptedNames)
    {
        if (Reading.Kind != HostFacts.Accounts || Reading.Value<HostAccounts>() is not { } accounts) return Reading;
        var matches = attemptedNames is null ? null : CountFullNamesAttempted(attemptedNames);
        return HostFactReading.Of(Reading.Fact, Reading.Kind, Reading.TakenAt,
            accounts with { FullNameTargeted = matches is null ? null : matches > 0, FullNameMatches = matches },
            Reading.Status, Reading.Reason, Reading.Remedy);
    }

    public override string ToString() => $"{Reading.Fact}/{Reading.Kind} {Reading.Status}";
}
