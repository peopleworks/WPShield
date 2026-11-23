using System.Diagnostics.CodeAnalysis;

namespace WPShield.SecurityMonitor;

public sealed record SqlLoginEvidence(int EventId, long RecordId, DateTimeOffset Timestamp, string Outcome);

public sealed record SqlLoginAuditWindow(string Provider, DateTimeOffset WindowEnd, string AuditStatus,
    IReadOnlyList<SqlLoginEvidence> Events)
{
    public string Channel => "Application";
    public DateTimeOffset WindowStart => WindowEnd - RecentEventLog.Lookback;
    public string? UnavailableReason { get; init; }
    public string ObservedOutcome => (Events.Any(e => e.Outcome == "success"), Events.Any(e => e.Outcome == "failure")) switch
    {
        (true, true) => "mixed",
        (true, false) => "success",
        (false, true) => "failure",
        _ => "unknown"
    };
    public string FlowAttribution => "unknown";
}

public static class SqlLoginAuditReader
{
    public static bool IsValidInstance([NotNullWhen(true)] string? name) =>
        name is { Length: >= 1 and <= 16 } && char.IsLetter(name[0]) &&
        name.All(c => char.IsLetterOrDigit(c) || c is '_' or '$');

    public static SqlLoginAuditWindow Read(string instance, DateTimeOffset end)
    {
        var provider = ProviderFor(instance);
        var filter = $"*[System[Provider[@Name='{provider}'] and (EventID=18453 or EventID=18454 or EventID=18455 or EventID=18456) and {RecentEventLog.TimeFilter(end)}]]";
        // The Application event's system fields suffice. Never render its message or read its insertion strings.
        var window = RecentEventLog.Read("Application", filter, record =>
            Project(provider, record.ProviderName, record.Id, record.RecordId, record.TimeCreated));
        return new(provider, end.ToUniversalTime(), window.Status, window.Events) { UnavailableReason = window.UnavailableReason };
    }

    internal static string ProviderFor(string instance)
    {
        if (!IsValidInstance(instance))
            throw new ArgumentException("Specify MSSQLSERVER or a single local SQL Server instance name.", nameof(instance));
        return instance.Equals("MSSQLSERVER", StringComparison.OrdinalIgnoreCase) ? "MSSQLSERVER" : $"MSSQL${instance}";
    }

    internal static SqlLoginEvidence? Project(string provider, string? actualProvider, int eventId, long? id, DateTime? time)
    {
        if (!provider.Equals(actualProvider, StringComparison.OrdinalIgnoreCase) || id is null or <= 0 || time is null)
            return null;
        var outcome = eventId switch
        {
            18453 or 18454 or 18455 => "success",
            18456 => "failure",
            _ => null
        };
        return outcome is null ? null : new(eventId, id.Value, time.Value.ToUniversalTime(), outcome);
    }
}
