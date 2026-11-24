using System.ComponentModel;
using System.Diagnostics;

namespace WPShield.Desktop;

/// <summary>
/// Names the process behind a listener's PID, so the operator reads <c>sqlservr</c> instead of a number.
/// </summary>
internal static class ProcessNames
{
    private const int MaxProcesses = 4096;

    internal sealed record Identity(string Name, DateTimeOffset StartedAtUtc);

    internal static Identity? Read(uint processId)
    {
        if (processId == 0 || processId > int.MaxValue) return null;
        try
        {
            using var process = Process.GetProcessById((int)processId);
            // Read the name first. If Windows recycles the PID during these two reads, the
            // replacement's start time is later than every owner sample in this refresh.
            var name = process.ProcessName;
            var startedAtUtc = process.StartTime.ToUniversalTime();
            return new(name, startedAtUtc);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or Win32Exception
            or NotSupportedException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>Reads each distinct PID once, bounded, with an injectable reader for tests.</summary>
    internal static IReadOnlyDictionary<uint, Identity?> Resolve(IEnumerable<uint> processIds, Func<uint, Identity?> read)
    {
        var names = new Dictionary<uint, Identity?>();
        foreach (var id in processIds)
        {
            if (names.ContainsKey(id)) continue;
            if (names.Count >= MaxProcesses) break;
            names[id] = read(id);
        }
        return names;
    }

    internal static (string Name, string? Reason) ForOwner(IReadOnlyDictionary<uint, Identity?> identities,
        uint processId, DateTimeOffset ownerObservedAtUtc)
    {
        if (!identities.TryGetValue(processId, out var identity)) return ("", "name-lookup-limit");
        if (identity is null || string.IsNullOrEmpty(identity.Name)) return ("", "name-unavailable");
        if (identity.StartedAtUtc >= ownerObservedAtUtc) return ("", "start-not-before-sample");
        return (DisplayText.Clean(identity.Name, 64), null);
    }
}
