using System.Reflection;
using System.Runtime.InteropServices;
using WPShield.Evidence;

namespace WPShield.Cli.Host;

/// <summary>
/// The patch level's fallback (ADR 0013, as built): the newest installed hotfix from <c>Win32_QuickFixEngineering</c>,
/// read through WMI's scripting interface only when the Windows Update log names no cumulative update. On the first
/// real host that log held no install event at all, although cumulative updates were installed; updates applied
/// from a package or by a management tool are recorded only here. Read-only: one fixed query, nothing written.
/// </summary>
internal static class HostHotfixReader
{
    private const string Query = "SELECT HotFixID, InstalledOn FROM Win32_QuickFixEngineering";

    /// <summary>The rows, or <see langword="null"/> when WMI could not be read: unknown, never "no hotfix".</summary>
    public static IReadOnlyList<HotfixRecord>? Read(CancellationToken cancellationToken)
    {
        try
        {
            var locator = ComLateBound.Create("WbemScripting.SWbemLocator");
            if (locator is null) return null;
            var services = ComLateBound.Invoke(locator, "ConnectServer", ".", @"root\cimv2");
            if (services is null) return null;
            var rows = new List<HotfixRecord>();
            foreach (var item in ComLateBound.Items(ComLateBound.Invoke(services, "ExecQuery", Query)))
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (rows.Count >= Hotfixes.MaxRows) break;
                rows.Add(new HotfixRecord(Property(item, "HotFixID"), Property(item, "InstalledOn")));
            }
            return rows;
        }
        catch (Exception exception) when (exception is COMException or UnauthorizedAccessException or InvalidCastException
            or MissingMethodException or MissingMemberException or TargetException)
        {
            return null;
        }
    }

    /// <summary>The patch level with the newest hotfix added, when the update log named no cumulative update.</summary>
    public static HostPatchLevel WithHotfix(HostPatchLevel patch, Func<IReadOnlyList<HotfixRecord>?> read)
    {
        ArgumentNullException.ThrowIfNull(patch);
        ArgumentNullException.ThrowIfNull(read);
        if (patch.LastCumulativeUpdateAt is not null) return patch;
        var rows = read();
        if (rows is null) return patch with { HotfixListRead = false };
        var newest = Hotfixes.Newest(rows);
        return patch with { HotfixListRead = true, LastHotfixId = newest?.Id, LastHotfixInstalledOn = newest?.InstalledOn };
    }

    /// <summary>The health reading with the hotfix fallback applied to its patch level; anything else unchanged.</summary>
    public static HostFactReading WithHotfix(HostFactReading reading, Func<IReadOnlyList<HotfixRecord>?> read)
    {
        ArgumentNullException.ThrowIfNull(reading);
        if (reading.Fact != HostFacts.Health || reading.Value<HostHealth>() is not { Patch: { } patch } health) return reading;
        var updated = WithHotfix(patch, read);
        return ReferenceEquals(updated, patch) ? reading
            : HostFactReading.Of(reading.Fact, reading.Kind, reading.TakenAt, health with { Patch = updated }, reading.Status, reading.Reason, reading.Remedy);
    }

    private static string? Property(object item, string name)
    {
        var property = ComLateBound.Invoke(ComLateBound.GetObject(item, "Properties_"), "Item", name);
        return property is null ? null : ComLateBound.Get(property, "Value") as string;
    }
}
