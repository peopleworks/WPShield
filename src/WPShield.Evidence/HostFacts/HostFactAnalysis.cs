using System.Globalization;
using System.Text;

namespace WPShield.Evidence;

/// <summary>Bugcheck codes and the names an operator searches for.</summary>
public static class BugChecks
{
    private static readonly Dictionary<uint, string> Names = new()
    {
        [0x0A] = "IRQL_NOT_LESS_OR_EQUAL",
        [0x18] = "REFERENCE_BY_POINTER",
        [0x19] = "BAD_POOL_HEADER",
        [0x1A] = "MEMORY_MANAGEMENT",
        [0x1E] = "KMODE_EXCEPTION_NOT_HANDLED",
        [0x3B] = "SYSTEM_SERVICE_EXCEPTION",
        [0x50] = "PAGE_FAULT_IN_NONPAGED_AREA",
        [0x7A] = "KERNEL_DATA_INPAGE_ERROR",
        [0x7E] = "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
        [0x7F] = "UNEXPECTED_KERNEL_MODE_TRAP",
        [0x9F] = "DRIVER_POWER_STATE_FAILURE",
        [0xA0] = "INTERNAL_POWER_ERROR",
        [0xC2] = "BAD_POOL_CALLER",
        [0xC4] = "DRIVER_VERIFIER_DETECTED_VIOLATION",
        [0xD1] = "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
        [0xEF] = "CRITICAL_PROCESS_DIED",
        [0xF4] = "CRITICAL_OBJECT_TERMINATION",
        [0xFC] = "ATTEMPTED_EXECUTE_OF_NOEXECUTE_MEMORY",
        [0x101] = "CLOCK_WATCHDOG_TIMEOUT",
        [0x116] = "VIDEO_TDR_FAILURE",
        [0x124] = "WHEA_UNCORRECTABLE_ERROR",
        [0x133] = "DPC_WATCHDOG_VIOLATION",
        [0x139] = "KERNEL_SECURITY_CHECK_FAILURE",
        [0x13A] = "KERNEL_MODE_HEAP_CORRUPTION",
        [0x154] = "UNEXPECTED_STORE_EXCEPTION",
        [0x1E0] = "MANUALLY_INITIATED_CRASH"
    };

    public static string? Name(uint code) => Names.GetValueOrDefault(code);

    /// <summary><c>0x133 DPC_WATCHDOG_VIOLATION</c>, or just the code when its name is not known.</summary>
    public static string Describe(uint code) =>
        Name(code) is { } name ? $"0x{code:X} {name}" : $"0x{code:X}";

    /// <summary>
    /// The code from the text of a WER 1001 bugcheck record, such as <c>0x00000133 (0x0, 0x501, ...)</c>, or
    /// from a decimal number as Kernel-Power 41 stores it.
    /// </summary>
    public static uint? Parse(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var value = text.Trim();
        var space = value.IndexOfAny([' ', '(', ',']);
        if (space > 0) value = value[..space];
        if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return uint.TryParse(value.AsSpan(2), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out var hex) && hex != 0 ? hex : null;
        return uint.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var number) && number != 0 ? number : null;
    }
}

/// <summary>One unexpected restart, made of the System log records Windows wrote about it at the next start.</summary>
/// <param name="Key">The earliest record's id and time: stable across reads, and new after a log clear.</param>
/// <param name="EventIds">Which of 41, 6008 and 1001 said so.</param>
public sealed record HostRestart(string Key, DateTimeOffset At, IReadOnlyList<int> EventIds, uint? BugCheckCode)
{
    public string? BugCheck => BugCheckCode is { } code ? BugChecks.Describe(code) : null;
}

/// <summary>
/// One crash leaves up to three records - Kernel-Power 41, EventLog 6008 and the WER 1001 that carries the
/// code, sometimes minutes later. They are one restart, and must be counted once.
/// </summary>
public static class HostRestarts
{
    /// <summary>Records closer than this to the previous one belong to the same restart.</summary>
    public static readonly TimeSpan SameRestart = TimeSpan.FromMinutes(15);

    /// <summary>How far before the last read a new read starts, so a 1001 written late joins its 41.</summary>
    public static readonly TimeSpan Overlap = TimeSpan.FromMinutes(30);

    public static IReadOnlyList<HostRestart> Group(IEnumerable<HostRestartRecord> records)
    {
        var result = new List<HostRestart>();
        List<HostRestartRecord>? current = null;
        foreach (var record in records.OrderBy(r => r.At).ThenBy(r => r.RecordId).Take(HostFacts.MaxRestartEvents))
        {
            if (current is not null && record.At - current[^1].At <= SameRestart)
            {
                current.Add(record);
                continue;
            }
            if (current is not null) result.Add(Close(current));
            current = [record];
        }
        if (current is not null) result.Add(Close(current));
        return result;
    }

    private static HostRestart Close(List<HostRestartRecord> records)
    {
        var first = records[0];
        var key = string.Create(CultureInfo.InvariantCulture, $"{first.RecordId}@{first.At.ToUnixTimeMilliseconds()}");
        var code = records.Select(r => r.BugCheckCode).FirstOrDefault(c => c is not null);
        return new(key, first.At, [.. records.Select(r => r.EventId).Distinct().Order()], code);
    }
}

/// <summary>An inventory item as the change detector compares it.</summary>
public sealed record InventoryItemView(string Key, string? Executable, string? Account, string Signature);

/// <param name="Change"><c>added</c>, <c>removed</c> or <c>changed</c>.</param>
/// <param name="Fields">For a change: which of <c>executable</c>, <c>account</c>, <c>signature</c> differ.</param>
public sealed record InventoryChange(string Kind, string Change, string Key, IReadOnlyList<string> Fields);

/// <summary>
/// "A task appeared": the difference between two inventory snapshots (ADR 0013, section 1.3).
/// </summary>
public static class InventoryDiff
{
    public static IReadOnlyList<InventoryChange> Compare(string kind, IEnumerable<InventoryItemView> before, IEnumerable<InventoryItemView> after)
    {
        var old = Index(before);
        var now = Index(after);
        var changes = new List<InventoryChange>();
        foreach (var (key, item) in now)
        {
            if (!old.TryGetValue(key, out var previous))
            {
                changes.Add(new(kind, "added", key, []));
                continue;
            }
            var fields = new List<string>(3);
            if (!string.Equals(previous.Executable, item.Executable, StringComparison.OrdinalIgnoreCase)) fields.Add("executable");
            if (!string.Equals(previous.Account, item.Account, StringComparison.OrdinalIgnoreCase)) fields.Add("account");
            // A signature not checked this time (the budget ran out) is not a change.
            if (previous.Signature != HostSignature.NotChecked && item.Signature != HostSignature.NotChecked &&
                previous.Signature != item.Signature)
                fields.Add("signature");
            if (fields.Count > 0) changes.Add(new(kind, "changed", key, fields));
        }
        foreach (var key in old.Keys.Where(k => !now.ContainsKey(k)))
            changes.Add(new(kind, "removed", key, []));
        return changes;
    }

    private static Dictionary<string, InventoryItemView> Index(IEnumerable<InventoryItemView> items)
    {
        var map = new Dictionary<string, InventoryItemView>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in items.Take(HostFacts.MaxInventoryItems)) map.TryAdd(item.Key, item);
        return map;
    }

    public static IEnumerable<InventoryItemView> Views(HostAccounts accounts) =>
        accounts.Accounts.Select(a => new InventoryItemView(a.Name, null,
            a.Administrator == true ? "administrators" : a.RemoteDesktopUser == true ? "remote-desktop-users" : "users", HostSignature.NotChecked));

    public static IEnumerable<InventoryItemView> Views(HostServices services) =>
        services.Services.Select(s => new InventoryItemView(s.Name, s.Executable, s.Account, s.Signature));

    public static IEnumerable<InventoryItemView> Views(HostTasks tasks) =>
        tasks.Tasks.Select(t => new InventoryItemView(t.Path, t.Executable, t.Principal, t.Signature));
}

/// <summary>
/// "The attackers try the full name of a real account" (ADR 0013, decision 5): computed in memory, stored as a
/// count. The full names are compared and dropped; no full name is ever written anywhere.
/// </summary>
public static class FullNameIndicator
{
    /// <summary>How many distinct local full names appear among the attempted account names.</summary>
    public static int Matches(IEnumerable<string> fullNames, IEnumerable<string> attemptedNames)
    {
        var attempted = new HashSet<string>(attemptedNames.Select(Normalize).Where(n => n.Length > 0), StringComparer.Ordinal);
        return fullNames.Select(Normalize).Where(n => n.Length > 0).Distinct(StringComparer.Ordinal).Count(attempted.Contains);
    }

    /// <summary>
    /// Case, accents, surrounding and repeated spaces, and a <c>HOST\</c> or <c>@domain</c> part do not make a name
    /// different (ADR 0013, section 1.3): an attacker types "jose" for "José".
    /// </summary>
    internal static string Normalize(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return "";
        var value = name.Trim();
        var slash = value.LastIndexOf('\\');
        if (slash >= 0) value = value[(slash + 1)..];
        var at = value.IndexOf('@');
        if (at > 0) value = value[..at];
        var builder = new StringBuilder(value.Length);
        var space = false;
        foreach (var c in value.Normalize(NormalizationForm.FormD))
        {
            if (CharUnicodeInfo.GetUnicodeCategory(c) == UnicodeCategory.NonSpacingMark) continue;
            if (char.IsWhiteSpace(c))
            {
                space = builder.Length > 0;
                continue;
            }
            if (space) builder.Append(' ');
            space = false;
            builder.Append(char.ToLowerInvariant(c));
        }
        return builder.ToString();
    }
}
