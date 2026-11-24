using System.ComponentModel;
using System.Diagnostics;

namespace WPShield.Desktop;

/// <summary>
/// Names the process behind a listener's PID, so the operator reads <c>sqlservr</c> instead of a number.
/// </summary>
/// <remarks>
/// The name is read after the socket table, so the process can exit, or its PID be reused, in between.
/// A process that cannot be read stays unnamed rather than guessed. Reading a name needs no elevation;
/// it never opens the process for anything else.
/// </remarks>
internal static class ProcessNames
{
    private const int MaxProcesses = 4096;

    internal static string? Read(uint processId)
    {
        if (processId == 0 || processId > int.MaxValue) return null;
        try
        {
            using var process = Process.GetProcessById((int)processId);
            return process.ProcessName;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or Win32Exception
            or NotSupportedException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>Reads each distinct PID once, bounded, with an injectable reader for tests.</summary>
    internal static IReadOnlyDictionary<uint, string?> Resolve(IEnumerable<uint> processIds, Func<uint, string?> read)
    {
        var names = new Dictionary<uint, string?>();
        foreach (var id in processIds)
        {
            if (names.ContainsKey(id)) continue;
            if (names.Count >= MaxProcesses) break;
            names[id] = read(id);
        }
        return names;
    }
}
