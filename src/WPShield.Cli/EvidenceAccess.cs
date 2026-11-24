using System.Security.Principal;
using Microsoft.Data.Sqlite;
using WPShield.Evidence;

namespace WPShield.Cli;

/// <summary>Why the evidence store could not be opened. The desktop words each one in its own language.</summary>
internal enum EvidenceProblem
{
    /// <summary>The store is not there: the service was never installed, or has not written yet.</summary>
    Missing,
    /// <summary>This process is not elevated, so it could not look. Not the same as "missing".</summary>
    NotElevated,
    /// <summary>Elevated, and still refused: the folder's permissions are not the ones install sets.</summary>
    AccessDenied,
    /// <summary>A store of another schema version; another build of WPShield wrote it.</summary>
    Schema,
    /// <summary>SQLite could not read it (corrupt, locked, not a database).</summary>
    Unreadable
}

internal sealed class EvidenceAccessException(EvidenceProblem problem, string message) : Exception(message)
{
    public EvidenceProblem Problem { get; } = problem;

    /// <summary>The CLI's exit code table: 1 could not look, 2 present but wrong, 3 nothing installed.</summary>
    public int ExitCode => Problem switch
    {
        EvidenceProblem.Missing => 3,
        EvidenceProblem.NotElevated or EvidenceProblem.AccessDenied => 1,
        _ => 2
    };
}

/// <summary>
/// Opens the evidence store for a reader, and says why when it cannot - so no reader ever shows an
/// empty history where the truth is "nobody could look".
/// </summary>
/// <remarks>
/// <see cref="File.Exists(string)"/> answers <see langword="false"/> when access is denied, and the
/// store's folder admits only administrators and the service. Without elevation, "not found" is
/// therefore reported as "could not look", because that is the more likely truth and the safer one
/// to act on.
/// </remarks>
internal static class EvidenceAccess
{
    internal static bool IsElevated()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch (Exception ex) when (ex is System.Security.SecurityException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    internal static string CurrentUser()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return identity.Name;
        }
        catch (System.Security.SecurityException)
        {
            return Environment.UserDomainName + "\\" + Environment.UserName;
        }
    }

    internal static EvidenceStore OpenReadOnly(string path, bool elevated)
    {
        var shown = NetworkMonitorCommand.ConsoleLabel(path);
        try
        {
            return EvidenceStore.OpenReadOnly(path);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException)
        {
            throw elevated
                ? new EvidenceAccessException(EvidenceProblem.Missing,
                    $"There is no evidence store at {shown}. The WPShield service creates it once it is installed ('wpshield install') " +
                    "and running. Without it there is no history to show - which is not the same as no attacks.")
                : NotElevated(shown);
        }
        catch (UnauthorizedAccessException)
        {
            throw elevated
                ? new EvidenceAccessException(EvidenceProblem.AccessDenied,
                    $"Access to the evidence store at {shown} was denied although this process is elevated. Check the folder's permissions.")
                : NotElevated(shown);
        }
        catch (InvalidDataException ex)
        {
            throw new EvidenceAccessException(EvidenceProblem.Schema,
                $"The evidence store at {shown} cannot be read by this build: {NetworkMonitorCommand.ConsoleLabel(ex.Message)} " +
                "Use the wpshield.exe installed with the service.");
        }
        catch (SqliteException ex)
        {
            throw elevated
                ? new EvidenceAccessException(EvidenceProblem.Unreadable,
                    $"The evidence store at {shown} could not be read (SQLite error {ex.SqliteErrorCode}: {NetworkMonitorCommand.ConsoleLabel(ex.Message)}).")
                : NotElevated(shown);
        }
    }

    /// <summary>
    /// Opens the store to change settings. Never creates or migrates it: the store must already exist
    /// and have exactly this build's schema, both checked read-only first. The service owns the file.
    /// </summary>
    internal static EvidenceStore OpenForSettings(string path, bool elevated)
    {
        using (OpenReadOnly(path, elevated))
        {
        }
        try
        {
            return EvidenceStore.OpenForWriting(path);
        }
        catch (UnauthorizedAccessException)
        {
            throw new EvidenceAccessException(EvidenceProblem.AccessDenied,
                $"The evidence store at {NetworkMonitorCommand.ConsoleLabel(path)} could be read but not written. Check the folder's permissions.");
        }
        catch (Exception ex) when (ex is SqliteException or IOException or InvalidDataException)
        {
            throw new EvidenceAccessException(EvidenceProblem.Unreadable,
                $"The evidence store at {NetworkMonitorCommand.ConsoleLabel(path)} could not be opened for writing: {NetworkMonitorCommand.ConsoleLabel(ex.Message)}");
        }
    }

    private static EvidenceAccessException NotElevated(string shown) => new(EvidenceProblem.NotElevated,
        $"Could not open the evidence store at {shown}. Its folder admits only administrators and the WPShield service, and this " +
        "process is not elevated: run it from an elevated prompt. Nothing was read, which is not the same as nothing recorded.");
}

/// <summary>A period a reader asks the store about.</summary>
/// <param name="Bucket">The timeline bucket the desktop draws for this range.</param>
internal sealed record EvidenceWindow(string Name, DateTimeOffset From, DateTimeOffset To, TimeSpan Bucket)
{
    internal string Describe() => Name switch
    {
        "1h" => "last hour",
        "6h" => "last 6 hours",
        "24h" => "last 24 hours",
        "7d" => "last 7 days",
        _ => "last 30 days"
    };
}

/// <summary>
/// The ranges every reader of the store offers, computed one way. From 24 hours up, a range starts on
/// a whole hour (30 days on a whole UTC day) so that hourly aggregates add up exactly; it is never
/// shorter than its name.
/// </summary>
internal static class EvidenceRanges
{
    internal static readonly string[] Names = ["1h", "6h", "24h", "7d", "30d"];

    internal static bool IsName(string? text) => text is not null && Names.Contains(text, StringComparer.Ordinal);

    internal static EvidenceWindow Window(string name, DateTimeOffset now)
    {
        now = now.ToUniversalTime();
        return name switch
        {
            "1h" => new(name, now.AddHours(-1), now, TimeSpan.FromMinutes(5)),
            "6h" => new(name, now.AddHours(-6), now, TimeSpan.FromMinutes(15)),
            "24h" => new(name, Floor(now.AddHours(-24), TimeSpan.TicksPerHour), now, TimeSpan.FromHours(1)),
            "7d" => new(name, Floor(now.AddDays(-7), TimeSpan.TicksPerHour), now, TimeSpan.FromHours(1)),
            "30d" => new(name, Floor(now.AddDays(-30), TimeSpan.TicksPerDay), now, TimeSpan.FromDays(1)),
            _ => throw new ArgumentOutOfRangeException(nameof(name), "Not a range: " + name)
        };
    }

    private static DateTimeOffset Floor(DateTimeOffset time, long unit) => new(time.UtcTicks - time.UtcTicks % unit, TimeSpan.Zero);
}

internal sealed record CoverageGap(DateTimeOffset From, DateTimeOffset To, string? Status, string? Reason);

/// <summary>What the collector vouched for in a range: all of it, part of it, or none.</summary>
internal sealed record CoverageReport(string State, IReadOnlyList<CoverageGap> Gaps, int Omitted)
{
    internal const string Full = "full";
    internal const string Partial = "partial";
    internal const string None = "none";
    internal const int MaxGaps = 10;

    /// <summary>
    /// The gaps in the failed-logon collector's coverage of a range. Only that collector's rows count:
    /// another source's interval says nothing about whether failed logons were being read.
    /// </summary>
    internal static CoverageReport Analyse(IReadOnlyList<EvidenceCoverage> rows, DateTimeOffset from, DateTimeOffset to)
    {
        var mine = rows.Where(r => r.Source == EvidenceWriter.RawSource).ToArray();
        var collected = new List<(DateTimeOffset From, DateTimeOffset To)>();
        foreach (var interval in mine.Where(r => r.Status == "collected" && r.To > from && r.From < to).OrderBy(r => r.From))
        {
            if (collected.Count > 0 && interval.From <= collected[^1].To)
            {
                if (interval.To > collected[^1].To) collected[^1] = (collected[^1].From, interval.To);
                continue;
            }
            collected.Add((interval.From, interval.To));
        }
        if (collected.Count == 0) return new(None, [Gap(mine, from, to)], 0);
        // The collector extends its interval as it goes; the last moments before 'to' are not a gap.
        var end = to - EvidenceQueries.CurrentAllowance > from ? to - EvidenceQueries.CurrentAllowance : from;
        var gaps = new List<CoverageGap>();
        var cursor = from;
        foreach (var (start, stop) in collected)
        {
            if (start > cursor && cursor < end) gaps.Add(Gap(mine, cursor, start < end ? start : end));
            if (stop > cursor) cursor = stop;
        }
        if (cursor < end) gaps.Add(Gap(mine, cursor, to));
        return gaps.Count == 0
            ? new(Full, [], 0)
            : new(Partial, gaps.Take(MaxGaps).ToArray(), Math.Max(0, gaps.Count - MaxGaps));
    }

    private static CoverageGap Gap(EvidenceCoverage[] rows, DateTimeOffset from, DateTimeOffset to)
    {
        var (status, reason) = Explain(rows, from, to);
        return new(from, to, status, reason);
    }

    /// <summary>A non-collected interval overlapping the gap, if the collector wrote down why.</summary>
    private static (string? Status, string? Reason) Explain(EvidenceCoverage[] rows, DateTimeOffset from, DateTimeOffset to)
    {
        var why = rows.FirstOrDefault(r => r.Status != "collected" && r.From < to && r.To > from);
        return why is null ? (null, null) : (why.Status, why.Reason);
    }
}
