using WPShield.Cli.Watch;

namespace WPShield.Cli.Report;

/// <summary>
/// One source file that fed the report, with the fixity it was read at.
/// </summary>
/// <remarks>
/// The SHA-256 is the chain-of-custody line: it says what the report was built from, so the same log
/// can be produced later and shown to hash the same. It is computed over the whole file at read time,
/// once.
/// </remarks>
internal sealed record EvidenceSource
{
    public required string FileName { get; init; }
    public required long SizeBytes { get; init; }
    public required string Sha256 { get; init; }
    public required int TotalLines { get; init; }
    public required int ParsedEvents { get; init; }
}

/// <summary>One rule's contribution across the window.</summary>
internal sealed record RuleRollup
{
    public required string RuleId { get; init; }
    public required int Findings { get; init; }
    public required int MaxScore { get; init; }

    /// <summary>How many distinct sites this rule fired on.</summary>
    public required int Sites { get; init; }
}

/// <summary>One site's contribution across the window.</summary>
internal sealed record SiteRollup
{
    public required string Site { get; init; }
    public required int Findings { get; init; }
    public required int Blocked { get; init; }
    public required int Observed { get; init; }
    public string? TopRule { get; init; }
}

/// <summary>One normalized request path and how often it drew a finding.</summary>
internal sealed record PathRollup
{
    public required string Path { get; init; }
    public required int Count { get; init; }
}

/// <summary>
/// Everything a report renders, aggregated from the evidence and independent of how it is drawn.
/// </summary>
/// <remarks>
/// <para>
/// This is the whole contract between reading the log and rendering the PDF. The aggregation is
/// tested against this; the QuestPDF document only lays it out.
/// </para>
/// <para>
/// <b>It counts what the log contains, never total traffic</b> — the same honesty <c>watch</c> keeps.
/// A clean request that is not a multipart upload is not in the log, so there is no request total
/// here and the report says so where a reader might otherwise assume one.
/// </para>
/// </remarks>
internal sealed record ReportModel
{
    public required DateTimeOffset GeneratedAt { get; init; }

    /// <summary>The sites the report was scoped to, or empty for all sites.</summary>
    public required IReadOnlyList<string> HostScope { get; init; }

    /// <summary>The earliest and latest event timestamps actually seen, or null when there were none.</summary>
    public DateTimeOffset? WindowStart { get; init; }
    public DateTimeOffset? WindowEnd { get; init; }

    public int TotalEvents { get; init; }
    public int Findings { get; init; }
    public int Blocked { get; init; }
    public int Observed { get; init; }
    public int AllowedUploads { get; init; }
    public int Dropped { get; init; }

    /// <summary>Distinct protection modes seen on verdict lines — "Monitor", "Block", or both.</summary>
    public IReadOnlyList<string> ModesSeen { get; init; } = [];

    public IReadOnlyList<RuleRollup> Rules { get; init; } = [];
    public IReadOnlyList<SiteRollup> Sites { get; init; } = [];
    public IReadOnlyList<PathRollup> TopPaths { get; init; } = [];
    public IReadOnlyList<EvidenceSource> Sources { get; init; } = [];

    /// <summary>True when nothing security-relevant was in the window at all.</summary>
    public bool Empty => TotalEvents == 0;
}
