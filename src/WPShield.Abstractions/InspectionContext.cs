namespace WPShield.Abstractions;

public sealed record InspectionContext(
    string SiteId,
    string Host,
    string Method,
    string Path,
    string? FileName = null,
    string? DeclaredContentType = null,
    ReadOnlyMemory<byte> Sample = default)
{
    /// <summary>
    /// <see cref="FileName"/> after Windows-aware normalization. Rules must match against this
    /// rather than against <see cref="FileName"/>, which is attacker-controlled and can hide an
    /// executable extension behind trailing dots, trailing spaces, an alternate data stream suffix,
    /// a directory prefix or embedded control characters.
    /// </summary>
    /// <remarks>
    /// Recomputed on each access so that <c>with</c> expressions can never hand a rule a stale
    /// normalization of a replaced file name. The work is a handful of string operations on a name
    /// bounded by <see cref="NormalizedFileName.MaximumSafeLength"/>. When the M2 multipart pipeline
    /// evaluates many rules per file it should hoist this into a local.
    /// </remarks>
    public NormalizedFileName NormalizedFile => NormalizedFileName.Create(FileName);

    /// <summary>
    /// <see cref="Path"/> after Windows-aware normalization, in every view a Windows web server
    /// could resolve differently. Rules must match against this rather than against
    /// <see cref="Path"/>, for the same reason they must never match a raw file name.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Recomputed on each access, exactly as <see cref="NormalizedFile"/> is, so a <c>with</c>
    /// expression cannot hand a rule a normalization of a path that was replaced. A pass that
    /// evaluates several rules against one context should hoist it into a local; the request-path
    /// engine does.
    /// </para>
    /// <para>
    /// Available to upload rules too, not only to path rules. An upload is posted <i>to</i> a path,
    /// and "this file arrived at an endpoint that never handles uploads" is a question worth being
    /// able to ask later without reshaping this record.
    /// </para>
    /// </remarks>
    public NormalizedRequestPath NormalizedPath => NormalizedRequestPath.Create(Path);
}
