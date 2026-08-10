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
}
