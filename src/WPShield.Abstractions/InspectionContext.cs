namespace WPShield.Abstractions;

public sealed record InspectionContext(
    string SiteId,
    string Host,
    string Method,
    string Path,
    string? FileName = null,
    string? DeclaredContentType = null,
    ReadOnlyMemory<byte> Sample = default);
