using System.Collections.Frozen;

namespace WPShield.Rules.WordPress;

/// <summary>
/// Extension vocabularies shared by the upload rules. Segments are stored lowercased and without a
/// leading dot to match <see cref="Abstractions.NormalizedFileName.ExtensionSegments"/>.
/// </summary>
internal static class DangerousUploadExtensions
{
    /// <summary>
    /// Extensions a PHP-FastCGI handler will execute. <c>phps</c>, <c>pht</c> and <c>phtm</c> are
    /// included because handler mappings commonly cover them by wildcard even when the documentation
    /// only mentions the numbered variants.
    /// </summary>
    public static readonly FrozenSet<string> PhpExecutable = new[]
    {
        "php", "php3", "php4", "php5", "php7", "php8",
        "phps", "pht", "phtm", "phtml", "phar"
    }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Extensions IIS maps to a managed or native handler. WPShield targets Windows hosting, so an
    /// upload that IIS itself will execute is exactly as dangerous as a PHP script, and a WordPress
    /// site never has a legitimate reason to receive one through an upload endpoint.
    /// </summary>
    public static readonly FrozenSet<string> IisExecutable = new[]
    {
        "aspx", "asp", "ashx", "asmx", "ascx", "axd",
        "cshtml", "vbhtml", "razor",
        "svc", "soap", "rem", "asax", "master"
    }.ToFrozenSet(StringComparer.OrdinalIgnoreCase);

    /// <summary>Every extension that can lead to code execution on the target platform.</summary>
    public static readonly FrozenSet<string> AllExecutable =
        PhpExecutable.Concat(IisExecutable).ToFrozenSet(StringComparer.OrdinalIgnoreCase);
}
