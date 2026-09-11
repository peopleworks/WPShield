using WPShield.Cli.Preflight;

namespace WPShield.Cli.Enable;

/// <summary>What a site's <c>wp-config.php</c> says about the forwarded scheme.</summary>
internal enum SchemeTranslation
{
    /// <summary>No <c>wp-config.php</c>, so this is not WordPress and there is nothing to translate.</summary>
    NotWordPress,

    /// <summary>The translation is present. Putting a proxy in front cannot produce the redirect loop.</summary>
    Present,

    /// <summary>WordPress is there and would see plain HTTP behind HTTPS. This is the outage.</summary>
    Missing
}

/// <summary>
/// The one place that decides whether WordPress has been told the original request was HTTPS.
/// </summary>
/// <remarks>
/// <para>
/// <c>enable</c> refuses on this and <c>setup</c> reports it as a step, and they must never disagree —
/// a second copy of this rule is exactly how one of them starts saying a site is ready while the
/// other refuses it. So the rule, the snippet and the explanation live here once.
/// </para>
/// <para>
/// This never writes <c>wp-config.php</c>. That file is the site's own source, and refusing to
/// proceed without the translation rather than adding it is what makes <c>enable</c> unable to create
/// the <c>ERR_TOO_MANY_REDIRECTS</c> loop it exists to prevent.
/// </para>
/// </remarks>
internal static class WordPressSchemeTranslation
{
    /// <summary>The marker that proves the site reads the forwarded scheme at all.</summary>
    private const string Marker = "HTTP_X_FORWARDED_PROTO";

    public const string FileName = "wp-config.php";

    /// <summary>The code an operator has to paste, printed identically wherever it is asked for.</summary>
    public static readonly string Snippet =
        "    if ( isset( $_SERVER['HTTP_X_FORWARDED_PROTO'] )" + Environment.NewLine +
        "         && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https' ) {" + Environment.NewLine +
        "        $_SERVER['HTTPS'] = 'on';" + Environment.NewLine +
        "    }";

    public static string PathFor(string physicalPath) => Path.Combine(physicalPath, FileName);

    public static SchemeTranslation Check(IHostFacts host, string physicalPath)
    {
        ArgumentNullException.ThrowIfNull(host);
        ArgumentException.ThrowIfNullOrWhiteSpace(physicalPath);

        var path = PathFor(physicalPath);

        if (!host.FileExists(path))
        {
            return SchemeTranslation.NotWordPress;
        }

        return Read(path).Contains(Marker, StringComparison.OrdinalIgnoreCase)
            ? SchemeTranslation.Present
            : SchemeTranslation.Missing;
    }

    /// <summary>The refusal text, so the operator reads the same instruction from every verb.</summary>
    public static string Explain(string path) =>
        $"{path} does not translate X-Forwarded-Proto, and WPShield will not write it: that file is the " +
        "site's own source. Without the translation WordPress sees plain HTTP behind an HTTPS site and every " +
        "page redirects to HTTPS forever - ERR_TOO_MANY_REDIRECTS. Add this before " +
        "require_once ABSPATH . 'wp-settings.php'; and run this again:" + Environment.NewLine +
        Environment.NewLine + Snippet + Environment.NewLine;

    private static string Read(string path)
    {
        try
        {
            return File.ReadAllText(path);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw new CliArgumentException(
                $"{path} could not be read, so this cannot confirm the scheme translation is present: " +
                $"{exception.Message}. Nothing was changed.");
        }
    }
}
