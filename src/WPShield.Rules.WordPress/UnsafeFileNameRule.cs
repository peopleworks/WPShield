using WPShield.Abstractions;

namespace WPShield.Rules.WordPress;

/// <summary>
/// <c>FILE-NAME-001</c> — the supplied file name is structurally unsafe on Windows, or the backend
/// would rewrite it into something dangerous.
/// </summary>
/// <remarks>
/// <para>
/// Reports the anomalies that normalization had to remove: a directory component, an NTFS alternate
/// data stream suffix, trailing dots or spaces that Windows strips on write, embedded control
/// characters, invisible formatting characters, a reserved device name, or an excessive length. Each
/// of these is a deliberate attempt to make the name that reaches disk — or the name that reaches an
/// operator's screen — differ from the name that was inspected.
/// </para>
/// <para>
/// <b><c>wordpressRewrite</c>.</b> The seventh anomaly is not something normalization removed; it is
/// something the backend would <i>add</i>. WordPress's <c>sanitize_file_name()</c> deletes
/// characters from the middle of a name and closes the gap, so <c>web.con{f}ig</c> becomes a live
/// IIS configuration file and <c>shell.p%hp</c> becomes an executable script, neither of which the
/// NTFS view can see. The extension rules act on that through their own two-view matching; this
/// anomaly exists so the <i>divergence itself</i> is on the log line. An operator running in Monitor
/// mode needs to see "the name you would read in the media library is not the name that was sent"
/// before Block mode turns the same request into a refusal.
/// </para>
/// <para>
/// It is reported only when the rewrite <b>produces</b> something dangerous: the reserved
/// <c>web.config</c> name, a reserved device name, an executable extension the NTFS view never saw,
/// or the same executable extension moved into the final position where a handler mapping runs it.
/// A merely different name is not an anomaly — see the false positives below.
/// </para>
/// <para>
/// The score is intentionally moderate. On its own the finding is an anomaly worth recording rather
/// than grounds for blocking, and it stays below the default block threshold. Combined with an
/// executable-extension finding it pushes the request over that threshold, which is the intended
/// behavior for something like <c>../../shell.php.</c>.
/// </para>
/// <para>
/// <b>False positives.</b> Unicode file names are not flagged; only control characters are. Some
/// browsers and legacy clients submit a full local path rather than a bare name, so
/// <c>HadPathSeparator</c> alone can fire on legitimate traffic from those clients. That is the main
/// reason this rule does not reach the block threshold by itself.
/// </para>
/// <para>
/// The <c>wordpressRewrite</c> anomaly was the dangerous one to add, and it is narrow on purpose.
/// Ordinary WordPress uploads are rewritten constantly — <c>Captura de pantalla (3).png</c>,
/// <c>Q&amp;A final.pdf</c>, <c>Informe (2024) v2.pdf</c>, any name with a space, a parenthesis, an
/// ampersand or a typographic quote — and reporting divergence as such would have put 60 points on a
/// large fraction of real traffic, which together with <c>FILE-TYPE-001</c>'s 40 is a blocked upload.
/// So divergence alone is silent, and only a rewrite that manufactures a dangerous name is reported.
/// Every benign rewrite listed above changes the stem and leaves the extension segments alone, which
/// is why the narrow test separates them cleanly.
/// </para>
/// <para>
/// Two things it cannot separate, stated rather than discovered later. A backup or editor artefact
/// such as <c>web.config~</c> or <c>functions.php-</c> is reported, and by name alone it is
/// indistinguishable from an evasion — though in both readings WordPress writes the dangerous name,
/// so the report is right even when the intent was innocent. And a site that filters
/// <c>sanitize_file_name_chars</c> to keep a character WordPress deletes by default gets a rewrite
/// WPShield predicted and the backend never performs; there the finding is genuinely wrong, and the
/// answer is Monitor mode rather than a heuristic.
/// </para>
/// <para>
/// <c>invisibleFormatting</c> deliberately excludes U+200C and U+200D, which are ordinary content in
/// Persian, Arabic and Indic names and in emoji sequences. See
/// <c>NormalizedFileName.HadInvisibleFormatting</c>.
/// </para>
/// </remarks>
public sealed class UnsafeFileNameRule : IInspectionRule
{
    internal const int Score = 60;

    public string Id => "FILE-NAME-001";

    public ValueTask<RuleFinding?> EvaluateAsync(
        InspectionContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        cancellationToken.ThrowIfCancellationRequested();

        if (context.FileName is null)
        {
            return ValueTask.FromResult<RuleFinding?>(null);
        }

        // NormalizedFile recomputes on every access by design, so it is hoisted once here.
        var normalized = context.NormalizedFile;
        var hostileRewrite = RewritesIntoADangerousName(normalized);

        if (!normalized.HasUnsafeForm && !normalized.IsEmpty && !hostileRewrite)
        {
            return ValueTask.FromResult<RuleFinding?>(null);
        }

        var anomalies = new List<string>(9);
        if (normalized.HadPathSeparator) anomalies.Add("pathSeparator");
        if (normalized.HadAlternateDataStream) anomalies.Add("alternateDataStream");
        if (normalized.HadTrailingDotsOrSpaces) anomalies.Add("trailingDotsOrSpaces");
        if (normalized.HadControlCharacter) anomalies.Add("controlCharacter");
        if (normalized.HadInvisibleFormatting) anomalies.Add("invisibleFormatting");
        if (normalized.IsReservedDeviceName) anomalies.Add("reservedDeviceName");
        if (normalized.ExceedsSafeLength) anomalies.Add("excessiveLength");
        if (normalized.IsEmpty) anomalies.Add("emptyAfterNormalization");
        if (hostileRewrite) anomalies.Add("wordpressRewrite");

        // Evidence records the anomaly kinds and the normalized result, never the raw
        // attacker-supplied name, which can carry control characters into a log consumer.
        var evidence = new Dictionary<string, string>(3)
        {
            ["anomalies"] = string.Join(",", anomalies),
            ["normalizedName"] = normalized.BaseName
        };

        if (normalized.DivergesUnderWordPress)
        {
            // Reported whenever the two views disagree, not only when the rewrite was hostile: an
            // operator reading a finding about some other anomaly still needs to know that the name
            // in their media library will not be the name on this line.
            evidence["wordpressName"] = normalized.WordPress.BaseName;
        }

        RuleFinding finding = new(Id, Score, "Findings.UnsafeUploadFileName", evidence);

        return ValueTask.FromResult<RuleFinding?>(finding);
    }

    /// <summary>
    /// Whether <c>sanitize_file_name()</c> would turn this name into one that is dangerous under a
    /// name rule, when the name as sent is not.
    /// </summary>
    /// <remarks>
    /// The comparison is against the NTFS view rather than against a fixed list, so the anomaly
    /// reports a <i>change in exposure</i> and not merely the presence of a dangerous token. A name
    /// that is already <c>shell.php</c> in both views is dangerous, but nothing about it was
    /// rewritten, and <c>WP-UPLOAD-001</c> is the rule that has something to say about it.
    /// </remarks>
    private static bool RewritesIntoADangerousName(NormalizedFileName normalized)
    {
        if (!normalized.DivergesUnderWordPress)
        {
            return false;
        }

        var ntfs = normalized.Windows;
        var wordPress = normalized.WordPress;

        if (wordPress.IsNamed(IisConfigurationUploadRule.ReservedName) &&
            !ntfs.IsNamed(IisConfigurationUploadRule.ReservedName))
        {
            return true;
        }

        if (wordPress.IsReservedDeviceName && !ntfs.IsReservedDeviceName)
        {
            return true;
        }

        var rewritten = wordPress.MatchExtension(DangerousUploadExtensions.AllExecutable);
        if (rewritten is null)
        {
            return false;
        }

        var asSent = ntfs.MatchExtension(DangerousUploadExtensions.AllExecutable);

        // Either the rewrite manufactured an executable extension out of nothing, or it moved one
        // that was harmlessly embedded into the final position, which is the position a handler
        // mapping actually runs.
        return asSent is null || (rewritten.IsFinalPosition && !asSent.IsFinalPosition);
    }
}
