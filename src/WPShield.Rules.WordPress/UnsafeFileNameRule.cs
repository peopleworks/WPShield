using WPShield.Abstractions;

namespace WPShield.Rules.WordPress;

/// <summary>
/// <c>FILE-NAME-001</c> — the supplied file name is structurally unsafe on Windows.
/// </summary>
/// <remarks>
/// <para>
/// Reports the anomalies that normalization had to remove: a directory component, an NTFS alternate
/// data stream suffix, trailing dots or spaces that Windows strips on write, embedded control
/// characters, a reserved device name, or an excessive length. Each of these is a deliberate attempt
/// to make the name that reaches disk differ from the name that was inspected.
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

        var normalized = context.NormalizedFile;
        if (!normalized.HasUnsafeForm && !normalized.IsEmpty)
        {
            return ValueTask.FromResult<RuleFinding?>(null);
        }

        var anomalies = new List<string>(6);
        if (normalized.HadPathSeparator) anomalies.Add("pathSeparator");
        if (normalized.HadAlternateDataStream) anomalies.Add("alternateDataStream");
        if (normalized.HadTrailingDotsOrSpaces) anomalies.Add("trailingDotsOrSpaces");
        if (normalized.HadControlCharacter) anomalies.Add("controlCharacter");
        if (normalized.IsReservedDeviceName) anomalies.Add("reservedDeviceName");
        if (normalized.ExceedsSafeLength) anomalies.Add("excessiveLength");
        if (normalized.IsEmpty) anomalies.Add("emptyAfterNormalization");

        RuleFinding finding = new(
            Id,
            Score,
            "Findings.UnsafeUploadFileName",
            new Dictionary<string, string>
            {
                // Evidence records the anomaly kinds and the normalized result, never the raw
                // attacker-supplied name, which can carry control characters into a log consumer.
                ["anomalies"] = string.Join(",", anomalies),
                ["normalizedName"] = normalized.BaseName
            });

        return ValueTask.FromResult<RuleFinding?>(finding);
    }
}
