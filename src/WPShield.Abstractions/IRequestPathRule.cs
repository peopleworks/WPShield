namespace WPShield.Abstractions;

/// <summary>
/// A rule that decides from the request line alone, before any body exists.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this is a separate interface from <see cref="IInspectionRule"/> rather than a convention.</b>
/// The two run at different times, against different evidence, and with different costs. An upload
/// rule runs once per file inside a buffered <c>multipart/form-data</c> body and may read a sample of
/// its bytes; a path rule runs once per request, on every request including the ones with no body at
/// all, and may read nothing but the method and the normalized path. Keeping them apart in the type
/// system is what stops a path rule from being registered into the per-file pass — where it would be
/// evaluated once per uploaded file and contribute its score several times — and stops an upload rule
/// from being asked to decide with no sample.
/// </para>
/// <para>
/// The context is shared deliberately. <see cref="InspectionContext"/> already carries the site, the
/// host, the method and the path; a path rule simply receives one whose file-shaped members are
/// empty, and the pass that builds it says so.
/// </para>
/// <para>
/// <b>These rules exist because of a real incident.</b> Through M2, WPShield inspected only
/// <c>multipart/form-data</c> bodies — so a request to a webshell that was already on disk passed
/// through with no rule looking at it. That is not a hypothetical: the traffic that exercised one was
/// a plain <c>GET</c> to a <c>.php</c> file inside a plugin's static asset directory. No body, no
/// upload, nothing for M2 to see. A rule that reads the request line would have refused it.
/// </para>
/// </remarks>
public interface IRequestPathRule
{
    /// <summary>Stable, untranslated identifier, in the published rule families.</summary>
    string Id { get; }

    ValueTask<RuleFinding?> EvaluateAsync(
        InspectionContext context,
        CancellationToken cancellationToken = default);
}
