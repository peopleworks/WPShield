namespace WPShield.Gateway;

public sealed class GatewayOptions
{
    public const long AbsoluteMaximumRequestBytes = 64L * 1024 * 1024;

    public string[] Urls { get; init; } = ["http://127.0.0.1:10000"];
    public bool AllowRemoteHealthChecks { get; init; }

    /// <summary>
    /// Peer addresses whose <c>X-Forwarded-For</c> and <c>X-Forwarded-Proto</c> headers WPShield will
    /// honor. Bound from <c>Gateway:TrustedProxies</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Empty by default, and that default is the safe posture rather than an unset value.</b> With
    /// no entry the gateway strips every inbound forwarding header exactly as it did through M2, so
    /// an operator who deploys behind IIS and forgets this setting gets a visibly wrong result — all
    /// traffic attributed to the proxy — instead of a silently forgeable one. An operator must opt in.
    /// </para>
    /// <para>
    /// Exact addresses only. A CIDR range is rejected rather than supported, because the entries
    /// decide whose forwarding headers become authoritative and a range mistyped one bit too wide
    /// hands that authority to strangers. Under the production traffic path the only trusted peer is
    /// the local proxy, so a range buys nothing and a typo costs everything.
    /// </para>
    /// </remarks>
    public string[] TrustedProxies { get; init; } = [];

    public int ActivityTimeoutSeconds { get; init; } = 100;
    public long MaximumRequestBytes { get; init; } = 6L * 1024 * 1024;

    /// <summary>
    /// Bounds for the <c>multipart/form-data</c> inspection pass, bound from
    /// <c>Gateway:Multipart</c>.
    /// </summary>
    /// <remarks>
    /// Nested under <c>Gateway</c> rather than promoted to a sibling top-level section on purpose.
    /// <see cref="MaximumRequestBytes"/> is the ceiling every multipart bound is measured against —
    /// the buffered body can never exceed it, and <see cref="MultipartInspectionOptions.SampleBytes"/>
    /// is validated against it — so the two belong in one object an operator reads together. It is
    /// also a JSON object rather than an array, so the element-by-element array merge that
    /// <c>ValidateNoPartiallyAppliedOverlay</c> exists to catch does not apply here: an overlay that
    /// sets one multipart value leaves the rest at their shipped defaults, which is what an operator
    /// editing one line expects.
    /// </remarks>
    public MultipartInspectionOptions Multipart { get; init; } = new();
}
