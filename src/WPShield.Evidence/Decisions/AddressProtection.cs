using System.Net;

namespace WPShield.Evidence.Decisions;

/// <summary>Whether an address or network holds a Remote Desktop session, or whether nobody could tell.</summary>
public enum RemoteDesktopState
{
    NotConnected,
    Connected,

    /// <summary>The connection table or the listener's port could not be read. Refuses the decision.</summary>
    Unknown
}

/// <summary>
/// The remote addresses of the established TCP connections to the host's Remote Desktop port, read once,
/// or why they could not be read.
/// </summary>
public sealed record RemoteDesktopSnapshot(IReadOnlyCollection<IPAddress>? Clients, string? Problem)
{
    public static RemoteDesktopSnapshot Of(IEnumerable<IPAddress> clients) =>
        new(clients.Select(AddressRanges.Canonical).Distinct().ToArray(), null);

    public static RemoteDesktopSnapshot Unreadable(string problem) => new(null, problem);

    public RemoteDesktopState For(IPNetwork target) =>
        Clients is null ? RemoteDesktopState.Unknown
        : Clients.Any(target.Contains) ? RemoteDesktopState.Connected
        : RemoteDesktopState.NotConnected;
}

/// <summary>What the engine may do about a target that triggered a rule.</summary>
public enum ProtectionVerdict
{
    /// <summary>Nothing protects it: decide.</summary>
    Decide,

    /// <summary>The target is one the engine never decides against. Recorded as <c>protected</c>.</summary>
    Protected,

    /// <summary>A fact needed to decide could not be read. Recorded as <c>refused</c>.</summary>
    Refused
}

public sealed record Protection(ProtectionVerdict Verdict, string? Reason)
{
    public static readonly Protection None = new(ProtectionVerdict.Decide, null);
}

/// <summary>
/// The addresses the engine never decides against (ADR 0009, section 4), as one check. The host-specific
/// facts - the host's own addresses and its Remote Desktop clients - are injected, so the rules are
/// tested anywhere and the Windows readers live with the other Windows code.
/// </summary>
/// <remarks>
/// <para>
/// A network target is protected when <b>any</b> address in it would be: a /24 that contains the host's
/// own address, an allow-listed address or a Remote Desktop client is never decided against as a whole.
/// </para>
/// <para>
/// A fact that cannot be read refuses the decision. "Nobody could look" is not "nobody is connected":
/// deciding against an address whose Remote Desktop session nobody could see is how an administrator
/// locks themselves out of the session they would fix it from.
/// </para>
/// </remarks>
/// <param name="hostAddresses">The host's own unicast addresses, or <see langword="null"/> when they could not be read.</param>
/// <param name="remoteDesktop">The established connections to the Remote Desktop port, read once per evaluation.</param>
public sealed class AddressProtection(Func<IReadOnlyCollection<IPAddress>?> hostAddresses, Func<RemoteDesktopSnapshot> remoteDesktop)
{
    private readonly Func<IReadOnlyCollection<IPAddress>?> hostAddresses = hostAddresses ?? throw new ArgumentNullException(nameof(hostAddresses));
    private readonly Func<RemoteDesktopSnapshot> remoteDesktop = remoteDesktop ?? throw new ArgumentNullException(nameof(remoteDesktop));

    /// <summary>
    /// Starts one evaluation. The host's addresses and the Remote Desktop table are read at most once per
    /// evaluation, and only if a rule fired: most batches decide nothing and read nothing.
    /// </summary>
    public Pass Begin(DefenseOptions options) => new(this, options ?? throw new ArgumentNullException(nameof(options)));

    public sealed class Pass
    {
        private readonly AddressProtection owner;
        private readonly DefenseOptions options;
        private bool hostRead;
        private IReadOnlyCollection<IPAddress>? host;
        private RemoteDesktopSnapshot? sessions;

        internal Pass(AddressProtection owner, DefenseOptions options)
        {
            this.owner = owner;
            this.options = options;
        }

        public Protection Check(IPNetwork target)
        {
            foreach (var allowed in options.Allow)
                if (AddressRanges.Overlaps(allowed, target))
                    return new(ProtectionVerdict.Protected, $"on the allow-list ({AddressRanges.Text(allowed)})");

            if (AddressRanges.SpecialKind(target) is { } kind) return new(ProtectionVerdict.Protected, kind);

            if (!options.IncludePrivate && AddressRanges.PrivateRangeOf(target) is { } range)
                return new(ProtectionVerdict.Protected, $"in the private range {range} (defense.include_private is false)");

            var own = Host();
            if (own is null)
                return new(ProtectionVerdict.Refused, "the host's own addresses could not be read");
            if (own.Any(target.Contains))
                return new(ProtectionVerdict.Protected, target.PrefixLength is 32 or 128 ? "an address of this host" : "contains an address of this host");

            sessions ??= ReadSessions();
            return sessions.For(target) switch
            {
                RemoteDesktopState.Connected => new(ProtectionVerdict.Protected, "holds a Remote Desktop session"),
                // Short on purpose: a reason is stored at most 200 characters, and the trigger comes first.
                RemoteDesktopState.Unknown => new(ProtectionVerdict.Refused,
                    $"the Remote Desktop connections could not be read ({EvidenceText.Clean(sessions.Problem, 24)})"),
                _ => Protection.None
            };
        }

        private IReadOnlyCollection<IPAddress>? Host()
        {
            if (hostRead) return host;
            hostRead = true;
            try
            {
                host = owner.hostAddresses()?.Select(AddressRanges.Canonical).ToArray();
            }
            catch (Exception exception) when (exception is not OutOfMemoryException)
            {
                host = null;
            }
            return host;
        }

        private RemoteDesktopSnapshot ReadSessions()
        {
            try
            {
                return owner.remoteDesktop() ?? RemoteDesktopSnapshot.Unreadable("no-answer");
            }
            catch (Exception exception) when (exception is not OutOfMemoryException)
            {
                return RemoteDesktopSnapshot.Unreadable(exception.GetType().Name);
            }
        }
    }
}
