using System.Globalization;
using System.Net;
using System.Text;

namespace WPShield.Evidence;

/// <summary>One failed Windows authentication, as the event log recorded it.</summary>
/// <param name="Channel">
/// <c>security-4625</c> (Security log, any logon type) or <c>rdpcorets-140</c> (Remote Desktop's own
/// record of a wrong user name or password, which carries the client address when NLA left 4625
/// without one).
/// </param>
/// <param name="Address">The source address, or <see langword="null"/> when the record has none.</param>
/// <param name="Account">
/// The account name the client tried, cleaned and bounded by <see cref="EvidenceText.Clean"/>. The
/// attacker chose this text; it is evidence, never a label to trust.
/// </param>
/// <param name="Reason">A stable code: <c>unknown-account</c>, <c>bad-password</c>, <c>locked-out</c>...</param>
public sealed record AuthFailure(DateTimeOffset Timestamp, string Channel, IPAddress? Address, int? Port,
    string Account, string Reason, int? LogonType, long RecordId);

/// <summary>
/// One attempt can be recorded twice. With NLA, Windows writes 4625 without the client address and
/// Remote Desktop writes event 140 with it; without NLA both may carry the address. Every consumer
/// pairs them the same way, so the desktop, the store and an assistant count the same attempts.
/// </summary>
public static class AttemptPairing
{
    public const string SecurityChannel = "security-4625";
    public const string RdpChannel = "rdpcorets-140";
    public static readonly TimeSpan Window = TimeSpan.FromSeconds(2);

    /// <summary>
    /// How many earlier records one record is compared with. A flood of thousands of failures in the
    /// same instant would otherwise make pairing quadratic; past this bound a pair may be missed, which
    /// counts one attempt twice rather than stalling the collector.
    /// </summary>
    public const int MaxCandidates = 256;

    public static bool IsSameAttempt(AuthFailure a, AuthFailure b)
    {
        if (a.Channel == b.Channel || (a.Timestamp - b.Timestamp).Duration() > Window) return false;
        var rdp = a.Channel == RdpChannel ? a : b;
        var security = ReferenceEquals(rdp, a) ? b : a;
        // NLA: 4625 type 3 without an address, 140 with it. Otherwise both name the same address.
        return security.Address is null ? security.LogonType == 3 : security.Address.Equals(rdp.Address);
    }

    /// <summary>
    /// Of a pair, the record with the address survives; when both carry it, the 4625 does, because it
    /// also names the account.
    /// </summary>
    public static bool KeepIncoming(AuthFailure incoming, AuthFailure partner)
    {
        var incomingIsSecurity = incoming.Channel == SecurityChannel;
        var security = incomingIsSecurity ? incoming : partner;
        return incomingIsSecurity ? security.Address is not null : security.Address is null;
    }

    /// <summary>Pairs a time-ordered batch one to one and returns the survivors in time order.</summary>
    public static IReadOnlyList<AuthFailure> Pair(IEnumerable<AuthFailure> failures)
    {
        var kept = new List<AuthFailure>();
        foreach (var failure in failures.OrderBy(f => f.Timestamp))
        {
            var partner = -1;
            for (var i = kept.Count - 1; i >= 0 && i >= kept.Count - MaxCandidates && failure.Timestamp - kept[i].Timestamp <= Window; i--)
            {
                if (IsSameAttempt(kept[i], failure)) { partner = i; break; }
            }
            if (partner < 0) { kept.Add(failure); continue; }
            if (!KeepIncoming(failure, kept[partner])) continue;
            kept.RemoveAt(partner);
            kept.Add(failure);
        }
        return kept;
    }
}

/// <summary>
/// Holds live records long enough for their partner to arrive from the other channel, then releases
/// them paired. A batch boundary must not split a pair, or the attempt is counted twice.
/// </summary>
public sealed class PairingBuffer
{
    public const int MaxHeld = 100_000;
    private readonly List<AuthFailure> held = [];
    private readonly object gate = new();

    /// <summary>Records dropped because the buffer was full; a writer that stalls must not grow memory.</summary>
    public long Dropped { get; private set; }

    public void Add(AuthFailure failure)
    {
        lock (gate)
        {
            if (held.Count >= MaxHeld) { Dropped++; return; }
            held.Add(failure);
        }
    }

    /// <summary>
    /// Returns, paired, every record older than twice the pairing window, and keeps the rest; with
    /// <paramref name="flushAll"/>, returns everything (on shutdown).
    /// </summary>
    public IReadOnlyList<AuthFailure> TakeReady(DateTimeOffset now, bool flushAll = false)
    {
        lock (gate)
        {
            if (held.Count == 0) return [];
            var paired = AttemptPairing.Pair(held);
            var cutoff = now - 2 * AttemptPairing.Window;
            var ready = flushAll ? paired : paired.Where(f => f.Timestamp < cutoff).ToList();
            held.Clear();
            if (!flushAll) held.AddRange(paired.Where(f => f.Timestamp >= cutoff));
            return ready;
        }
    }
}

/// <summary>Attacker-chosen text, made safe to store and to show.</summary>
public static class EvidenceText
{
    public const int MaxAccountLength = 64;

    /// <summary>
    /// Replaces control, format and unassigned characters with U+FFFD and bounds the length. Letters,
    /// accented ones included, are kept: a Spanish Windows really has an account named "Administrador".
    /// </summary>
    public static string Clean(string? text, int max = MaxAccountLength)
    {
        if (string.IsNullOrEmpty(text) || text == "-") return "";
        var builder = new StringBuilder(Math.Min(text.Length, max));
        foreach (var rune in text.EnumerateRunes())
        {
            if (builder.Length >= max) break;
            var category = Rune.GetUnicodeCategory(rune);
            builder.Append(category is UnicodeCategory.Control or UnicodeCategory.Format or UnicodeCategory.LineSeparator
                or UnicodeCategory.ParagraphSeparator or UnicodeCategory.Surrogate or UnicodeCategory.PrivateUse
                or UnicodeCategory.OtherNotAssigned ? "�" : rune.ToString());
        }
        return builder.ToString();
    }
}
