using System.Net.NetworkInformation;
using System.Security;
using SharpPcap;

namespace WPShield.NetworkSensor;

/// <summary>Why packet capture through Npcap could not be used.</summary>
public enum CaptureFailureReason
{
    /// <summary><c>wpcap.dll</c> could not be found: Npcap is not installed.</summary>
    NpcapMissing,

    /// <summary>Npcap is present but could not be loaded: an old or incompatible version, or the wrong architecture.</summary>
    NpcapIncompatible,

    /// <summary>Npcap, or Windows, refused access to the capture adapters.</summary>
    AccessDenied,

    /// <summary>Anything else. Reported with the exception type name only.</summary>
    Other
}

/// <summary>
/// Classifies a capture failure so the operator is told why capture is unavailable, not only that it is.
/// </summary>
/// <remarks>
/// <para>
/// "Check Npcap and access permissions" is true of every one of these causes, which is why it helps
/// with none of them: an operator who never installed Npcap reads it as a permissions problem. The
/// reason is decided from the exception's type, and from the message only to recognise a refusal -
/// the message itself is never shown, because a native library's text is not ours to put on screen.
/// What is shown for <see cref="CaptureFailureReason.Other"/> is the type name, which is an
/// identifier of this process's own types.
/// </para>
/// <para>
/// SharpPcap loads <c>wpcap.dll</c> from a type initializer, so a missing library usually arrives as
/// a <see cref="TypeInitializationException"/> around the <see cref="DllNotFoundException"/>; the
/// innermost exception decides.
/// </para>
/// </remarks>
public static class CaptureFailure
{
    /// <summary>Whether <paramref name="exception"/> is a failure of the capture source rather than a bug.</summary>
    public static bool IsCaptureFailure(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        return exception.GetBaseException() is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException
            or UnauthorizedAccessException or SecurityException
            || exception is InvalidOperationException or PcapException or NetworkInformationException
                or UnauthorizedAccessException or SecurityException or PlatformNotSupportedException;
    }

    /// <summary>The reason capture is unavailable.</summary>
    public static CaptureFailureReason Classify(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        var root = exception.GetBaseException();
        if (root is DllNotFoundException) return CaptureFailureReason.NpcapMissing;
        if (root is EntryPointNotFoundException or BadImageFormatException) return CaptureFailureReason.NpcapIncompatible;
        if (root is UnauthorizedAccessException or SecurityException || exception is UnauthorizedAccessException or SecurityException)
            return CaptureFailureReason.AccessDenied;
        var pcap = root as PcapException ?? exception as PcapException;
        if (pcap is not null && (pcap.Message.Contains("denied", StringComparison.OrdinalIgnoreCase) ||
                                 pcap.Message.Contains("permission", StringComparison.OrdinalIgnoreCase)))
            return CaptureFailureReason.AccessDenied;
        return CaptureFailureReason.Other;
    }

    /// <summary>The innermost exception's type name: safe to show, because it is never external text.</summary>
    public static string TypeName(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        return exception.GetBaseException().GetType().Name;
    }

    /// <summary>The English explanation, as the CLI prints it.</summary>
    public static string Describe(Exception exception) => Classify(exception) switch
    {
        CaptureFailureReason.NpcapMissing =>
            "Npcap is not installed on this computer, so traffic cannot be captured. Npcap is needed only for traffic capture " +
            "(network-monitor and the desktop Port traffic window); Attacks, evidence, decisions and the audit do not use it. " +
            "Installing it is the operator's decision: it adds a packet-capture driver, and its license terms for use on servers are worth checking first.",
        CaptureFailureReason.NpcapIncompatible =>
            "The Npcap installed here could not be loaded (an incompatible or outdated version, or the wrong architecture), so traffic cannot be captured. " +
            "Npcap is needed only for traffic capture.",
        CaptureFailureReason.AccessDenied =>
            "Npcap refused access to the capture adapters. If it was installed to allow administrators only, run WPShield as administrator; " +
            "otherwise check what is denying access.",
        _ => $"Cannot enumerate capture interfaces ({TypeName(exception)}). Check the Npcap installation."
    };
}
