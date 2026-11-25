using System.Net.NetworkInformation;
using System.Security;
using SharpPcap;
using Xunit;

namespace WPShield.NetworkSensor.Tests;

/// <summary>
/// "Check Npcap and access permissions" was true of every cause and helped with none: the operator is
/// told which one it is.
/// </summary>
public sealed class CaptureFailureTests
{
    private static Exception Make(string kind) => kind switch
    {
        "dll" => new DllNotFoundException("wpcap.dll"),
        // SharpPcap loads wpcap.dll from a type initializer: the innermost exception decides.
        "initializer" => new TypeInitializationException("SharpPcap.LibPcap.LibPcapSafeNativeMethods", new DllNotFoundException("wpcap.dll")),
        "entry-point" => new EntryPointNotFoundException("pcap_findalldevs"),
        "bad-image" => new BadImageFormatException("wpcap.dll"),
        "unauthorized" => new UnauthorizedAccessException(),
        "security" => new SecurityException(),
        "pcap-denied" => new StatisticsException("Error opening adapter: Access is denied. (5)"),
        "pcap-permission" => new StatisticsException("You don't have permission to capture on that device"),
        "pcap-other" => new StatisticsException("pcap_findalldevs failed"),
        "invalid-operation" => new InvalidOperationException("synthetic"),
        "network-information" => new NetworkInformationException(),
        "platform" => new PlatformNotSupportedException(),
        _ => throw new ArgumentOutOfRangeException(nameof(kind))
    };

    [Theory]
    [InlineData("dll", CaptureFailureReason.NpcapMissing)]
    [InlineData("initializer", CaptureFailureReason.NpcapMissing)]
    [InlineData("entry-point", CaptureFailureReason.NpcapIncompatible)]
    [InlineData("bad-image", CaptureFailureReason.NpcapIncompatible)]
    [InlineData("unauthorized", CaptureFailureReason.AccessDenied)]
    [InlineData("security", CaptureFailureReason.AccessDenied)]
    [InlineData("pcap-denied", CaptureFailureReason.AccessDenied)]
    [InlineData("pcap-permission", CaptureFailureReason.AccessDenied)]
    [InlineData("pcap-other", CaptureFailureReason.Other)]
    [InlineData("invalid-operation", CaptureFailureReason.Other)]
    [InlineData("network-information", CaptureFailureReason.Other)]
    [InlineData("platform", CaptureFailureReason.Other)]
    public void EachCauseIsNamedAndEachIsACaptureFailure(string kind, CaptureFailureReason reason)
    {
        var exception = Make(kind);
        Assert.True(CaptureFailure.IsCaptureFailure(exception));
        Assert.Equal(reason, CaptureFailure.Classify(exception));
    }

    [Fact]
    public void ABugIsNotACaptureFailure()
    {
        Assert.False(CaptureFailure.IsCaptureFailure(new NullReferenceException()));
        Assert.False(CaptureFailure.IsCaptureFailure(new ArgumentException("synthetic")));
    }

    [Fact]
    public void AMissingNpcapSaysWhatNeedsItAndThatInstallingItIsTheOperatorsCall()
    {
        var text = CaptureFailure.Describe(new DllNotFoundException("wpcap.dll"));

        Assert.Contains("Npcap is not installed", text, StringComparison.Ordinal);
        Assert.Contains("needed only for traffic capture", text, StringComparison.Ordinal);
        Assert.Contains("Attacks, evidence, decisions and the audit do not use it", text, StringComparison.Ordinal);
        Assert.Contains("operator's decision", text, StringComparison.Ordinal);
        Assert.Contains("license", text, StringComparison.Ordinal);
        Assert.DoesNotContain("http", text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void AnUnknownCauseShowsTheTypeNameAndNeverTheNativeMessage()
    {
        var exception = new StatisticsException("adapter \u001b[31mred\u001b[0m\r\nforged line");

        var text = CaptureFailure.Describe(exception);

        Assert.Equal("StatisticsException", CaptureFailure.TypeName(exception));
        Assert.Contains("(StatisticsException)", text, StringComparison.Ordinal);
        Assert.DoesNotContain("forged", text, StringComparison.Ordinal);
        Assert.DoesNotContain('\u001b', text);
        Assert.DoesNotContain('\n', text);
    }
}
