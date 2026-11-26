using WPShield.Cli.Host;
using WPShield.Evidence;
using Xunit;

namespace WPShield.Cli.Tests;

/// <summary>
/// The owner of a listener, named even when its process refuses to be opened (ADR 0013, section 1.1, as built): the
/// kernel's image name is used only when its device maps to a drive, and anything else stays unknown, which keeps every
/// program rule - the open direction. Synthetic paths only.
/// </summary>
public sealed class ProcessImagePathTests
{
    private const string Database = @"C:\Program Files\SyntheticDb\bin\syntheticdb.exe";
    private const string DatabaseDevice = @"\Device\HarddiskVolume3\Program Files\SyntheticDb\bin\syntheticdb.exe";

    private static readonly ProcessImagePath.DosDevice[] Devices =
    [
        new("C:", @"\Device\HarddiskVolume3"),
        new("D:", @"\Device\HarddiskVolume1"),
    ];

    [Fact]
    public void ADevicePathMapsToItsDriveOnASeparatorBoundaryOnly()
    {
        Assert.Equal(Database, ProcessImagePath.ToDosPath(DatabaseDevice, Devices));
        Assert.Equal(@"D:\Tools\x.exe", ProcessImagePath.ToDosPath(@"\device\harddiskvolume1\Tools\x.exe", Devices));
        // HarddiskVolume1 is not a prefix of HarddiskVolume10.
        Assert.Null(ProcessImagePath.ToDosPath(@"\Device\HarddiskVolume10\Tools\x.exe", Devices));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(@"\Device\HarddiskVolume3")]
    [InlineData(@"\Device\HarddiskVolume3\")]
    [InlineData(@"\Device\Mup\files.example\share\x.exe")]
    [InlineData(@"syntheticdb.exe")]
    public void APathNoDriveMapsIsUnknownNeverARawDevicePath(string? devicePath)
    {
        Assert.Null(ProcessImagePath.ToDosPath(devicePath, Devices));
        Assert.Null(ProcessImagePath.ToDosPath(DatabaseDevice, []));
    }

    [Fact]
    public void TheKernelNameIsAskedForOnlyWhenTheProcessRefusesToBeOpened()
    {
        var kernelAsked = 0;
        var drivesAsked = 0;
        string? Kernel(uint _) { kernelAsked++; return DatabaseDevice; }
        IReadOnlyList<ProcessImagePath.DosDevice> Drives() { drivesAsked++; return Devices; }

        Assert.Equal(@"C:\Opened\app.exe", ProcessImagePath.Read(812, _ => @"C:\Opened\app.exe", Kernel, Drives));
        Assert.Equal((0, 0), (kernelAsked, drivesAsked));

        Assert.Equal(Database, ProcessImagePath.Read(812, _ => null, Kernel, Drives));
        Assert.Equal((1, 1), (kernelAsked, drivesAsked));
    }

    [Fact]
    public void TheKernelProcessIsSystemAndAnUnnamedOwnerIsUnknown()
    {
        Assert.Equal("System", ProcessImagePath.Read(4, _ => null, _ => null, () => Devices));
        Assert.Null(ProcessImagePath.Read(0, _ => Database, _ => DatabaseDevice, () => Devices));
        Assert.Null(ProcessImagePath.Read(812, _ => null, _ => null, () => Devices));
        Assert.Null(ProcessImagePath.Read(812, _ => null, _ => @"\Device\HarddiskVolume9\x.exe", () => Devices));
    }

    [Fact]
    public void OnThisMachineTheKernelNameReadsTheSamePathAsTheProcessItself()
    {
        var self = (uint)Environment.ProcessId;
        var opened = ProcessImagePath.Open(self);
        Assert.NotNull(opened);

        var mapped = ProcessImagePath.ToDosPath(ProcessImagePath.KernelImageName(self), ProcessImagePath.DosDevices());

        // The firewall compares a rule's program with this string, so both ways must yield the same form.
        Assert.Equal(opened, mapped, StringComparer.OrdinalIgnoreCase);
        Assert.Null(ProcessImagePath.KernelImageName(0));
        Assert.Null(ProcessImagePath.KernelImageName(uint.MaxValue - 3));
    }

    [Fact]
    public void ANamedDatabaseOwnerLeavesOnlyThePortRulesThatOpenIt()
    {
        // An app-container rule and a program rule on any port, a program rule for a service host on a port range, and
        // the port rule an operator restricts.
        var policy = new FirewallPolicy(4, 0, 0,
        [
            new(true, true, true, ExposureVerdicts.ProtocolAny, null, "*", 7, null, "Synthetic packaged app", AppPackage: "S-1-15-2-1"),
            new(true, true, true, ExposureVerdicts.ProtocolTcp, "*", "*", 7, @"C:\Windows\System32\synthetic-shadow.exe", "Synthetic shadow"),
            new(true, true, true, ExposureVerdicts.ProtocolTcp, "1024-65535", "*", 7, @"C:\Windows\System32\svchost.exe", "Synthetic passive range"),
            new(true, true, true, ExposureVerdicts.ProtocolTcp, "3306", "*", 7, null, "Synthetic DB 3306"),
        ]);

        var unknown = ProcessImagePath.Read(812, _ => null, _ => @"\Device\HarddiskVolume9\x.exe", () => Devices);
        Assert.Equal(4, ExposureVerdicts.OpenedBy("TCP", 3306, "any", unknown, policy).Count);

        var named = ProcessImagePath.Read(812, _ => null, _ => DatabaseDevice, () => Devices);
        Assert.Equal(["Synthetic DB 3306"], ExposureVerdicts.OpenedBy("TCP", 3306, "any", named, policy));

        // Restricting that rule is then the whole remedy.
        var restricted = policy with { Rules = [.. policy.Rules.Take(3), policy.Rules[3] with { RemoteAddresses = "198.51.100.20" }] };
        Assert.Equal(ExposureVerdicts.Restricted, ExposureVerdicts.Classify("TCP", 3306, "any", named, restricted));
        Assert.Equal(ExposureVerdicts.OpenToAny, ExposureVerdicts.Classify("TCP", 3306, "any", unknown, restricted));
    }
}
