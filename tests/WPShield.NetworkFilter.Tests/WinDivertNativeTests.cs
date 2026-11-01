using System.Reflection;
using System.Runtime.InteropServices;
using WPShield.NetworkFilter.Native;

namespace WPShield.NetworkFilter.Tests;

/// <summary>
/// The interop is checked against windivert.h, because the 2026-10-20 declarations compiled, passed
/// every test, and could not have worked: the address struct was 8 bytes where the driver writes 80.
/// </summary>
public sealed class WinDivertNativeTests
{
    private static IReadOnlyList<MethodInfo> Imports =>
        [
            .. typeof(WinDivertNative).Assembly.GetTypes()
                .SelectMany(type => type.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static))
                .Where(method => (method.Attributes & MethodAttributes.PinvokeImpl) != 0),
        ];

    [Fact]
    public void TheAddressStruct_IsTheEightyBytesTheDriverWrites()
    {
        Assert.Equal(80, Marshal.SizeOf<WinDivertAddress>());
        Assert.Equal(WinDivertAddress.Size, Marshal.SizeOf<WinDivertAddress>());
    }

    [Fact]
    public void FlagValues_MatchWindivertH()
    {
        Assert.Equal(0x0001UL, WinDivertNative.FlagSniff);
        Assert.Equal(0x0002UL, WinDivertNative.FlagDrop);
        Assert.Equal(0x0004UL, WinDivertNative.FlagRecvOnly);
        Assert.Equal(0x0010UL, WinDivertNative.FlagNoInstall);
        Assert.Equal(40 + 0xFFFF, WinDivertNative.MtuMax);
        Assert.Equal(256, WinDivertNative.FilterMaxObjects);
    }

    [Fact]
    public void EveryImport_ResolvesWinDivertFromTheAssemblyDirectoryOnly()
    {
        Assert.NotEmpty(Imports);
        foreach (var method in Imports)
        {
            var searchPaths = method.GetCustomAttribute<DefaultDllImportSearchPathsAttribute>();
            Assert.True(searchPaths is not null, $"{method.Name} has no DefaultDllImportSearchPaths");
            Assert.Equal(DllImportSearchPath.AssemblyDirectory, searchPaths!.Paths);
        }
    }

    [Fact]
    public void NoImport_CanReinjectAPacket()
    {
        Assert.DoesNotContain(Imports, method => method.Name.StartsWith("WinDivertSend", StringComparison.Ordinal));
    }

    [Fact]
    public void TheInboundAddress_DescribesAnInboundNetworkLayerPacket()
    {
        var v4 = WinDivertAddress.InboundNetwork(ipv6: false);
        var v6 = WinDivertAddress.InboundNetwork(ipv6: true);

        Assert.Equal(WinDivertNative.LayerNetwork, v4.Layer);
        Assert.False(v4.Outbound);
        Assert.False(v4.Loopback);
        Assert.False(v4.IsIpv6);
        Assert.True(v6.IsIpv6);
        Assert.False(v6.Outbound);
    }
}
