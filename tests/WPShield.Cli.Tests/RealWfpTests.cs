using System.Security.Principal;
using WPShield.Cli;
using WPShield.NetworkFilter;
using WPShield.NetworkFilter.Tests.Support;

namespace WPShield.Cli.Tests;

public sealed class RealWfpTests
{
    [ElevatedWindowsFact]
    public void DynamicWfpSessionEnumeratesAndDeletesBothAddressFamilies()
    {
        using var output = new StringWriter();
        var exitCode = NetworkFilterCommand.Run(CliOptions.Parse(["--check", "--allow", "192.0.2.0/24"]), output);
        Assert.True(exitCode == 0, output.ToString());

        using var session = WfpSession.Open();

        var range = Ranges.Block("2001:db8:abcd::/48");
        var id = session.Add(range);
        Assert.True(session.Contains(id, range));
        session.Delete(id);
        Assert.False(session.Contains(id, range));
    }

    private sealed class ElevatedWindowsFactAttribute : FactAttribute
    {
        public ElevatedWindowsFactAttribute()
        {
            if (!OperatingSystem.IsWindows())
            {
                Skip = "Windows Filtering Platform requires Windows.";
                return;
            }

            using var identity = WindowsIdentity.GetCurrent();
            if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
            {
                Skip = "WFP integration requires an elevated Windows Administrator.";
            }
        }
    }
}
