namespace WPShield.Cli.Tests.Setup;

/// <summary>
/// Where <c>setup</c> decides to write, and the rule that a preview must be reachable before the
/// thing it previews.
/// </summary>
public sealed class SetupCommandTests
{
    [Fact]
    public void An_installed_gateway_decides_where_the_site_table_lives()
    {
        var report = new InstallationReport { ServiceInstalled = true, InstallDirectory = @"D:\Tools\WPShield" };

        Assert.Equal(@"D:\Tools\WPShield", SetupCommand.ResolveInstallDirectory(report, dryRun: false));
        Assert.Equal(@"D:\Tools\WPShield", SetupCommand.ResolveInstallDirectory(report, dryRun: true));
    }

    /// <summary>
    /// Found by running the verb on a machine with nothing installed: the dry run refused, which is
    /// backwards. A preview is most wanted before the install, and the installer already states the
    /// principle for its own - requiring more to read what a tool intends than to let it act makes
    /// the preview harder to reach than the thing it previews.
    /// </summary>
    [Fact]
    public void A_dry_run_works_with_nothing_installed_and_assumes_the_default_path()
    {
        var report = new InstallationReport { ServiceInstalled = false };

        Assert.Equal(
            Install.Installer.DefaultInstallPath,
            SetupCommand.ResolveInstallDirectory(report, dryRun: true));
    }

    [Fact]
    public void A_real_run_with_nothing_installed_refuses_and_points_at_the_dry_run()
    {
        var report = new InstallationReport { ServiceInstalled = false };

        var failure = Assert.Throws<CliArgumentException>(
            () => SetupCommand.ResolveInstallDirectory(report, dryRun: false));

        Assert.Contains("wpshield install --path", failure.Message);
        Assert.Contains("--dry-run", failure.Message);
    }

    /// <summary>The default an install lands on and a preview assumes must be the same string.</summary>
    [Fact]
    public void The_installer_default_and_the_preview_assumption_are_one_constant()
    {
        Assert.Equal(Install.Installer.DefaultInstallPath, new Install.InstallOptions { SourcePath = "x" }.InstallPath);
    }
}
