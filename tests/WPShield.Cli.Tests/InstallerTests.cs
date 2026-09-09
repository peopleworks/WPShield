using System.Security.AccessControl;
using System.Security.Principal;
using WPShield.Cli.Install;
using WPShield.Cli.Preflight;

namespace WPShield.Cli.Tests;

/// <summary>
/// The verbs that change the machine, and the order they change it in.
/// </summary>
/// <remarks>
/// The PowerShell installer could be checked for these properties only by reading it. That is how it
/// shipped able to throw between registering the service and restricting the directories, leaving the
/// gateway running as <c>LocalSystem</c> with an evidence log readable by every account on a
/// sixty-six-site server — while every summary it had printed said otherwise.
/// </remarks>
public sealed class InstallerTests
{
    private const string Source = @"C:\staging\wpshield";

    // =============================================================================================
    //  The guards, and that they run before anything is touched.
    // =============================================================================================

    [Fact]
    public void AnInstallPathInsideAServedDirectory_IsRefusedBeforeAnythingIsTouched()
    {
        var environment = Ready();
        environment.Served.Add(@"C:\inetpub\wwwroot");

        var exception = Assert.Throws<CliArgumentException>(
            () => Install(environment, o => o with { InstallPath = @"C:\inetpub\wwwroot\WPShield" }));

        Assert.Contains("refuses to be", exception.Message, StringComparison.Ordinal);
        Assert.Contains("Nothing was changed", exception.Message, StringComparison.Ordinal);
        Assert.Empty(environment.Mutations);
    }

    [Fact]
    public void ALogPathInsideAServedDirectory_IsRefused()
    {
        var environment = Ready();
        environment.Served.Add(@"C:\inetpub\wwwroot");

        Assert.Throws<CliArgumentException>(
            () => Install(environment, o => o with { LogPath = @"C:\inetpub\wwwroot\WPShield\logs" }));

        Assert.Empty(environment.Mutations);
    }

    [Fact]
    public void TheWebRootRefusal_CanBeOverriddenExplicitly()
    {
        var environment = Ready();
        environment.Served.Add(@"C:\inetpub\wwwroot");

        Install(environment, o => o with
        {
            InstallPath = @"C:\inetpub\wwwroot\WPShield",
            AllowWebRootPaths = true
        });

        Assert.NotEmpty(environment.Mutations);
        Assert.Contains(environment.Lines, line => line.Contains("--allow-web-root-paths", StringComparison.Ordinal));
    }

    [Fact]
    public void ASourceWithoutTheGatewayExecutable_IsRefused()
    {
        var environment = Ready();
        environment.Files.Remove(Path.Combine(Source, "WPShield.Gateway.exe"));

        var exception = Assert.Throws<CliArgumentException>(() => Install(environment));

        Assert.Contains("does not look like a WPShield build", exception.Message, StringComparison.Ordinal);
        Assert.Empty(environment.Mutations);
    }

    [Fact]
    public void ARealRunWithoutElevation_IsRefusedBeforeAnythingIsTouched()
    {
        var environment = Ready();
        environment.IsElevated = false;

        Assert.Throws<CliArgumentException>(() => Install(environment));
        Assert.Empty(environment.Mutations);
    }

    /// <summary>
    /// A dry run does not require elevation, and refusing it there would be the wrong trade: the
    /// point of a preview is that an operator can read what a tool intends before deciding to let it.
    /// </summary>
    [Fact]
    public void ADryRunDoesNotRequireElevationAndChangesNothing()
    {
        var environment = Ready();
        environment.IsElevated = false;

        Install(environment, o => o with { DryRun = true });

        Assert.Empty(environment.Mutations);
        Assert.Contains(environment.Lines, line => line.Contains("nothing above was actually done", StringComparison.Ordinal));
    }

    [Fact]
    public void ADryRunAnnouncesEveryStepItWouldTake()
    {
        var environment = Ready();

        Install(environment, o => o with { DryRun = true });

        var announced = environment.Lines.Where(line => line.StartsWith("would ", StringComparison.Ordinal)).ToArray();
        Assert.Contains(announced, line => line.Contains("create the Windows service", StringComparison.Ordinal));
        Assert.Contains(announced, line => line.Contains("set the service identity", StringComparison.Ordinal));
        Assert.Contains(announced, line => line.Contains("replace the permissions", StringComparison.Ordinal));
    }

    // =============================================================================================
    //  The order. This is the defect, asserted.
    // =============================================================================================

    [Fact]
    public void TheServiceSidIsEnabledBeforeTheDirectoriesAreHardened()
    {
        var environment = Ready();

        Install(environment);

        var sid = environment.Mutations.IndexOf("EnableServiceSid");
        var harden = environment.Mutations.IndexOf("HardenDirectory:C:\\Program Files\\WPShield");

        Assert.True(sid >= 0 && harden >= 0, string.Join(", ", environment.Mutations));
        Assert.True(
            sid < harden,
            "The per-service SID has to exist before it can be named in an ACL. Hardening first would grant nothing.");
    }

    [Fact]
    public void TheIdentityIsSetBeforeTheDirectoriesAreHardened()
    {
        var environment = Ready();

        Install(environment);

        Assert.True(
            environment.Mutations.IndexOf("SetServiceIdentity") <
            environment.Mutations.IndexOf("HardenDirectory:C:\\ProgramData\\WPShield\\logs"));
    }

    /// <summary>
    /// The copy replaces <c>appsettings.json</c>, so writing the log directory into it has to come
    /// after. Doing it before would be overwritten and silently lost.
    /// </summary>
    [Fact]
    public void TheLogDirectoryIsWrittenIntoTheConfigurationAfterTheCopy()
    {
        var environment = Ready();

        Install(environment);

        Assert.True(environment.Mutations.IndexOf("CopyTree") < environment.Mutations.IndexOf("SetLogDirectory"));
    }

    [Fact]
    public void BothDirectoriesAreHardened()
    {
        var environment = Ready();

        Install(environment);

        Assert.Contains(@"HardenDirectory:C:\Program Files\WPShield", environment.Mutations);
        Assert.Contains(@"HardenDirectory:C:\ProgramData\WPShield\logs", environment.Mutations);
    }

    /// <summary>
    /// A gateway that can overwrite its own executable is a persistence mechanism waiting for a bug.
    /// </summary>
    [Fact]
    public void TheServiceGetsReadAndExecuteOnTheProgramFilesAndModifyOnTheLogs()
    {
        var environment = Ready();

        Install(environment);

        Assert.Equal(FileSystemRights.ReadAndExecute, environment.Rights[@"C:\Program Files\WPShield"]);
        Assert.Equal(FileSystemRights.Modify, environment.Rights[@"C:\ProgramData\WPShield\logs"]);
    }

    [Fact]
    public void TheServiceIsNotStartedUnlessAsked()
    {
        var environment = Ready();

        Install(environment);

        Assert.DoesNotContain("StartService", environment.Mutations);
    }

    /// <summary>
    /// A gateway with no site configuration resolves no host, so starting it proves nothing.
    /// </summary>
    [Fact]
    public void StartIsSkippedWhenThereIsNoOperatorConfiguration()
    {
        var environment = Ready();

        Install(environment, o => o with { Start = true });

        Assert.DoesNotContain("StartService", environment.Mutations);
        Assert.Contains(environment.Lines, line => line.Contains("no real site to resolve", StringComparison.Ordinal));
    }

    [Fact]
    public void TheClosingNotesDoNotAskForAConfigurationThatWasJustInstalled()
    {
        var environment = Ready();
        environment.Files.Add(@"C:\staging\config.json");

        Install(environment, o => o with { ConfigurationPath = @"C:\staging\config.json" });

        Assert.DoesNotContain(environment.Lines, line => line.Contains("Put appsettings.Local.json in place", StringComparison.Ordinal));
        Assert.Contains(environment.Lines, line => line.Contains("Read back the site table", StringComparison.Ordinal));
    }

    // =============================================================================================
    //  Uninstall. The guard that keeps a rollback from becoming an outage.
    // =============================================================================================

    [Fact]
    public void UninstallRefusesWhileAWPShieldRewriteRuleStillExists()
    {
        var environment = Ready();
        environment.IisReadable = true;
        environment.Rules.Add("peopleworksgpt/WPShield");

        var exception = Assert.Throws<CliArgumentException>(() => Uninstall(environment));

        Assert.Contains("takes", exception.Message, StringComparison.Ordinal);
        Assert.Contains("Nothing was changed", exception.Message, StringComparison.Ordinal);
        Assert.Empty(environment.Mutations);
    }

    /// <summary>
    /// Not finding a rule is not the same as there being none. An unreadable IIS refuses just as hard,
    /// because collapsing the two turns "could not check" into "checked and fine".
    /// </summary>
    [Fact]
    public void UninstallRefusesJustAsHardWhenIisCannotBeRead()
    {
        var environment = Ready();
        environment.IisReadable = false;

        var exception = Assert.Throws<CliArgumentException>(() => Uninstall(environment));

        Assert.Contains("not the same as there being none", exception.Message, StringComparison.Ordinal);
        Assert.Empty(environment.Mutations);
    }

    [Fact]
    public void UninstallProceedsWhenNothingForwardsToTheGateway()
    {
        var environment = Ready();
        environment.IisReadable = true;

        Uninstall(environment);

        Assert.Contains("DeleteService", environment.Mutations);
    }

    [Fact]
    public void ForceOverridesTheGuardAndSaysSo()
    {
        var environment = Ready();
        environment.IisReadable = true;
        environment.Rules.Add("peopleworksgpt/WPShield");

        Uninstall(environment, o => o with { Force = true });

        Assert.Contains("DeleteService", environment.Mutations);
        Assert.Contains(environment.Lines, line => line.Contains("--force was given", StringComparison.Ordinal));
    }

    /// <summary>
    /// The log is the record of what the gateway saw, and an uninstall during an incident is the
    /// worst moment to delete evidence.
    /// </summary>
    [Fact]
    public void LogsAreKeptUnlessExplicitlyAskedFor()
    {
        var environment = Ready();
        environment.IisReadable = true;
        environment.Directories.Add(@"C:\ProgramData\WPShield\logs");

        Uninstall(environment);

        Assert.DoesNotContain(@"DeleteDirectory:C:\ProgramData\WPShield\logs", environment.Mutations);
        Assert.Contains(environment.Lines, line => line.Contains("--remove-logs", StringComparison.Ordinal));
    }

    /// <summary>
    /// <c>--install-path</c> takes an arbitrary path, and a recursive delete pointed at the wrong one
    /// is unrecoverable.
    /// </summary>
    [Fact]
    public void UninstallRefusesToDeleteADirectoryThatIsNotAnInstallation()
    {
        var environment = Ready();
        environment.IisReadable = true;
        environment.Directories.Add(@"D:\important");

        var exception = Assert.Throws<CliArgumentException>(
            () => Uninstall(environment, o => o with { InstallPath = @"D:\important", RemoveFiles = true }));

        Assert.Contains("not a WPShield installation", exception.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(environment.Mutations, entry => entry.StartsWith("DeleteDirectory", StringComparison.Ordinal));
    }

    [Fact]
    public void AnUninstallDryRunChangesNothing()
    {
        var environment = Ready();
        environment.IisReadable = true;

        Uninstall(environment, o => o with { DryRun = true, RemoveFiles = true, RemoveLogs = true });

        Assert.Empty(environment.Mutations);
    }

    // =============================================================================================
    //  Helpers.
    // =============================================================================================

    private static void Install(FakeEnvironment environment, Func<InstallOptions, InstallOptions>? adjust = null)
    {
        var options = new InstallOptions { SourcePath = Source };
        new Installer(environment, adjust is null ? options : adjust(options)).Run();
    }

    private static void Uninstall(FakeEnvironment environment, Func<UninstallOptions, UninstallOptions>? adjust = null)
    {
        environment.ServiceInstalled = true;
        var options = new UninstallOptions();
        new Uninstaller(environment, adjust is null ? options : adjust(options)).Run();
    }

    private static FakeEnvironment Ready()
    {
        var environment = new FakeEnvironment();
        environment.Files.Add(Path.Combine(Source, "WPShield.Gateway.exe"));
        environment.Directories.Add(Source);
        return environment;
    }

    /// <summary>Records what would be done, in order, and does none of it.</summary>
    private sealed class FakeEnvironment : IInstallEnvironment
    {
        public bool IsElevated { get; set; } = true;
        public bool IisReadable { get; set; } = true;

        /// <summary>A fresh host has none; the uninstall tests turn it on.</summary>
        public bool ServiceInstalled { get; set; }

        public List<string> Mutations { get; } = [];
        public List<string> Lines { get; } = [];
        public HashSet<string> Files { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> Directories { get; } = new(StringComparer.OrdinalIgnoreCase);
        public List<string> Served { get; } = [];
        public List<string> Rules { get; } = [];
        public Dictionary<string, FileSystemRights> Rights { get; } = new(StringComparer.OrdinalIgnoreCase);

        public bool DirectoryExists(string path) => Directories.Contains(path);
        public bool FileExists(string path) => Files.Contains(path);
        public IReadOnlyList<string> ChildDirectories(string path) => [];

        public void CreateDirectory(string path)
        {
            Mutations.Add($"CreateDirectory:{path}");
            Directories.Add(path);
        }

        public void CopyTree(string source, string destination) => Mutations.Add("CopyTree");
        public void CopyFile(string source, string destination) => Mutations.Add($"CopyFile:{destination}");
        public int CountFiles(string path) => 350;
        public void DeleteDirectory(string path) => Mutations.Add($"DeleteDirectory:{path}");
        public void SetLogDirectory(string settingsFile, string logDirectory) => Mutations.Add("SetLogDirectory");

        public void HardenDirectory(string path, FileSystemRights serviceRights, SecurityIdentifier serviceSid)
        {
            Mutations.Add($"HardenDirectory:{path}");
            Rights[path] = serviceRights;
        }

        public IReadOnlyList<string> BroadAccess(string path) => [];

        public InstalledService? QueryService(string name) =>
            ServiceInstalled ? new InstalledService("Stopped", @"NT SERVICE\WPShield", null) : null;

        public void StopService(string name) => Mutations.Add("StopService");
        public void StartService(string name) => Mutations.Add("StartService");
        public void CreateService(string a, string b, string c, string d) => Mutations.Add("CreateService");
        public void DeleteService(string name) => Mutations.Add("DeleteService");
        public void SetServiceBinaryPath(string a, string b) => Mutations.Add("SetServiceBinaryPath");
        public void EnableServiceSid(string name) => Mutations.Add("EnableServiceSid");
        public void SetServiceIdentity(string a, string b) => Mutations.Add("SetServiceIdentity");
        public void ConfigureServiceRecovery(string name) => Mutations.Add("ConfigureServiceRecovery");

        public SecurityIdentifier ResolveServiceSid(string name) =>
            new(WellKnownSidType.LocalServiceSid, null);

        public IReadOnlyList<string> ServedDirectories() => Served;

        public (bool Readable, IReadOnlyList<string> Rules) WPShieldRewriteRules() => (IisReadable, Rules);

        public void Report(string line) => Lines.Add(line);
    }
}
