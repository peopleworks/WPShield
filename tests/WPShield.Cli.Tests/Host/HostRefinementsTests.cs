using WPShield.Cli.Host;
using WPShield.Evidence;

namespace WPShield.Cli.Tests.Host;

/// <summary>
/// The refinements from the first real <c>wpshield host</c> run, on the CLI's side: the hotfix fallback of the patch
/// level, and a bare program name judged where Windows would find it rather than in the reader's current folder.
/// </summary>
public sealed class HostRefinementsTests : IDisposable
{
    private static readonly DateTimeOffset Now = EvidenceTestStore.Now;
    private readonly string folder = Path.Combine(Path.GetTempPath(), "wpshield-host-" + Guid.NewGuid().ToString("N"));

    public HostRefinementsTests() => Directory.CreateDirectory(folder);

    public void Dispose()
    {
        if (Directory.Exists(folder)) Directory.Delete(folder, recursive: true);
    }

    private static HostPatchLevel Patch(DateTimeOffset? lastCumulative) =>
        new("20348", 5761, "21H2", "10.0.20348.5756", true, lastCumulative is null ? null : "2026-11 Cumulative Update (KB5090001)", lastCumulative, 0);

    [Fact]
    public void TheHotfixListIsReadOnlyWhenTheUpdateLogNamesNoCumulativeUpdate()
    {
        var reads = 0;
        var known = HostHotfixReader.WithHotfix(Patch(Now.AddDays(-20)), () =>
        {
            reads++;
            return [];
        });

        Assert.Equal(0, reads);
        Assert.Null(known.HotfixListRead);
    }

    [Fact]
    public void TheNewestHotfixStandsInForAMissingCumulativeUpdate()
    {
        var patch = HostHotfixReader.WithHotfix(Patch(null), () =>
        [
            new HotfixRecord("KB5090001", "10/14/2026"),
            new HotfixRecord("KB5090002", "11/2/2026"),
            new HotfixRecord("KB5090000", "1/28/2025")
        ]);

        Assert.True(patch.HotfixListRead);
        Assert.Equal("KB5090002", patch.LastHotfixId);
        Assert.Equal(new DateTimeOffset(2026, 11, 2, 0, 0, 0, TimeSpan.Zero), patch.LastHotfixInstalledOn);
    }

    [Fact]
    public void AnUnreadableHotfixListIsUnknownNotEmpty()
    {
        var patch = HostHotfixReader.WithHotfix(Patch(null), () => null);

        Assert.False(patch.HotfixListRead);
        Assert.Null(patch.LastHotfixId);
    }

    [Fact]
    public void TheHealthReadingKeepsItsStatusWhenTheHotfixIsAdded()
    {
        var reading = HostFactReading.Of(HostFacts.Health, null, Now,
            new HostHealth(Now.AddDays(-1), 86_400, 5, 100, 50, [], 10, Patch(null)), HostFactStatus.Partial, "not-read: cpu", "Read again in five minutes.");

        var updated = HostHotfixReader.WithHotfix(reading, () => [new HotfixRecord("KB5090002", "11/2/2026")]);

        Assert.Equal(HostFactStatus.Partial, updated.Status);
        Assert.Equal("not-read: cpu", updated.Reason);
        Assert.Equal("KB5090002", updated.Value<HostHealth>()!.Patch!.LastHotfixId);
        var failed = HostFactReading.Failed(HostFacts.Health, null, Now, HostFactStatus.Unreadable, "x", "y");
        Assert.Same(failed, HostHotfixReader.WithHotfix(failed, () => throw new InvalidOperationException("must not be read")));
    }

    [Fact]
    public void ABareProgramNameIsFoundInTheSystemFolderThenInPath()
    {
        var system = Directory.CreateDirectory(Path.Combine(folder, "system")).FullName;
        var tools = Directory.CreateDirectory(Path.Combine(folder, "tools")).FullName;
        File.WriteAllText(Path.Combine(system, "synthetic-copy.exe"), "");
        File.WriteAllText(Path.Combine(tools, "synthetic-sync.exe"), "");

        Assert.Equal(Path.Join(system, "synthetic-copy.exe"), HostInventoryReader.Resolve("synthetic-copy", system, tools));
        Assert.Equal(Path.Join(system, "synthetic-copy.exe"), HostInventoryReader.Resolve("synthetic-copy.exe", system, tools));
        Assert.Equal(Path.Join(tools, "synthetic-sync.exe"), HostInventoryReader.Resolve("synthetic-sync", system, "relative;" + tools));
        Assert.Null(HostInventoryReader.Resolve("synthetic-missing", system, tools));
        Assert.Null(HostInventoryReader.Resolve(@"sub\synthetic-copy.exe", system, tools));
    }

    [Fact]
    public void ABareNameFoundNowhereIsNotJudgedByTheCurrentFolder()
    {
        // The reader's current folder may well be writable by users; a bare name never inherits that verdict.
        Assert.False(HostInventoryReader.IsUserWritable("wpshield-synthetic-program-that-does-not-exist"));
    }
}
