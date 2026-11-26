using System.IO;
using WPShield.Desktop.Demo;
using WPShield.Evidence;
using WPShield.Evidence.Decisions;
using Xunit;

namespace WPShield.Desktop.Tests;

public sealed class DemoStoreTests
{
    [Fact]
    public void SyntheticStoreReadsThroughTheCurrentEvidenceApis()
    {
        using var workspace = new DemoWorkspace();
        var path = workspace.FilePath("new.db");
        Assert.Equal(path, Program.CreateStore(path));
        using var store = EvidenceStore.OpenReadOnly(path);
        Assert.True(store.ReadOnly);
        var now = DemoData.Now;
        var week = now.AddDays(-7);
        var logons = new EvidenceQueries(store);
        Assert.True(logons.Summary(week, now).Attempts > 500);
        Assert.All(logons.TopSources(week, now), source =>
        {
            Assert.Contains(source.Network, new[] { "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24" });
            Assert.True(source.Neighbors > 0);
        });
        Assert.Contains(logons.ActiveDecisions(now).Decisions,
            decision => decision.Action == DecisionActions.WouldBlock && decision.Mode == DecisionActions.MonitorMode);
        Assert.Equal("Demo edge network", new EvidenceSettings(store).Get(AddressLabels.SettingKey)["192.0.2.0/24"]?.ToString());

        var web = new WebEvidenceQueries(store);
        var sites = web.Sites();
        Assert.Equal(12, sites.Count);
        Assert.All(sites, site => Assert.EndsWith(".example", site.Name, StringComparison.Ordinal));
        Assert.Single(sites, site => site.Status == "unavailable");
        Assert.Contains(web.RuleCounts(week, now), rule => rule.Observation && rule.Id == "WEB-OBS-001" && rule.Requests == 1);

        var host = new HostFactsQueries(store);
        var restarts = host.Restarts(now.AddDays(-30), now);
        Assert.Equal(5, restarts.Count);
        Assert.All(restarts, restart => Assert.Equal(0x133u, restart.BugCheckCode));
        var posture = host.PostureHistory(now.AddDays(-30), now);
        Assert.Equal(9, posture[0].PoolsAdministrator);
        Assert.Equal(6, posture[^1].PoolsAdministrator);
        Assert.All(posture, point => Assert.Equal(10, point.PoolsTotal));
        var ports = Assert.IsType<HostPorts>(host.Latest(HostFacts.Ports)?.Value<HostPorts>());
        Assert.Contains(ports.Listeners, port => port.Port == 445 && port.Red);
        Assert.Contains(ports.Listeners, port => port.Verdict == ExposureVerdicts.Restricted);
        Assert.NotNull(host.Latest(HostFacts.Inventory, HostFacts.Services));
        Assert.Single(host.InventoryChanges(week, now, HostFacts.Tasks));
    }

    [Fact]
    public void GeneratorRejectsExistingFilesWithoutChangingThem()
    {
        using var workspace = new DemoWorkspace();
        var path = workspace.FilePath("existing.db");
        File.WriteAllText(path, "keep this file");

        Assert.Contains("already exists", Assert.Throws<IOException>(() => Program.CreateStore(path)).Message);
        Assert.Equal("keep this file", File.ReadAllText(path));
    }

    [Fact]
    public void GeneratorRejectsTheDefaultEvidenceDirectoryAndItsDescendants()
    {
        var evidence = Path.GetDirectoryName(EvidenceStore.DefaultPath)!;
        var descendant = Path.Combine(evidence, "demo", "new.db");

        Assert.Contains("default evidence", Assert.Throws<IOException>(() => Program.CreateStore(EvidenceStore.DefaultPath)).Message);
        Assert.Contains("default evidence", Assert.Throws<IOException>(() => Program.CreateStore(descendant)).Message);
    }

    [Fact]
    public void DirectoryGuardAllowsASiblingSharingTheProtectedPrefix()
    {
        using var workspace = new DemoWorkspace();
        var protectedDirectory = workspace.FilePath("evidence");
        var sibling = workspace.FilePath("evidence-other");
        Directory.CreateDirectory(sibling);
        try
        {
            var path = Path.Combine(sibling, "new.db");
            Assert.Equal(path, DemoPaths.NewStorePath(path, protectedDirectory));
        }
        finally { Directory.Delete(sibling); }
    }
}
