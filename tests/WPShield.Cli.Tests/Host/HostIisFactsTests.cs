using WPShield.Cli;
using WPShield.Cli.Audit;
using WPShield.Cli.Host;
using WPShield.Evidence;
using WPShield.WebEvidence;

namespace WPShield.Cli.Tests.Host;

/// <summary>
/// <c>iis_sites</c> and <c>iis_posture</c> from the audit's own reader, and the one write <c>wpshield audit</c>
/// makes: a posture summary in WPShield's store - counts and IDs, never names.
/// </summary>
public sealed class HostIisFactsTests : IDisposable
{
    private static readonly DateTimeOffset Now = EvidenceTestStore.Now;
    private readonly EvidenceTestStore store = new();

    public void Dispose() => store.Dispose();

    private static AuditSite Site(string name, string pool, string path) => new(name, "Started", path, pool,
        [new Preflight.IisBinding("https", "*:443:" + name)], LooksLikeWordPress: true, ExecutesPhp: true,
        new FolderAccess(true, ["Everyone (S-1-1-0)"]), null);

    private static AuditFacts Facts(bool readable = true) => new(true, readable, readable ? null : "denied",
        [
            new AuditPool("shop", "Started", "SpecificUser", "administrator", true),
            new AuditPool("blog", "Started", "ApplicationPoolIdentity", null, null),
            new AuditPool("legacy", "Started", "LocalSystem", null, null)
        ],
        [Site("shop.example", "shop", @"C:\sites\shop-secret-folder"), Site("blog.example", "blog", @"C:\sites\blog")],
        []);

    [Fact]
    public void SitesCarryTheirIdAndPoolIdentityTypeAndNeverAPassword()
    {
        var logs = new IisLogConfiguration([new IisLogSite(7, "shop.example", @"C:\logs", true, "W3C", true)], null, null);

        var sites = HostIisFacts.ReadSites(Facts(), logs).Value<HostSites>()!.Sites;

        var shop = Assert.Single(sites, s => s.Name == "shop.example");
        Assert.Equal(7, shop.Id);
        Assert.Equal("SpecificUser", shop.IdentityType);
        Assert.True(shop.IdentityIsAdministrator);
        Assert.False(Assert.Single(sites, s => s.Name == "blog.example").IdentityIsAdministrator);
        Assert.True(HostIisFacts.IsAdministrator(new AuditPool("x", "Started", "LocalSystem", null, null)));
        Assert.Null(HostIisFacts.IsAdministrator(new AuditPool("x", "Started", "SpecificUser", "someone", null)));
    }

    [Fact]
    public void AnUnreadableIisIsAStatusWithARemedyNotAnEmptyList()
    {
        var reading = HostIisFacts.ReadSites(Facts(readable: false), null);

        Assert.Equal(HostFactStatus.Unreadable, reading.Status);
        Assert.Null(reading.Payload);
        Assert.NotNull(reading.Remedy);
    }

    [Fact]
    public void ThePostureHoldsCountsAndIdsAndNoNames()
    {
        var facts = Facts();
        var report = new AuditRunner(facts).Run();

        var posture = HostIisFacts.Posture(report, facts, "audit", Now);

        var value = posture.Value<HostPosture>()!;
        Assert.Equal(3, value.PoolsTotal);
        Assert.Equal(2, value.PoolsAdministrator);
        Assert.Equal("audit", value.Source);
        Assert.Contains(value.Findings, f => f.Id == "AUDIT-002" && f.Severity == "critical");
        Assert.DoesNotContain("shop.example", posture.Payload!.ToJsonString(), StringComparison.Ordinal);
        Assert.DoesNotContain("shop-secret-folder", posture.Payload!.ToJsonString(), StringComparison.Ordinal);
    }

    [Fact]
    public void TheAuditRecordsItsSummaryInWPShieldsStoreAndSaysSo()
    {
        store.Write(_ => { });
        var output = new StringWriter();

        var exit = AuditCommand.Run(CliOptions.Parse([]), output, () => Facts(),
            (report, facts, path) => AuditCommand.RecordPosture(report, facts, path, elevated: true), store.Path);

        Assert.Equal(AuditCommand.ExitCritical, exit);
        Assert.Contains("Nothing on this server was changed.", output.ToString(), StringComparison.Ordinal);
        Assert.Contains("A summary was recorded in WPShield's evidence store", output.ToString(), StringComparison.Ordinal);
        using var reader = EvidenceStore.OpenReadOnly(store.Path);
        var posture = new HostFactsQueries(reader).Latest(HostFacts.Posture)!;
        Assert.Equal("audit", posture.Value<HostPosture>()!.Source);
    }

    [Fact]
    public void AnAuditThatCannotRecordStillRunsAndSaysWhyNot()
    {
        var output = new StringWriter();

        var exit = AuditCommand.Run(CliOptions.Parse([]), output, () => Facts(),
            (report, facts, path) => AuditCommand.RecordPosture(report, facts, path, elevated: true), Path.Combine(store.DirectoryPath, "none.db"));

        Assert.Equal(AuditCommand.ExitCritical, exit);
        Assert.Contains("The summary was not recorded in WPShield's evidence store", output.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void AnIncompleteAuditIsNeverRecordedAsTheLatestPosture()
    {
        store.Write(_ => { });
        var facts = Facts(readable: false);
        var report = new AuditRunner(facts).Run();

        Assert.NotNull(AuditCommand.RecordPosture(report, facts, store.Path, elevated: true));
        using var reader = EvidenceStore.OpenReadOnly(store.Path);
        Assert.Null(new HostFactsQueries(reader).Latest(HostFacts.Posture));
    }

    [Theory]
    [InlineData(@"C:\Windows\System32\cmd.exe", false, true)]
    [InlineData(@"C:\Windows\System32\svchost.exe", false, false)]
    [InlineData(@"C:\Windows\System32\svchost.exe", true, true)]
    public void AMicrosoftBinaryThatRunsAPayloadIsStillListed(string executable, bool encoded, bool listed)
    {
        var flags = encoded ? new[] { CommandFlags.HasArguments, CommandFlags.EncodedCommand } : [CommandFlags.HasArguments];
        var microsoft = new SignatureResult(HostSignature.Signed, "Microsoft Windows", true);

        Assert.Equal(listed, !HostInventoryReader.IsQuietMicrosoft(microsoft, executable, flags));
    }
}
