using System.Text.Json;
using WPShield.Cli;
using WPShield.Cli.Audit;

namespace WPShield.Cli.Tests.Audit;

/// <summary>
/// What the operator reads: the rendered report, the exit code and the JSON Lines file.
/// </summary>
public sealed class AuditCommandTests
{
    [Fact]
    public void TheReport_SaysItChangedNothing()
    {
        var text = Render(ReportWith(new AuditFinding("AUDIT-002", AuditSeverity.Pass, "No application pool runs with administrator rights")));

        Assert.Contains("read-only", text, StringComparison.Ordinal);
        Assert.Contains("Nothing on this server was changed.", text, StringComparison.Ordinal);
    }

    /// <summary>
    /// Site names and paths come from a server that may be compromised. An escape sequence in one
    /// must not reach the terminal intact.
    /// </summary>
    [Fact]
    public void AnEscapeSequenceInASiteName_NeverReachesTheTerminal()
    {
        const string escape = "\u001b";
        var text = Render(ReportWith(new AuditFinding(
            "AUDIT-005", AuditSeverity.Critical, "1 site folder(s) are writable by every account on this server",
            Remedy: "Replace the permissions by hand.",
            Items: [$"evil{escape}[31m.example  (C:\\sites\\evil)  writable by Everyone (S-1-1-0)"])));

        Assert.DoesNotContain(escape, text, StringComparison.Ordinal);
        Assert.Contains("evil?[31m.example", text, StringComparison.Ordinal);
    }

    [Fact]
    public void ALongList_IsCutAndSaysHowManyMoreThereAre()
    {
        var items = Enumerable.Range(1, AuditRunner.ListLimit + 7).Select(index => $"site-{index}").ToArray();
        var text = Render(ReportWith(new AuditFinding(
            "AUDIT-005", AuditSeverity.Critical, "Writable folders", Remedy: "By hand.", Items: items)));

        Assert.Contains($"site-{AuditRunner.ListLimit}", text, StringComparison.Ordinal);
        Assert.DoesNotContain($"site-{AuditRunner.ListLimit + 1}", text, StringComparison.Ordinal);
        Assert.Contains("and 7 more", text, StringComparison.Ordinal);
    }

    [Fact]
    public void RemediesArePrintedTogetherAtTheEnd()
    {
        var text = Render(ReportWith(new AuditFinding(
            "AUDIT-004", AuditSeverity.Warn, "PHP is mapped for the whole server", Remedy: "Map PHP only on the sites that need it.")));

        var summary = text.IndexOf("warning(s)", StringComparison.Ordinal);
        var remedy = text.IndexOf("Map PHP only on the sites that need it.", StringComparison.Ordinal);
        Assert.True(summary >= 0 && remedy > summary);
    }

    [Fact]
    public void AnIncompleteAudit_SaysSoInsteadOfCountingFindings()
    {
        var report = ReportWith(new AuditFinding("AUDIT-001", AuditSeverity.Critical, "Not running as administrator", Remedy: "Run elevated."));
        report.Complete = false;

        Assert.Contains("INCOMPLETE", Render(report), StringComparison.Ordinal);
        Assert.Equal(AuditCommand.ExitIncomplete, AuditCommand.ExitCode(report));
    }

    [Fact]
    public void TheJsonLinesReport_UsesTheSharedEnvelope()
    {
        var path = Path.Combine(Path.GetTempPath(), $"wpshield-audit-{Guid.NewGuid():N}.jsonl");

        try
        {
            AuditCommand.WriteJsonLines(
                ReportWith(new AuditFinding(
                    "AUDIT-002", AuditSeverity.Critical, "1 application pool(s) run with administrator rights",
                    Remedy: "By hand.", Items: ["blog  runs as Administrator"])),
                path,
                TextWriter.Null);

            using var document = JsonDocument.Parse(File.ReadAllLines(path).Single());
            var root = document.RootElement;

            Assert.Equal("Error", root.GetProperty("level").GetString());
            Assert.Equal("WPShield.Audit", root.GetProperty("category").GetString());
            Assert.Equal("AUDIT-002", root.GetProperty("state").GetProperty("CheckId").GetString());
            Assert.Equal(1, root.GetProperty("state").GetProperty("Items").GetArrayLength());
            Assert.True(root.TryGetProperty("timestamp", out _));
            Assert.True(root.TryGetProperty("message", out _));
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static AuditReport ReportWith(params AuditFinding[] findings)
    {
        var report = new AuditReport();
        foreach (var finding in findings)
        {
            report.Add(finding);
        }

        return report;
    }

    private static string Render(AuditReport report)
    {
        using var writer = new StringWriter();
        AuditCommand.Render(report, writer);
        return writer.ToString();
    }
}
