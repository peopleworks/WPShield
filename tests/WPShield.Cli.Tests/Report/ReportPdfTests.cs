using QuestPDF.Fluent;
using QuestPDF.Infrastructure;
using WPShield.Cli.Report;
using WPShield.Cli.Watch;

namespace WPShield.Cli.Tests.Report;

/// <summary>
/// The document has no logic of its own — the aggregator decides every number — so the one thing
/// worth asserting is that a populated model renders a real, multi-page PDF without throwing. When
/// WPSHIELD_REPORT_SNAPSHOT names a directory, the pages are also written there as PNGs to be looked
/// at; off by default, so the suite writes nothing outside its temp file.
/// </summary>
public sealed class ReportPdfTests
{
    private static EvidenceEvent Finding(string host, string rules, int score, string? path = null) => new()
    {
        Timestamp = new DateTimeOffset(2026, 9, 10, 9, 5, 0, TimeSpan.Zero),
        Level = "Warning",
        Kind = EvidenceKind.Finding,
        Host = host,
        Rules = rules,
        Score = score,
        Path = path,
        Message = "x"
    };

    private static EvidenceEvent Verdict(string host, EvidenceAction action, string mode) => new()
    {
        Timestamp = new DateTimeOffset(2026, 9, 10, 9, 5, 0, TimeSpan.Zero),
        Level = "Warning",
        Kind = EvidenceKind.Verdict,
        Host = host,
        Action = action,
        Mode = mode,
        Message = "x"
    };

    [Fact]
    public void A_populated_model_renders_a_real_pdf()
    {
        QuestPDF.Settings.License = LicenseType.Community;

        var events = new[]
        {
            Finding("peopleworks.example", "IIS-CONFIG-001", 100, "/wp-admin/async-upload.php"),
            Finding("peopleworks.example", "WP-PATH-002", 100),
            Finding("shop.example", "WP-UPLOAD-001,WP-UPLOAD-002", 80, "/wp-admin/async-upload.php"),
            Verdict("peopleworks.example", EvidenceAction.Block, "Block"),
            Verdict("shop.example", EvidenceAction.Observe, "Monitor"),
            Verdict("blog.example", EvidenceAction.Allow, "Monitor"),
        };

        var sources = new[]
        {
            new EvidenceSource
            {
                FileName = "wpshield-20260910.jsonl",
                SizeBytes = 4096,
                Sha256 = new string('a', 64),
                TotalLines = 42,
                ParsedEvents = events.Length
            }
        };

        var model = ReportAggregator.Build(events, sources, [], DateTimeOffset.Now);
        var document = new ReportPdf(model);

        var pdf = document.GeneratePdf();

        Assert.True(pdf.Length > 1000);
        Assert.Equal("%PDF", System.Text.Encoding.ASCII.GetString(pdf, 0, 4));

        var snapshotDir = Environment.GetEnvironmentVariable("WPSHIELD_REPORT_SNAPSHOT");
        if (!string.IsNullOrWhiteSpace(snapshotDir))
        {
            Directory.CreateDirectory(snapshotDir);
            var images = document.GenerateImages();
            var index = 1;
            foreach (var image in images)
            {
                File.WriteAllBytes(Path.Combine(snapshotDir, $"page-{index++}.png"), image);
            }
        }
    }

    [Fact]
    public void An_empty_model_still_renders()
    {
        QuestPDF.Settings.License = LicenseType.Community;

        var model = ReportAggregator.Build([], [], [], DateTimeOffset.Now);
        var pdf = new ReportPdf(model).GeneratePdf();

        Assert.Equal("%PDF", System.Text.Encoding.ASCII.GetString(pdf, 0, 4));
    }
}
