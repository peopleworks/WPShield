using WPShield.Cli.Report;
using WPShield.Cli.Watch;

namespace WPShield.Cli.Tests.Report;

public sealed class ReportAggregatorTests
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 10, 9, 0, 0, TimeSpan.Zero);
    private static readonly DateTimeOffset Generated = new(2026, 9, 10, 12, 0, 0, TimeSpan.Zero);

    private static EvidenceEvent Finding(string host, string rules, int score, DateTimeOffset? at = null, string? path = null) => new()
    {
        Timestamp = at ?? T0,
        Level = "Warning",
        Kind = EvidenceKind.Finding,
        Host = host,
        Rules = rules,
        Score = score,
        Path = path,
        Message = "x"
    };

    private static EvidenceEvent Verdict(string host, EvidenceAction action, string mode, DateTimeOffset? at = null) => new()
    {
        Timestamp = at ?? T0,
        Level = "Warning",
        Kind = EvidenceKind.Verdict,
        Host = host,
        Action = action,
        Mode = mode,
        Message = "x"
    };

    private static ReportModel Build(params EvidenceEvent[] events) =>
        ReportAggregator.Build(events, [], [], Generated);

    [Fact]
    public void Empty_input_is_an_empty_report()
    {
        var model = Build();

        Assert.True(model.Empty);
        Assert.Equal(0, model.TotalEvents);
        Assert.Null(model.WindowStart);
    }

    [Fact]
    public void Other_lines_do_not_count()
    {
        var other = new EvidenceEvent { Timestamp = T0, Level = "Information", Kind = EvidenceKind.Other, Message = "config" };
        var model = Build(other);

        Assert.True(model.Empty);
    }

    [Fact]
    public void Comma_joined_rules_credit_each_rule()
    {
        var model = Build(Finding("shop.example", "WP-UPLOAD-001,WP-UPLOAD-002", 80));

        Assert.Equal(2, model.Rules.Count);
        Assert.All(model.Rules, rule => Assert.Equal(1, rule.Findings));
        Assert.All(model.Rules, rule => Assert.Equal(80, rule.MaxScore));
    }

    [Fact]
    public void Rules_are_ordered_by_findings_then_score()
    {
        var model = Build(
            Finding("a.example", "WP-UPLOAD-001", 50),
            Finding("b.example", "WP-UPLOAD-001", 50),
            Finding("a.example", "IIS-CONFIG-001", 100));

        Assert.Equal("WP-UPLOAD-001", model.Rules[0].RuleId); // 2 findings
        Assert.Equal(2, model.Rules[0].Findings);
        Assert.Equal(2, model.Rules[0].Sites);               // fired on two sites
        Assert.Equal("IIS-CONFIG-001", model.Rules[1].RuleId);
    }

    [Fact]
    public void Verdicts_count_per_site_and_pick_a_top_rule()
    {
        var model = Build(
            Finding("peopleworks.example", "IIS-CONFIG-001", 100),
            Finding("peopleworks.example", "WP-PATH-002", 100),
            Finding("peopleworks.example", "IIS-CONFIG-001", 100),
            Verdict("peopleworks.example", EvidenceAction.Block, "Block"),
            Verdict("peopleworks.example", EvidenceAction.Observe, "Monitor"));

        var site = Assert.Single(model.Sites);
        Assert.Equal("peopleworks.example", site.Site);
        Assert.Equal(3, site.Findings);
        Assert.Equal(1, site.Blocked);
        Assert.Equal(1, site.Observed);
        Assert.Equal("IIS-CONFIG-001", site.TopRule); // fired twice, WP-PATH-002 once
    }

    [Fact]
    public void Allow_verdicts_count_as_clean_uploads_not_as_a_site_finding()
    {
        var model = Build(Verdict("blog.example", EvidenceAction.Allow, "Monitor"));

        Assert.Equal(1, model.AllowedUploads);
        Assert.Equal(0, model.Findings);
        // A site with only a clean upload still appears with zero findings.
        Assert.Empty(model.Sites); // no finding, no block, no observe -> nothing to roll up
    }

    [Fact]
    public void Window_spans_the_earliest_and_latest_events()
    {
        var model = Build(
            Finding("a.example", "R", 10, at: T0.AddMinutes(30)),
            Finding("a.example", "R", 10, at: T0),
            Finding("a.example", "R", 10, at: T0.AddHours(2)));

        Assert.Equal(T0, model.WindowStart);
        Assert.Equal(T0.AddHours(2), model.WindowEnd);
    }

    [Fact]
    public void Modes_seen_are_distinct_and_sorted()
    {
        var model = Build(
            Verdict("a.example", EvidenceAction.Observe, "Monitor"),
            Verdict("b.example", EvidenceAction.Block, "Block"),
            Verdict("c.example", EvidenceAction.Observe, "Monitor"));

        Assert.Equal(["Block", "Monitor"], model.ModesSeen);
    }

    [Fact]
    public void Top_paths_count_and_rank_by_frequency()
    {
        var model = Build(
            Finding("a.example", "R", 80, path: "/wp-admin/async-upload.php"),
            Finding("a.example", "R", 80, path: "/wp-admin/async-upload.php"),
            Finding("a.example", "R", 80, path: "/upload.php"));

        Assert.Equal("/wp-admin/async-upload.php", model.TopPaths[0].Path);
        Assert.Equal(2, model.TopPaths[0].Count);
        Assert.Equal("/upload.php", model.TopPaths[1].Path);
    }
}
