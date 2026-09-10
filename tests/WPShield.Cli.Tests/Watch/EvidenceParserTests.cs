using WPShield.Cli.Watch;

namespace WPShield.Cli.Tests.Watch;

/// <summary>
/// The parser's contract is with the exact lines the gateway writes, so these are those lines. If a
/// gateway log message changes, the prefix match here is where that break is meant to surface.
/// </summary>
public sealed class EvidenceParserTests
{

    [Fact]
    public void Path_finding_is_a_finding_with_rule_and_score()
    {
        var line =
            """
            {"timestamp":"2026-09-09T14:22:01.0000000+00:00","level":"Warning","category":"WPShield.Gateway.RequestPath","message":"Request path finding. RequestId=abc SiteId=peopleworks.example RuleId=WP-PATH-002 Score=100 Evidence=segment=dist","state":{"RequestId":"abc","SiteId":"peopleworks.example","RuleId":"WP-PATH-002","Score":100,"Evidence":"segment=dist"}}
            """;

        var evidence = EvidenceParser.Parse(line);

        Assert.NotNull(evidence);
        Assert.Equal(EvidenceKind.Finding, evidence!.Kind);
        Assert.Equal("peopleworks.example", evidence.Host);
        Assert.Equal("WP-PATH-002", evidence.Rules);
        Assert.Equal(100, evidence.Score);
        Assert.Equal(EvidenceAction.Unknown, evidence.Action);
    }

    [Fact]
    public void Path_verdict_carries_action_and_method_but_no_rule()
    {
        var line =
            """
            {"timestamp":"2026-09-09T14:22:01.0000000+00:00","level":"Information","category":"WPShield.Gateway.RequestPath","message":"Request path inspected. RequestId=abc SiteId=peopleworks.example Method=GET Score=100 Action=Observe Mode=Monitor","state":{"RequestId":"abc","SiteId":"peopleworks.example","Method":"GET","Score":100,"Action":"Observe","Mode":"Monitor"}}
            """;

        var evidence = EvidenceParser.Parse(line);

        Assert.NotNull(evidence);
        Assert.Equal(EvidenceKind.Verdict, evidence!.Kind);
        Assert.Equal(EvidenceAction.Observe, evidence.Action);
        Assert.Equal("GET", evidence.Method);
        Assert.Null(evidence.Rules);
    }

    [Fact]
    public void Upload_finding_reads_ruleids_and_path()
    {
        var line =
            """
            {"timestamp":"2026-09-09T14:22:01.0000000+00:00","level":"Warning","category":"WPShield.Gateway.Upload","message":"Upload finding. RequestId=abc SiteId=shop.example Method=POST Path=/wp-admin/async-upload.php PartIndex=0 NormalizedName=invoice.php.jpg Score=80 Action=Observe RuleIds=WP-UPLOAD-001,WP-UPLOAD-002 Evidence=x","state":{"RequestId":"abc","SiteId":"shop.example","Method":"POST","Path":"/wp-admin/async-upload.php","PartIndex":0,"NormalizedName":"invoice.php.jpg","Score":80,"Action":"Observe","RuleIds":"WP-UPLOAD-001,WP-UPLOAD-002","Evidence":"x"}}
            """;

        var evidence = EvidenceParser.Parse(line);

        Assert.NotNull(evidence);
        Assert.Equal(EvidenceKind.Finding, evidence!.Kind);
        Assert.Equal("shop.example", evidence.Host);
        Assert.Equal("WP-UPLOAD-001,WP-UPLOAD-002", evidence.Rules);
        Assert.Equal(80, evidence.Score);
        Assert.Equal("/wp-admin/async-upload.php", evidence.Path);
    }

    [Fact]
    public void Upload_verdict_is_a_verdict_even_though_it_carries_ruleids()
    {
        // This is the case a shape-guessing parser gets wrong: the verdict line carries RuleIds too.
        var line =
            """
            {"timestamp":"2026-09-09T14:22:01.0000000+00:00","level":"Warning","category":"WPShield.Gateway.Upload","message":"Upload inspection complete. RequestId=abc SiteId=shop.example Method=POST Path=/u Files=1 Fields=0 Status=Inspected Score=80 Action=Block WouldBlock=true RuleIds=WP-UPLOAD-001,WP-UPLOAD-002 BufferedBytes=10 Disposition=forwarded","state":{"RequestId":"abc","SiteId":"shop.example","Method":"POST","Path":"/u","Score":80,"Action":"Block","WouldBlock":true,"RuleIds":"WP-UPLOAD-001,WP-UPLOAD-002","Disposition":"forwarded"}}
            """;

        var evidence = EvidenceParser.Parse(line);

        Assert.NotNull(evidence);
        Assert.Equal(EvidenceKind.Verdict, evidence!.Kind);
        Assert.Equal(EvidenceAction.Block, evidence.Action);
    }

    [Fact]
    public void Dropped_notice_is_recognised()
    {
        var line =
            """
            {"timestamp":"2026-09-09T14:22:01.0000000+00:00","level":"Warning","category":"WPShield.Gateway.Logging","message":"Log entries were dropped because the write queue was full. The gap is in this file, not in what the gateway did.","state":{"DroppedEntries":42}}
            """;

        Assert.Equal(EvidenceKind.DroppedNotice, EvidenceParser.Parse(line)!.Kind);
    }

    [Fact]
    public void Startup_and_configuration_lines_are_other()
    {
        var line =
            """
            {"timestamp":"2026-09-09T14:22:01.0000000+00:00","level":"Information","category":"WPShield.Gateway.Configuration","message":"Gateway configuration resolved 2 site(s).","state":{"SiteCount":2}}
            """;

        Assert.Equal(EvidenceKind.Other, EvidenceParser.Parse(line)!.Kind);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("{")]
    [InlineData("not json at all")]
    [InlineData("[1,2,3]")]
    [InlineData("\"a string\"")]
    [InlineData("{\"level\":\"Information\"}")] // no message
    public void Garbage_and_incomplete_lines_return_null(string line)
    {
        Assert.Null(EvidenceParser.Parse(line));
    }

    [Fact]
    public void A_line_without_a_timestamp_returns_null()
    {
        var line = """{"level":"Information","message":"Request path inspected. x"}""";
        Assert.Null(EvidenceParser.Parse(line));
    }
}
