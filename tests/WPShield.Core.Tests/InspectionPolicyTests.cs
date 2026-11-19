using WPShield.Abstractions;
using WPShield.Core;

namespace WPShield.Core.Tests;

public sealed class InspectionPolicyTests
{
    [Theory]
    [InlineData(29, ProtectionMode.Block, InspectionAction.Allow)]
    [InlineData(30, ProtectionMode.Block, InspectionAction.Observe)]
    [InlineData(79, ProtectionMode.Block, InspectionAction.Observe)]
    [InlineData(80, ProtectionMode.Block, InspectionAction.Block)]
    [InlineData(100, ProtectionMode.Block, InspectionAction.Block)]
    [InlineData(80, ProtectionMode.Monitor, InspectionAction.Observe)]
    [InlineData(100, ProtectionMode.Disabled, InspectionAction.Allow)]
    public async Task SharedPolicy_PreservesServingBoundaries(int score, ProtectionMode mode, InspectionAction expected)
    {
        var site = new SiteOptions { Id = "one", Hosts = ["one.example"], Destination = new Uri("http://127.0.0.1:8081"), Mode = mode };
        var context = new InspectionContext("one", "one.example", "POST", "/upload");
        var upload = await new InspectionEngine([new UploadRule(score)]).InspectAsync(context, site);
        var path = await new RequestPathEngine([new PathRule(score)]).InspectAsync(context, site);
        Assert.Equal(expected, upload.RecommendedAction);
        Assert.Equal(expected, path.RecommendedAction);
        Assert.Equal(expected, InspectionPolicy.Recommend(score, mode, 30, 80));
    }

    private sealed class UploadRule(int score) : IInspectionRule
    {
        public string Id => "SYNTHETIC-UPLOAD";
        public ValueTask<RuleFinding?> EvaluateAsync(InspectionContext context, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<RuleFinding?>(new RuleFinding(Id, score, "synthetic"));
    }

    private sealed class PathRule(int score) : IRequestPathRule
    {
        public string Id => "SYNTHETIC-PATH";
        public ValueTask<RuleFinding?> EvaluateAsync(InspectionContext context, CancellationToken cancellationToken = default) =>
            ValueTask.FromResult<RuleFinding?>(new RuleFinding(Id, score, "synthetic"));
    }
}
