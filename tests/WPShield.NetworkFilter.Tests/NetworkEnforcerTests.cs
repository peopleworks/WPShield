namespace WPShield.NetworkFilter.Tests;

public sealed class NetworkEnforcerTests
{
    private static DropFilterPlan Plan(params string[] blocks) =>
        DivertFilterBuilder.BuildDropFilters(blocks.Select(Ranges.Block), []);

    [Fact]
    public void Apply_OpensDropHandlesAtTheConfiguredPriority()
    {
        var driver = new FakeDivertDriver();
        using var enforcer = new NetworkEnforcer(driver, priority: 1000);

        var result = enforcer.Apply(Plan("203.0.113.7"));

        Assert.Equal(EnforcementStatus.Applied, result.Status);
        var handle = Assert.Single(driver.Live(DivertHandleKind.Drop));
        Assert.Equal(1000, handle.Priority);
        Assert.Empty(driver.Live(DivertHandleKind.Observe));
    }

    [Fact]
    public void AnUpdate_OpensTheNewHandleBeforeClosingTheOld()
    {
        var driver = new FakeDivertDriver();
        using var enforcer = new NetworkEnforcer(driver, 0);
        enforcer.Apply(Plan("203.0.113.7"));
        var first = driver.Opened[0];
        var oldStillLiveWhenNewOpened = false;
        driver.OpenFails = (_, _) =>
        {
            oldStillLiveWhenNewOpened = !first.IsDisposed;
            return false;
        };

        enforcer.Apply(Plan("203.0.113.7", "203.0.113.8"));

        Assert.True(oldStillLiveWhenNewOpened);
        Assert.True(first.IsDisposed);
        Assert.Single(driver.Live(DivertHandleKind.Drop));
    }

    [Fact]
    public void ACompileFailure_LeavesThePreviousBlocksInForce()
    {
        var driver = new FakeDivertDriver();
        using var enforcer = new NetworkEnforcer(driver, 0);
        enforcer.Apply(Plan("203.0.113.7"));
        driver.CompileFails = _ => true;

        var result = enforcer.Apply(Plan("203.0.113.8"));

        Assert.Equal(EnforcementStatus.Failed, result.Status);
        Assert.Contains("203.0.113.7", Assert.Single(driver.Live(DivertHandleKind.Drop)).Filter, StringComparison.Ordinal);
    }

    [Fact]
    public void AnOpenFailurePartWay_ClosesWhatItOpenedAndKeepsThePrevious()
    {
        var driver = new FakeDivertDriver();
        using var enforcer = new NetworkEnforcer(driver, 0);
        enforcer.Apply(Plan("203.0.113.7"));
        var opens = 0;
        driver.OpenFails = (_, _) => ++opens == 2;
        var big = Enumerable.Range(0, 300).Select(i => $"198.51.{100 + (i / 200)}.{i % 200}").ToArray();

        var result = enforcer.Apply(Plan(big));

        Assert.Equal(EnforcementStatus.Failed, result.Status);
        Assert.Contains("203.0.113.7", Assert.Single(driver.Live(DivertHandleKind.Drop)).Filter, StringComparison.Ordinal);
        Assert.All(driver.Opened.Skip(1), handle => Assert.True(handle.IsDisposed));
    }

    [Fact]
    public void TheSamePlan_IsNotReapplied()
    {
        var driver = new FakeDivertDriver();
        using var enforcer = new NetworkEnforcer(driver, 0);
        enforcer.Apply(Plan("203.0.113.7"));

        Assert.Equal(EnforcementStatus.Unchanged, enforcer.Apply(Plan("203.0.113.7")).Status);
        Assert.Single(driver.Opened);
    }

    [Fact]
    public void AnEmptyPlan_ClosesEveryHandle()
    {
        var driver = new FakeDivertDriver();
        using var enforcer = new NetworkEnforcer(driver, 0);
        enforcer.Apply(Plan("203.0.113.7"));

        enforcer.Apply(DropFilterPlan.Empty);

        Assert.Empty(driver.Live(DivertHandleKind.Drop));
    }

    [Fact]
    public void Dispose_LiftsEveryBlock()
    {
        var driver = new FakeDivertDriver();
        var enforcer = new NetworkEnforcer(driver, 0);
        enforcer.Apply(Plan(Enumerable.Range(0, 300).Select(i => $"198.51.{100 + (i / 200)}.{i % 200}").ToArray()));
        Assert.True(driver.Live(DivertHandleKind.Drop).Count > 1);

        enforcer.Dispose();

        Assert.Empty(driver.Live(DivertHandleKind.Drop));
    }
}
