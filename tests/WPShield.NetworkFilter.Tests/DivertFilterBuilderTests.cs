using System.Net;

namespace WPShield.NetworkFilter.Tests;

public sealed class DivertFilterBuilderTests
{
    private static PacketHeaders Syn(string source) => new(
        IPAddress.Parse(source),
        IPAddress.Parse(source.Contains(':', StringComparison.Ordinal) ? "2001:db8::1" : "192.0.2.1"),
        49152,
        443,
        Syn: true,
        Ack: false);

    private static bool Dropped(DropFilterPlan plan, string source) =>
        plan.Filters.Any(filter => ReferenceFilterEvaluator.Evaluate(filter, Syn(source)));

    [Fact]
    public void TheObserverFilter_SelectsNewInboundConnectionAttemptsOnly()
    {
        Assert.Equal("inbound and !loopback and tcp.Syn and !tcp.Ack", DivertFilterBuilder.ObserverFilter);
        Assert.True(ReferenceFilterEvaluator.Evaluate(DivertFilterBuilder.ObserverFilter, Syn("198.51.100.7")));
        Assert.False(ReferenceFilterEvaluator.Evaluate(DivertFilterBuilder.ObserverFilter, Syn("198.51.100.7") with { Ack = true }));
    }

    [Fact]
    public void AnEmptyBlockSet_HasNoDropFilterAtAll()
    {
        Assert.Empty(DivertFilterBuilder.BuildDropFilters([], []).Filters);
    }

    [Fact]
    public void SingleAddressesAndRanges_DropExactlyWhatTheyName()
    {
        var plan = DivertFilterBuilder.BuildDropFilters(
            [Ranges.Block("203.0.113.7"), Ranges.Block("198.51.100.0/24"), Ranges.Block("2001:db8:5::/64")],
            []);

        Assert.Single(plan.Filters);
        Assert.StartsWith("inbound and !loopback and (", plan.Filters[0], StringComparison.Ordinal);
        Assert.True(Dropped(plan, "203.0.113.7"));
        Assert.False(Dropped(plan, "203.0.113.8"));
        Assert.True(Dropped(plan, "198.51.100.0"));
        Assert.True(Dropped(plan, "198.51.100.255"));
        Assert.False(Dropped(plan, "198.51.101.0"));
        Assert.True(Dropped(plan, "2001:db8:5::abcd"));
        Assert.False(Dropped(plan, "2001:db8:6::"));
    }

    [Fact]
    public void AnAllowListedEntry_IsExcludedEvenIfItReachedTheBuilder()
    {
        var plan = DivertFilterBuilder.BuildDropFilters(
            [Ranges.Block("203.0.113.7"), Ranges.Block("198.51.100.0/24")],
            [Ranges.Allow("198.51.100.50")]);

        Assert.Equal("198.51.100.0/24", Assert.Single(plan.Excluded).ToString());
        Assert.False(Dropped(plan, "198.51.100.50"));
        Assert.False(Dropped(plan, "198.51.100.1"));
        Assert.True(Dropped(plan, "203.0.113.7"));
    }

    [Fact]
    public void ALargeSet_IsSplitAcrossFiltersThatEachStayUnderTheObjectBudget()
    {
        var blocks = Enumerable.Range(0, 400).Select(i => Ranges.Block($"198.51.{100 + (i / 250)}.{i % 250}"))
            .Concat(Enumerable.Range(0, 150).Select(i => Ranges.Block($"10.{100 + i}.0.0/16")))
            .ToList();

        var plan = DivertFilterBuilder.BuildDropFilters(blocks, []);

        Assert.True(plan.Filters.Count > 1);
        foreach (var filter in plan.Filters)
        {
            var objects = 2 + filter.Split(" == ").Length - 1 + (filter.Split(" >= ").Length - 1) * 2;
            Assert.True(objects <= DivertFilterBuilder.ObjectBudget, $"{objects} objects");
        }

        foreach (var block in blocks)
        {
            Assert.True(Dropped(plan, block.First.ToString()));
            Assert.True(Dropped(plan, block.Last.ToString()));
        }

        Assert.False(Dropped(plan, "198.51.99.255"));
    }

    [Fact]
    public void DuplicateEntries_AreWrittenOnce()
    {
        var plan = DivertFilterBuilder.BuildDropFilters([Ranges.Block("203.0.113.7"), Ranges.Block("203.0.113.7")], []);

        Assert.Single(plan.Filters[0].Split(" == ").Skip(1));
    }
}
