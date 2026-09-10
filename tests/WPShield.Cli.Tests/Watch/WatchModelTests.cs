using WPShield.Cli.Watch;

namespace WPShield.Cli.Tests.Watch;

public sealed class WatchModelTests
{
    private static readonly DateTimeOffset T0 = new(2026, 9, 9, 14, 0, 0, TimeSpan.Zero);

    private static EvidenceEvent Event(
        EvidenceKind kind,
        EvidenceAction action = EvidenceAction.Unknown,
        DateTimeOffset? at = null) => new()
        {
            Timestamp = at ?? T0,
            Level = "Warning",
            Kind = kind,
            Action = action,
            Message = "x"
        };

    [Fact]
    public void A_finding_counts_as_a_finding_and_an_event_only()
    {
        var model = new WatchModel();
        model.Add(Event(EvidenceKind.Finding));

        Assert.Equal(1, model.Findings);
        Assert.Equal(1, model.Events);
        Assert.Equal(0, model.Blocked);
        Assert.Equal(0, model.Observed);
    }

    [Fact]
    public void Verdicts_count_by_action()
    {
        var model = new WatchModel();
        model.Add(Event(EvidenceKind.Verdict, EvidenceAction.Block));
        model.Add(Event(EvidenceKind.Verdict, EvidenceAction.Observe));
        model.Add(Event(EvidenceKind.Verdict, EvidenceAction.Allow));

        Assert.Equal(1, model.Blocked);
        Assert.Equal(1, model.Observed);
        Assert.Equal(1, model.AllowedUploads);
        Assert.Equal(3, model.Events);
    }

    [Fact]
    public void Other_lines_are_ignored_entirely()
    {
        var model = new WatchModel();
        model.Add(Event(EvidenceKind.Other));

        Assert.Equal(0, model.Events);
        Assert.Empty(model.Recent);
        Assert.Null(model.FirstSeen);
    }

    [Fact]
    public void Dropped_notice_counts_but_does_not_enter_the_feed()
    {
        var model = new WatchModel();
        model.Add(Event(EvidenceKind.DroppedNotice));

        Assert.Equal(1, model.Dropped);
        Assert.Empty(model.Recent);
    }

    [Fact]
    public void Recent_keeps_only_the_capacity_and_in_order()
    {
        var model = new WatchModel(recentCapacity: 3);
        for (var i = 0; i < 5; i++)
        {
            model.Add(Event(EvidenceKind.Finding, at: T0.AddSeconds(i)));
        }

        var recent = model.Recent;
        Assert.Equal(3, recent.Count);
        Assert.Equal(T0.AddSeconds(2), recent[0].Timestamp);
        Assert.Equal(T0.AddSeconds(4), recent[^1].Timestamp);
    }

    [Fact]
    public void First_and_last_seen_track_the_edges()
    {
        var model = new WatchModel();
        model.Add(Event(EvidenceKind.Finding, at: T0));
        model.Add(Event(EvidenceKind.Finding, at: T0.AddSeconds(10)));

        Assert.Equal(T0, model.FirstSeen);
        Assert.Equal(T0.AddSeconds(10), model.LastSeen);
    }

    [Fact]
    public void Rate_window_buckets_events_in_the_same_second()
    {
        var model = new WatchModel(rateWindowSeconds: 5);
        model.Add(Event(EvidenceKind.Finding, at: T0));
        model.Add(Event(EvidenceKind.Finding, at: T0));
        model.Add(Event(EvidenceKind.Finding, at: T0));

        var window = model.RateWindow(T0);
        Assert.Equal(5, window.Count);
        Assert.Equal(3, window[^1]); // the newest bucket is "now"
        Assert.Equal(0, window[0]);
    }

    [Fact]
    public void Rate_window_empties_as_time_passes_the_window()
    {
        var model = new WatchModel(rateWindowSeconds: 3);
        model.Add(Event(EvidenceKind.Finding, at: T0));

        // Six seconds later the one event has aged out of a three-second window.
        model.Tick(T0.AddSeconds(6));
        var window = model.RateWindow(T0.AddSeconds(6));

        Assert.All(window, count => Assert.Equal(0, count));
    }
}
