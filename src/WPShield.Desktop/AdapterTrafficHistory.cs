namespace WPShield.Desktop;

internal readonly record struct AdapterCounters(long Received, long Sent);

internal enum RateStatus { Measured, Baseline, Unavailable, CounterReset, Delayed, ClockChanged }

internal sealed record AdapterRate(DateTimeOffset EndUtc, double? Received, double? Sent, RateStatus Status);

internal sealed class AdapterTrafficHistory
{
    internal const int Capacity = 30;
    private readonly Queue<AdapterRate> rows = new(Capacity);
    private AdapterCounters? previous;
    private DateTimeOffset previousUtc;
    private TimeSpan previousElapsed;
    internal AdapterRate[] Snapshot() => rows.ToArray();

    internal void Add(DateTimeOffset utc, TimeSpan elapsed, AdapterCounters? counters)
    {
        var interval = elapsed - previousElapsed;
        var status = RateStatus.Baseline;
        double? received = null;
        double? sent = null;
        if (counters is null or { Received: < 0 } or { Sent: < 0 })
        {
            counters = null;
            status = RateStatus.Unavailable;
        }
        else if (previous is { } first && counters is { } last)
        {
            if (interval <= TimeSpan.Zero || utc < previousUtc || ((utc - previousUtc) - interval).Duration() > TimeSpan.FromSeconds(1))
                status = RateStatus.ClockChanged;
            else if (interval > TimeSpan.FromSeconds(5)) status = RateStatus.Delayed;
            else if (last.Received < first.Received || last.Sent < first.Sent) status = RateStatus.CounterReset;
            else
            {
                received = (last.Received - first.Received) / interval.TotalSeconds;
                sent = (last.Sent - first.Sent) / interval.TotalSeconds;
                status = RateStatus.Measured;
            }
        }
        if (rows.Count == Capacity) rows.Dequeue();
        rows.Enqueue(new(utc, received, sent, status));
        previous = counters;
        previousElapsed = elapsed;
        previousUtc = utc;
    }
}
