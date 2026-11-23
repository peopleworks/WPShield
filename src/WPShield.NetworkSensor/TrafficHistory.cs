namespace WPShield.NetworkSensor;

public sealed record TrafficInterval(DateTimeOffset StartUtc, DateTimeOffset EndUtc, double Seconds,
    long ReceivedBytes, long SentBytes, long SkippedPackets, uint? DriverDrops, IReadOnlyList<string> GapReasons)
{
    public string Coverage => GapReasons.Count > 0 ? "gap" : DriverDrops.HasValue ? "observed" : "unknown";
    public double? ReceivedBytesPerSecond => GapReasons.Count == 0 && Seconds > 0 ? ReceivedBytes / Seconds : null;
    public double? SentBytesPerSecond => GapReasons.Count == 0 && Seconds > 0 ? SentBytes / Seconds : null;
}

// The capture lock protects packet accounting and interval rollover together.
internal sealed class TrafficHistory(TimeProvider clock, DateTimeOffset startUtc, uint? initialDrops, long initialSkipped)
{
    internal const int Capacity = 30;
    private readonly Queue<TrafficInterval> _intervals = new(Capacity);
    private DateTimeOffset _start = startUtc;
    private long _timestamp = clock.GetTimestamp();
    private uint? _previousDrops = initialDrops;
    private long _previousSkipped = initialSkipped;
    private long _received;
    private long _sent;

    internal void Count(bool outbound, int bytes)
    {
        if (outbound) _sent += bytes;
        else _received += bytes;
    }

    internal TrafficInterval[] Finish(DateTimeOffset end, uint? drops, long skipped, bool interrupted)
    {
        var timestamp = clock.GetTimestamp();
        var elapsed = clock.GetElapsedTime(_timestamp, timestamp);
        var reasons = new List<string>();
        if (interrupted) reasons.Add("capture-stopped");
        if (elapsed > TimeSpan.FromSeconds(5)) reasons.Add("sample-delayed");
        if (elapsed <= TimeSpan.Zero || end < _start || ((end - _start) - elapsed).Duration() > TimeSpan.FromSeconds(1))
            reasons.Add("clock-discontinuity");
        var skippedDelta = skipped - _previousSkipped;
        if (skippedDelta > 0) reasons.Add("skipped-packets");
        uint? dropDelta = null;
        if (drops is uint current && _previousDrops is uint previous)
        {
            if (current < previous) reasons.Add("driver-counter-reset");
            else
            {
                dropDelta = current - previous;
                if (dropDelta > 0) reasons.Add("driver-drops");
            }
        }
        if (_intervals.Count == Capacity) _intervals.Dequeue();
        _intervals.Enqueue(new(_start, end, elapsed.TotalSeconds, _received, _sent,
            skippedDelta, dropDelta, reasons.ToArray()));
        _timestamp = timestamp;
        _start = end;
        _received = _sent = 0;
        _previousDrops = drops;
        _previousSkipped = skipped;
        return _intervals.ToArray();
    }
}
