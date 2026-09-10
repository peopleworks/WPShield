namespace WPShield.Cli.Watch;

/// <summary>
/// The running state the console renders: the most recent events, the counts since it started, and a
/// per-second rate for the sparkline.
/// </summary>
/// <remarks>
/// <para>
/// Pure and synchronous. It is fed one event at a time and asked for a snapshot; the tail reader and
/// the Spectre rendering stay outside it, so what the console counts can be tested without a terminal
/// or a file. The only clock it reads is the one passed to <see cref="Tick"/>, so tests drive time.
/// </para>
/// <para>
/// <b>The counts describe what WPShield saw and did, never total traffic.</b> A clean request that is
/// not a multipart upload is not in the log at all (see <see cref="EvidenceKind"/>), so there is no
/// honest "allowed" total to keep here. Findings, verdicts by action, and the drop notices are all
/// things the log actually contains.
/// </para>
/// </remarks>
internal sealed class WatchModel
{
    /// <summary>How many recent events the feed keeps. Older ones fall off the top.</summary>
    private readonly int _recentCapacity;

    /// <summary>How many one-second buckets the sparkline spans.</summary>
    private readonly int _rateWindowSeconds;

    private readonly Queue<EvidenceEvent> _recent = new();

    /// <summary>Event count keyed by unix second. Seconds older than the window are pruned on write.</summary>
    private readonly Dictionary<long, int> _rate = new();

    public WatchModel(int recentCapacity = 200, int rateWindowSeconds = 30)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(recentCapacity, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(rateWindowSeconds, 1);

        _recentCapacity = recentCapacity;
        _rateWindowSeconds = rateWindowSeconds;
    }

    public long Findings { get; private set; }

    public long Observed { get; private set; }

    public long Blocked { get; private set; }

    public long AllowedUploads { get; private set; }

    public long Dropped { get; private set; }

    /// <summary>Every security-relevant line seen, the denominator the rate is drawn from.</summary>
    public long Events { get; private set; }

    /// <summary>The first event's time, so the console can show how long it has been watching.</summary>
    public DateTimeOffset? FirstSeen { get; private set; }

    public DateTimeOffset? LastSeen { get; private set; }

    /// <summary>
    /// Records one event. Lines classified <see cref="EvidenceKind.Other"/> are ignored: they are
    /// startup and configuration noise, not something the console counts or shows.
    /// </summary>
    public void Add(EvidenceEvent evidence)
    {
        ArgumentNullException.ThrowIfNull(evidence);

        if (evidence.Kind == EvidenceKind.Other)
        {
            return;
        }

        FirstSeen ??= evidence.Timestamp;
        LastSeen = evidence.Timestamp;
        Events++;

        switch (evidence.Kind)
        {
            case EvidenceKind.Finding:
                Findings++;
                break;

            case EvidenceKind.Verdict:
                switch (evidence.Action)
                {
                    case EvidenceAction.Block:
                        Blocked++;
                        break;
                    case EvidenceAction.Observe:
                        Observed++;
                        break;
                    case EvidenceAction.Allow:
                        AllowedUploads++;
                        break;
                }

                break;

            case EvidenceKind.DroppedNotice:
                Dropped++;
                break;
        }

        if (evidence.Kind != EvidenceKind.DroppedNotice)
        {
            _recent.Enqueue(evidence);
            while (_recent.Count > _recentCapacity)
            {
                _recent.Dequeue();
            }
        }

        BumpRate(evidence.Timestamp);
    }

    /// <summary>The most recent events, oldest first.</summary>
    public IReadOnlyList<EvidenceEvent> Recent => _recent.ToArray();

    /// <summary>
    /// Advances the clock so the rate window drops seconds that have aged out even when nothing is
    /// arriving. Without it the sparkline would freeze on the last busy second during a quiet spell.
    /// </summary>
    public void Tick(DateTimeOffset now) => Prune(ToSecond(now));

    /// <summary>
    /// The per-second event counts across the rate window, oldest bucket first, one entry per second
    /// including the empty ones, anchored to <paramref name="now"/>.
    /// </summary>
    public IReadOnlyList<int> RateWindow(DateTimeOffset now)
    {
        var end = ToSecond(now);
        var start = end - _rateWindowSeconds + 1;

        var window = new int[_rateWindowSeconds];
        for (var second = start; second <= end; second++)
        {
            window[second - start] = _rate.TryGetValue(second, out var count) ? count : 0;
        }

        return window;
    }

    private void BumpRate(DateTimeOffset timestamp)
    {
        var second = ToSecond(timestamp);
        _rate[second] = _rate.GetValueOrDefault(second) + 1;
        Prune(second);
    }

    /// <summary>Drops buckets older than the window relative to the newest second seen.</summary>
    private void Prune(long newestSecond)
    {
        var cutoff = newestSecond - _rateWindowSeconds + 1;
        if (_rate.Count == 0)
        {
            return;
        }

        var stale = _rate.Keys.Where(second => second < cutoff).ToArray();
        foreach (var second in stale)
        {
            _rate.Remove(second);
        }
    }

    private static long ToSecond(DateTimeOffset moment) => moment.ToUnixTimeSeconds();
}
