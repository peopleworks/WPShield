using WPShield.NetworkFilter.Rules;

namespace WPShield.NetworkFilter;

/// <summary>
/// Decides when a finding is worth a log line: the first time a source crosses a threshold, whenever
/// its score rises, and at most once a minute while it stays there. One line per SYN would let any
/// scanner write the log at line rate.
/// </summary>
internal sealed class FindingThrottle
{
    private static readonly TimeSpan Quiet = TimeSpan.FromMinutes(1);

    private readonly BoundedSourceTable<State> _seen;
    private readonly object _gate = new();

    public FindingThrottle(int capacity)
    {
        _seen = new BoundedSourceTable<State>(capacity);
    }

    public bool ShouldReport(string ruleId, string source, int score, DateTimeOffset now)
    {
        lock (_gate)
        {
            var state = _seen.GetOrAdd(ruleId + "|" + source, () => new State());
            if (state.LastReported is null || score > state.Score || now - state.LastReported.Value >= Quiet)
            {
                state.Score = score;
                state.LastReported = now;
                return true;
            }

            return false;
        }
    }

    private sealed class State
    {
        public int Score { get; set; }

        public DateTimeOffset? LastReported { get; set; }
    }
}
