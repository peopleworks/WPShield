namespace WPShield.NetworkFilter;

/// <summary>Rate-limits repeated refusal or preview events for one rule and address.</summary>
internal sealed class FindingThrottle
{
    private static readonly TimeSpan Quiet = TimeSpan.FromMinutes(1);

    private readonly BoundedSourceTable<State> _seen;
    private readonly object _gate = new();

    public FindingThrottle(int capacity)
    {
        _seen = new BoundedSourceTable<State>(capacity);
    }

    public bool ShouldReport(string ruleId, string source, DateTimeOffset now)
    {
        lock (_gate)
        {
            var state = _seen.GetOrAdd(ruleId + "|" + source, () => new State());
            if (state.LastReported is null || now - state.LastReported.Value >= Quiet)
            {
                state.LastReported = now;
                return true;
            }

            return false;
        }
    }

    private sealed class State
    {
        public DateTimeOffset? LastReported { get; set; }
    }
}
