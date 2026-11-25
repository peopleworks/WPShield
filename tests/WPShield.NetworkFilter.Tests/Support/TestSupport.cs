using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;

namespace WPShield.NetworkFilter.Tests.Support;

internal sealed class ManualTimeProvider : TimeProvider
{
    private DateTimeOffset _now = new(2026, 11, 1, 12, 0, 0, TimeSpan.Zero);

    public override DateTimeOffset GetUtcNow() => _now;

    public void Advance(TimeSpan by) => _now += by;

    /// <summary>Timers never fire on their own; tests call Maintain() when they mean it.</summary>
    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period) => new InertTimer();

    private sealed class InertTimer : ITimer
    {
        public bool Change(TimeSpan dueTime, TimeSpan period) => true;

        public void Dispose()
        {
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }
}

internal sealed class RecordingSink : INetworkFilterEventSink
{
    private readonly ConcurrentQueue<NetworkFilterEvent> _events = new();

    public IReadOnlyList<NetworkFilterEvent> Events => [.. _events];

    public IEnumerable<NetworkFilterEvent> WithAction(string action) =>
        Events.Where(e => e.State.TryGetValue("action", out var value) && (string)value == action);

    public void Write(NetworkFilterEvent networkFilterEvent) => _events.Enqueue(networkFilterEvent);
}

internal static class Ranges
{
    public static IpRange Block(string text) =>
        IpRange.TryParseBlock(text, out var range, out var error) ? range! : throw new InvalidOperationException(error);

    public static IpRange Allow(string text) =>
        IpRange.TryParseAllow(text, out var range, out var error) ? range! : throw new InvalidOperationException(error);

    public static IPAddress Ip(string text) => IPAddress.Parse(text);
}
