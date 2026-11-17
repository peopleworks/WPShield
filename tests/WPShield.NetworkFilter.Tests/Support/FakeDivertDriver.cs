using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Xunit;

namespace WPShield.NetworkFilter.Tests.Support;

/// <summary>
/// Stands in for WinDivert. Records every handle opened and disposed, and evaluates filters with
/// <see cref="ReferenceFilterEvaluator"/>, an independent reading of the subset of the WinDivert filter
/// language WPShield writes. That makes the filter tests about meaning, not text; whether the real
/// library agrees is what the opt-in <c>RealWinDivertSelfTest</c> and the self-test itself establish.
/// </summary>
internal sealed class FakeDivertDriver : IDivertDriver
{
    private readonly ConcurrentQueue<FakeHandle> _opened = new();

    public Func<string, bool> CompileFails { get; set; } = _ => false;

    public Func<string, DivertHandleKind, bool> OpenFails { get; set; } = (_, _) => false;

    public Func<string, IPAddress, bool?>? EvaluateOverride { get; set; }

    public int CompileCalls { get; private set; }

    public IReadOnlyList<FakeHandle> Opened => [.. _opened];

    public IReadOnlyList<FakeHandle> Live(DivertHandleKind kind) =>
        [.. _opened.Where(handle => handle.Kind == kind && !handle.IsDisposed)];

    public IDivertHandle Open(string filter, DivertHandleKind kind, short priority)
    {
        if (OpenFails(filter, kind))
        {
            throw new DivertDriverException("fake: open refused", DivertDriverException.ErrorServiceDoesNotExist);
        }

        var handle = new FakeHandle(filter, kind, priority);
        _opened.Enqueue(handle);
        return handle;
    }

    public FilterCompileResult Compile(string filter)
    {
        CompileCalls++;
        if (CompileFails(filter))
        {
            return new FilterCompileResult(false, "fake: rejected", 0);
        }

        return ReferenceFilterEvaluator.TryParse(filter, out _)
            ? FilterCompileResult.Success
            : new FilterCompileResult(false, "fake: unparseable", 0);
    }

    public bool Evaluate(string filter, byte[] packet, bool isIpv6)
    {
        Assert.True(PacketHeaderParser.TryParse(packet, out var headers));
        if (EvaluateOverride?.Invoke(filter, headers.Source) is { } forced)
        {
            return forced;
        }

        return ReferenceFilterEvaluator.Evaluate(filter, headers);
    }
}

internal sealed class FakeHandle : IDivertHandle
{
    private readonly BlockingCollection<byte[]> _packets = new();

    public FakeHandle(string filter, DivertHandleKind kind, short priority)
    {
        Filter = filter;
        Kind = kind;
        Priority = priority;
    }

    public string Filter { get; }

    public DivertHandleKind Kind { get; }

    public short Priority { get; }

    public bool IsDisposed { get; private set; }

    public void Deliver(byte[] packet) => _packets.Add(packet);

    public int Receive(byte[] buffer)
    {
        Assert.Equal(DivertHandleKind.Observe, Kind);
        try
        {
            var packet = _packets.Take();
            packet.CopyTo(buffer, 0);
            return packet.Length;
        }
        catch (InvalidOperationException)
        {
            return 0;
        }
    }

    public void Shutdown() => _packets.CompleteAdding();

    public void Dispose()
    {
        IsDisposed = true;
        _packets.CompleteAdding();
    }
}
