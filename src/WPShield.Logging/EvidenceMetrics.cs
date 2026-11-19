using System.Diagnostics.Metrics;

namespace WPShield.Logging;

/// <summary>Process-lifetime counters read by local diagnostics even while file logging is unavailable.</summary>
public sealed class EvidenceMetrics : IDisposable
{
    private readonly Meter _meter;
    private long _dropped;
    private long _failed;
    private long _skipped;

    public EvidenceMetrics(bool fileEnabled)
    {
        _meter = new Meter(new MeterOptions("WPShield.Evidence") { Scope = this });
        _meter.CreateObservableCounter("wpshield.evidence.queue_drops", () => Interlocked.Read(ref _dropped));
        _meter.CreateObservableCounter("wpshield.evidence.failed_batches", () => Interlocked.Read(ref _failed));
        _meter.CreateObservableCounter("wpshield.evidence.skipped_stages", () => Interlocked.Read(ref _skipped));
        _meter.CreateObservableGauge("wpshield.evidence.file_enabled", () => fileEnabled ? 1L : 0L);
        _meter.CreateObservableGauge("wpshield.evidence.degraded", () =>
            Interlocked.Read(ref _dropped) > 0 || Interlocked.Read(ref _failed) > 0 ? 1L : 0L);
    }

    internal void RecordDrop() => Interlocked.Increment(ref _dropped);
    internal void RecordFailedBatch() => Interlocked.Increment(ref _failed);
    public void RecordSkippedStage() => Interlocked.Increment(ref _skipped);
    public void Dispose() => _meter.Dispose();
}
