using System.Diagnostics.Metrics;
using WPShield.Logging;

namespace WPShield.Gateway.Tests;

internal static class EvidenceMetricSnapshot
{
    public static Dictionary<string, long> Read(EvidenceMetrics metrics)
    {
        using var listener = new MeterListener();
        var result = new Dictionary<string, long>();
        listener.InstrumentPublished = (instrument, subscriber) =>
        {
            if (instrument.Meter.Name == "WPShield.Evidence" && instrument.Meter.Scope == metrics)
                subscriber.EnableMeasurementEvents(instrument);
        };
        listener.SetMeasurementEventCallback<long>((instrument, value, tags, _) =>
        {
            Assert.True(tags.IsEmpty);
            result.Add(instrument.Name, value);
        });
        listener.Start();
        listener.RecordObservableInstruments();
        return result;
    }
}
