using System.Windows;
using System.Windows.Controls;
using WPShield.NetworkSensor;
using Xunit;

namespace WPShield.Desktop.Tests;

public sealed class PortTrafficWindowTests
{
    private static readonly FlowInterface Adapter = new("synthetic-id", "Test adapter", null, true, false);

    [Theory]
    [InlineData("")]
    [InlineData("80,,443")]
    [InlineData("0")]
    [InlineData("65536")]
    [InlineData("all")]
    [InlineData("80\0")]
    public void InvalidPortsNeverWidenTheCapture(string text) => Assert.Empty(PortTrafficWindow.ParsePorts(text));

    [Fact]
    public void PortBudgetIncludesDuplicatesAndHandlesBothBoundaries()
    {
        Assert.Equal([1, 443, 65535], PortTrafficWindow.ParsePorts("65535, 443,1,443"));
        Assert.Equal(64, PortTrafficWindow.ParsePorts(string.Join(",", Enumerable.Range(1, 64))).Length);
        Assert.Empty(PortTrafficWindow.ParsePorts(string.Join(",", Enumerable.Repeat("443", 65))));
    }

    [Theory]
    [InlineData(false, "administrator")]
    [InlineData(true, "administrador")]
    public Task OpeningWithoutElevationShowsThePrerequisiteWithoutAccessingNpcap(bool spanish, string prerequisite) =>
        DesktopDispatcher.RunAsync(async () =>
        {
            var view = new PortTrafficWindow(spanish, false, () => throw new Exception("Unexpected Npcap query"),
                (_, _, _, _) => throw new Exception("Unexpected capture"));
            try
            {
                await view.ReadAdaptersAsync();
                Assert.Contains(prerequisite, view.Status.Text);
                Assert.True(view.Ports.IsEnabled);
                Assert.True(view.PortChoices.IsEnabled);
                view.Ports.Text = "8443";
                view.PortChoices.SelectedValue = 3389;
                Assert.True(view.AddPort.IsEnabled);
                view.AddPort.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                Assert.Equal([3389, 8443], PortTrafficWindow.ParsePorts(view.Ports.Text));
                Assert.False(view.AddPort.IsEnabled);
                Assert.False(view.Start.IsEnabled);
                await view.RunCaptureAsync();
            }
            finally { view.Close(); }
        });

    [Fact]
    public Task PickerIncludesObservedPortsAndPreservesInvalidOrFullInput() =>
        DesktopDispatcher.RunAsync(() =>
        {
            var view = new PortTrafficWindow(true, false, () => [], (_, _, _, _) => throw new Exception("Unexpected capture"),
                () => [443, 8443, 8443]);
            try
            {
                Assert.Equal(5, view.PortChoices.Items.Count);
                view.PortChoices.SelectedValue = 8443;
                Assert.True(view.AddPort.IsEnabled);
                foreach (var text in new[] { "443,", string.Join(',', Enumerable.Range(1, 64)) })
                {
                    view.Ports.Text = text;
                    Assert.False(view.AddPort.IsEnabled);
                    view.AddPort.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                    Assert.Equal(text, view.Ports.Text);
                }
                view.Ports.Text = "";
                view.AddPort.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                Assert.Equal("8443", view.Ports.Text);
            }
            finally { view.Close(); }
            return Task.CompletedTask;
        });

    [Theory]
    [InlineData(false, "Observed", "Unknown", "Gap", "Capture stopped.")]
    [InlineData(true, "Observada", "Desconocida", "Intervalo sin medición", "Captura detenida.")]
    public Task PauseKeepsSamplingAndStopRetainsTheFinalHistory(bool spanish, string observed, string unknown, string gap, string stopped) =>
        DesktopDispatcher.RunAsync(async () =>
        {
            using var advance = new ManualResetEventSlim();
            var first = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var second = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var start = DateTimeOffset.UnixEpoch;
            var rx = new TrafficInterval(start, start.AddSeconds(2), 2, 200, 0, 0, 0, []);
            var tx = new TrafficInterval(rx.EndUtc, start.AddSeconds(4), 2, 0, 400, 0, null, []);
            var loss = new TrafficInterval(tx.EndUtc, start.AddSeconds(6), 2, 200, 200, 1, 0, ["skipped-packets"]);
            var snapshot = new FlowSnapshot(Adapter.DeviceId, start, 0, 0, 0, null, []);
            var view = new PortTrafficWindow(spanish, true, () => [Adapter], (id, ports, publish, token) =>
            {
                Assert.Equal(Adapter.DeviceId, id);
                Assert.Equal([80, 443], ports);
                publish(snapshot with { History = [rx] });
                first.SetResult();
                Assert.True(advance.Wait(TimeSpan.FromSeconds(10), token));
                publish(snapshot with { History = [rx, tx] });
                second.SetResult();
                Assert.True(token.WaitHandle.WaitOne(TimeSpan.FromSeconds(10)));
                publish(snapshot with { History = [rx, tx, loss], CaptureStatus = "stopped" });
            });
            try
            {
                await view.ReadAdaptersAsync();
                Assert.False(view.Start.IsEnabled);
                view.Adapters.SelectedIndex = 0;
                view.Ports.Text = "443,80";
                Assert.True(view.Start.IsEnabled);
                var running = view.RunCaptureAsync();
                await first.Task.WaitAsync(TimeSpan.FromSeconds(10));
                Assert.False(view.Start.IsEnabled);
                view.RenderLatest();
                Assert.False(view.Ports.IsEnabled);
                Assert.False(view.PortChoices.IsEnabled);
                var row = Assert.IsType<PortTrafficWindow.IntervalRow>(view.Rows.Items[0]);
                Assert.Equal(observed, row.Coverage);
                Assert.Equal(1, row.ReceiveFraction);
                view.Pause.IsChecked = true;
                advance.Set();
                await second.Task.WaitAsync(TimeSpan.FromSeconds(10));
                view.RenderLatest();
                Assert.Single(view.Rows.Items);
                view.Pause.IsChecked = false;
                Assert.Equal(2, view.Rows.Items.Count);
                var newest = Assert.IsType<PortTrafficWindow.IntervalRow>(view.Rows.Items[0]);
                Assert.StartsWith(unknown, newest.Coverage);
                Assert.Equal(1, newest.SendFraction);
                view.Stop.RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                await running;
                newest = Assert.IsType<PortTrafficWindow.IntervalRow>(view.Rows.Items[0]);
                Assert.StartsWith(gap, newest.Coverage);
                Assert.True(newest.IsGap);
                Assert.Contains("skipped-packets", newest.Details);
                Assert.Equal("—", newest.Received);
                Assert.Equal(stopped, view.Status.Text);
                Assert.True(view.Start.IsEnabled);
            }
            finally { advance.Set(); view.Close(); }
        });

    [Fact]
    public Task FailedInventoryAndRemovedAdapterClearPriorSelection() =>
        DesktopDispatcher.RunAsync(async () =>
        {
            var reads = 0;
            var view = new PortTrafficWindow(false, true, () => ++reads switch
            {
                1 => [Adapter],
                2 => [Adapter with { DeviceId = "another-id" }],
                _ => throw new DllNotFoundException()
            }, (_, _, _, _) => throw new Exception("Unexpected capture"));
            try
            {
                await view.ReadAdaptersAsync();
                view.Adapters.SelectedIndex = 0;
                view.Ports.Text = "443";
                Assert.True(view.Start.IsEnabled);
                await view.ReadAdaptersAsync();
                Assert.Null(view.Adapters.SelectedItem);
                Assert.False(view.Start.IsEnabled);
                await view.ReadAdaptersAsync();
                Assert.Empty(view.Adapters.Items);
                Assert.Contains("Npcap", view.Status.Text);
            }
            finally { view.Close(); }
        });

    [Fact]
    public Task ClosingAnActiveWindowCancelsAndWaitsForTheWorker() =>
        DesktopDispatcher.RunAsync(async () =>
        {
            var entered = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var exited = false;
            var view = new PortTrafficWindow(false, true, () => [Adapter], (_, _, _, token) =>
            {
                entered.SetResult();
                Assert.True(token.WaitHandle.WaitOne(TimeSpan.FromSeconds(10)));
                exited = true;
            });
            var wasClosed = false;
            view.Closed += (_, _) => wasClosed = exited;
            await view.ReadAdaptersAsync();
            view.Adapters.SelectedIndex = 0;
            view.Ports.Text = "443";
            var running = view.RunCaptureAsync();
            await entered.Task.WaitAsync(TimeSpan.FromSeconds(10));
            view.Close();
            await running;
            Assert.True(wasClosed);
        });
}
