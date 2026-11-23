using System.Net.NetworkInformation;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;

namespace WPShield.Desktop;

public partial class AdapterTrafficWindow : Window
{
    private sealed record Adapter(string Id, string Name);

    private readonly bool spanish;
    private readonly DispatcherTimer timer = new() { Interval = TimeSpan.FromSeconds(2) };
    private readonly long origin = TimeProvider.System.GetTimestamp();
    private static readonly Brush Inbound = new SolidColorBrush(Color.FromRgb(26, 119, 113));
    private static readonly Brush Outbound = new SolidColorBrush(Color.FromRgb(80, 105, 167));
    private static readonly Brush Gap = new SolidColorBrush(Color.FromRgb(193, 135, 56));
    private AdapterTrafficHistory history = new();
    private AdapterRate[] displayed = [];
    private bool reading;
    private bool listing;
    private bool closed;

    internal AdapterTrafficWindow(bool spanish)
    {
        this.spanish = spanish;
        InitializeComponent();
        Heading.Text = L("Adapter traffic", "Tráfico por adaptador");
        Title = "WPShield | " + Heading.Text;
        AdapterLabel.Content = L("_Adapter", "_Adaptador");
        Reload.Content = L("Refresh list", "Actualizar lista");
        ReceiveLabel.Text = L("↓  Received", "↓  Entrada");
        SendLabel.Text = L("↑  Sent", "↑  Salida");
        Pause.Content = L("Pause chart", "Pausar gráfica");
        GapLabel.Text = L("■  Measurement gap", "■  Intervalo sin medición");
        timer.Tick += Sample;
        Render();
    }

    private string L(string english, string es) => spanish ? es : english;

    private static bool Unavailable(Exception ex) => ex is NetworkInformationException or UnauthorizedAccessException
        or System.Security.SecurityException or PlatformNotSupportedException;

    private async void LoadAdapters(object sender, RoutedEventArgs e)
    {
        if (listing) return;
        listing = true;
        Reload.IsEnabled = false;
        Adapters.IsEnabled = false;
        var selected = (Adapters.SelectedItem as Adapter)?.Id;
        try
        {
            var choices = await Task.Run(() => NetworkInterface.GetAllNetworkInterfaces()
                .OrderBy(n => n.Name, StringComparer.CurrentCultureIgnoreCase)
                .Select(n => new Adapter(n.Id, n.Name)).ToArray());
            if (closed) return;
            Adapters.ItemsSource = choices;
            Adapters.SelectedItem = choices.FirstOrDefault(a => a.Id == selected);
            if (selected is not null && Adapters.SelectedItem is null) ResetSampling();
            if (Adapters.SelectedItem is null)
                Status.Text = choices.Length == 0 ? L("Windows reported no adapters.", "Windows no encontró adaptadores.") :
                    L("Select an adapter to start measuring.", "Seleccione un adaptador para iniciar la medición.");
        }
        catch (Exception ex) when (Unavailable(ex))
        {
            if (closed) return;
            Adapters.ItemsSource = null;
            ResetSampling();
            Status.Text = L("Cannot read the Windows adapter list.", "No se pudo leer la lista de adaptadores de Windows.");
        }
        finally
        {
            Reload.IsEnabled = true;
            Adapters.IsEnabled = true;
            listing = false;
        }
    }

    private void ChangeAdapter(object sender, SelectionChangedEventArgs e)
    {
        if (!listing) ResetSampling();
    }

    private void ResetSampling()
    {
        timer.Stop();
        history = new();
        displayed = [];
        Pause.IsChecked = false;
        Render();
        if (Adapters.SelectedItem is Adapter)
        {
            Status.Text = L("Reading adapter counters…", "Leyendo los contadores del adaptador…");
            timer.Start();
            Sample(this, EventArgs.Empty);
        }
    }

    private async void Sample(object? sender, EventArgs e)
    {
        if (reading || closed || Adapters.SelectedItem is not Adapter adapter) return;
        var target = history;
        reading = true;
        try
        {
            var observation = await Task.Run(() =>
            {
                AdapterCounters? counters = null;
                try
                {
                    var current = NetworkInterface.GetAllNetworkInterfaces().FirstOrDefault(n => n.Id == adapter.Id);
                    if (current?.OperationalStatus == OperationalStatus.Up)
                    {
                        var stats = current.GetIPStatistics();
                        counters = new(stats.BytesReceived, stats.BytesSent);
                    }
                }
                catch (Exception ex) when (Unavailable(ex)) { /* Record an unavailable observation. */ }
                return (counters, Utc: DateTimeOffset.UtcNow, Elapsed: TimeProvider.System.GetElapsedTime(origin));
            });
            if (closed || target != history) return;
            target.Add(observation.Utc, observation.Elapsed, observation.counters);
            if (Pause.IsChecked != true) ShowLatest();
        }
        finally { reading = false; }
    }

    private void ChangePause(object sender, RoutedEventArgs e)
    {
        if (Pause.IsChecked == true)
            Status.Text = L("Chart paused. Adapter sampling continues.", "Gráfica en pausa. La medición del adaptador continúa.");
        else ShowLatest();
    }

    private void ShowLatest()
    {
        displayed = history.Snapshot();
        Render();
        if (displayed.LastOrDefault() is { } latest) Status.Text = $"{latest.EndUtc:HH:mm:ss} UTC  ·  {Describe(latest.Status)}";
    }

    private string Describe(RateStatus status) => status switch
    {
        RateStatus.Measured => L("Windows adapter counters · all ports", "Contadores de Windows del adaptador · todos los puertos"),
        RateStatus.Baseline => L("Waiting for a second reading", "Esperando la segunda lectura"),
        RateStatus.Unavailable => L("Adapter or counters unavailable", "Adaptador o contadores no disponibles"),
        RateStatus.CounterReset => L("Counter reset", "Reinicio de contador"),
        RateStatus.Delayed => L("Delayed reading", "Lectura tardía"),
        _ => L("Clock discontinuity", "Discontinuidad del reloj")
    };

    private static string Rate(double? bytes) => bytes switch
    {
        null => "—",
        >= 1048576 => $"{bytes / 1048576:N1} MiB/s",
        >= 1024 => $"{bytes / 1024:N1} KiB/s",
        _ => $"{bytes:N1} B/s"
    };

    private void ResizePlot(object sender, SizeChangedEventArgs e) => Render();

    private void Render()
    {
        var last = displayed.LastOrDefault();
        ReceiveRate.Text = Rate(last?.Received);
        SendRate.Text = Rate(last?.Sent);
        Pause.IsEnabled = Adapters.SelectedItem is Adapter;
        var maximum = displayed.Select(row => Math.Max(row.Received ?? 0, row.Sent ?? 0)).DefaultIfEmpty().Max();
        Scale.Text = L("Interval history", "Historial por intervalo") +
            (maximum > 0 ? $"   ·   {L("Peak", "Máximo")} {Rate(maximum)}" : "");
        RangeLabel.Text = displayed.Length > 0 ? $"{displayed[0].EndUtc:HH:mm:ss} – {last!.EndUtc:HH:mm:ss} UTC" : "—";
        Plot.Children.Clear();
        foreach (var row in displayed)
        {
            var pair = new System.Windows.Controls.Primitives.UniformGrid
            {
                Columns = 2,
                Rows = 1,
                Margin = new Thickness(1, 0, 1, 0),
                Background = Brushes.Transparent
            };
            var label = $"{row.EndUtc:HH:mm:ss} UTC  ·  {Describe(row.Status)}";
            if (row.Received.HasValue)
            {
                label += $"   ↓ {Rate(row.Received)}   ↑ {Rate(row.Sent)}";
                pair.Children.Add(Bar(Inbound, row.Received.Value));
                pair.Children.Add(Bar(Outbound, row.Sent!.Value));
            }
            else if (row.Status != RateStatus.Baseline)
                pair.Children.Add(new Border { Background = Gap, Height = 8, VerticalAlignment = VerticalAlignment.Bottom });
            pair.ToolTip = label;
            AutomationProperties.SetName(pair, label);
            Plot.Children.Add(pair);
        }
        Border Bar(Brush brush, double value) => new()
        {
            Background = brush,
            VerticalAlignment = VerticalAlignment.Bottom,
            Height = maximum > 0 ? value / maximum * Plot.ActualHeight : 0
        };
    }

    private void OnClosed(object? sender, EventArgs e)
    {
        closed = true;
        timer.Stop();
    }
}
