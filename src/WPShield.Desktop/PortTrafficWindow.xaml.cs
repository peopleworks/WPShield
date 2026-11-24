using System.ComponentModel;
using System.Globalization;
using System.Net.NetworkInformation;
using System.Windows;
using System.Windows.Threading;
using WPShield.Cli;
using WPShield.NetworkSensor;

namespace WPShield.Desktop;

public partial class PortTrafficWindow : Window
{
    internal delegate void Capture(string deviceId, int[] ports, Action<FlowSnapshot> publish, CancellationToken token);
    private sealed record Choice(string Id, string Label);
    private sealed record PortChoice(int Port, string Label);
    internal sealed record IntervalRow(string Interval, string Received, string Sent, double ReceiveFraction, double SendFraction,
        string Coverage, string Details, bool IsGap);

    private readonly bool spanish;
    private readonly bool elevated;
    private readonly Func<IReadOnlyList<FlowInterface>> list;
    private readonly Capture run;
    private readonly Func<IEnumerable<int>> observedPorts;
    private readonly DispatcherTimer timer = new() { Interval = TimeSpan.FromMilliseconds(500) };
    private CancellationTokenSource? session;
    private IReadOnlyList<TrafficInterval> latest = [];
    private IReadOnlyList<TrafficInterval>? displayed;
    private bool listing;
    private bool closing;
    private bool closed;

    internal PortTrafficWindow(bool spanish, Func<IEnumerable<int>> observedPorts) : this(spanish, NetworkMonitorCommand.IsElevated(), HostFlowMonitor.ListInterfaces,
        (id, ports, publish, token) => HostFlowMonitor.Run(id, ports, false, publish, token, includeAllRows: false, includeHistory: true), observedPorts)
    { }

    internal PortTrafficWindow(bool spanish, bool elevated, Func<IReadOnlyList<FlowInterface>> list, Capture run, Func<IEnumerable<int>>? observedPorts = null)
    {
        this.spanish = spanish;
        this.elevated = elevated;
        this.list = list;
        this.run = run;
        this.observedPorts = observedPorts ?? (() => []);
        InitializeComponent();
        Heading.Text = L("Port traffic", "Tráfico por puertos");
        Title = "WPShield | " + Heading.Text;
        AdapterLabel.Content = L("_Adapter", "_Adaptador");
        Reload.Content = L("Refresh list", "Actualizar lista");
        PortLabel.Content = L("_TCP/UDP ports", "_Puertos TCP/UDP");
        PortChoicesLabel.Content = L("Port _list", "_Lista de puertos");
        AddPort.Content = L("Add port", "Añadir puerto");
        RefreshPortChoices(this, EventArgs.Empty);
        Ports.ToolTip = L("1–64 comma-separated ports", "Entre 1 y 64 puertos separados por comas");
        Start.Content = L("Start capture", "Iniciar captura");
        Stop.Content = L("Stop", "Detener");
        Pause.Content = L("Pause chart", "Pausar gráfica");
        IntervalColumn.Header = L("UTC interval", "Intervalo UTC");
        ReceiveColumn.Header = L("Received (B/s)", "Entrada (B/s)");
        SendColumn.Header = L("Sent (B/s)", "Salida (B/s)");
        CoverageColumn.Header = L("Coverage", "Cobertura");
        Scope.Text = L("Observed IP bytes per second", "Bytes IP observados por segundo");
        timer.Tick += (_, _) => RenderLatest();
        UpdateControls();
    }

    private string L(string en, string es) => spanish ? es : en;

    internal static int[] ParsePorts(string text)
    {
        if (text.Length > 448) return [];
        var values = text.Split(',', StringSplitOptions.TrimEntries);
        if (values.Length > 64) return [];
        var result = new SortedSet<int>();
        foreach (var value in values)
        {
            if (value.Any(c => !char.IsAsciiDigit(c)) || !ushort.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var port) || port == 0) return [];
            result.Add(port);
        }
        return [.. result];
    }

    private static bool SourceError(Exception ex) => ex.GetBaseException() is DllNotFoundException or EntryPointNotFoundException or BadImageFormatException
        || ex is InvalidOperationException or SharpPcap.PcapException or NetworkInformationException or UnauthorizedAccessException
        or System.Security.SecurityException or PlatformNotSupportedException;

    private async void LoadAdapters(object sender, RoutedEventArgs e) => await ReadAdaptersAsync();

    internal async Task ReadAdaptersAsync()
    {
        if (!elevated)
        {
            Status.Text = L("You can select ports here. To start capture, open WPShield as administrator on a Windows host with Npcap.",
                "Puede elegir los puertos aquí. Para iniciar la captura, abra WPShield como administrador en un equipo Windows con Npcap.");
            return;
        }
        if (listing || session != null || closed) return;
        var previous = (Adapters.SelectedItem as Choice)?.Id;
        listing = true;
        UpdateControls();
        try
        {
            var found = await Task.Run(list);
            if (closed) return;
            var choices = found.Where(i => i.HasIPv4 || i.HasIPv6).Select(i =>
                new Choice(i.DeviceId, i.FriendlyName is { Length: > 0 } name
                    ? $"{DisplayText.Clean(name, 120)}  ·  {DisplayText.Clean(i.DeviceId, 120)}"
                    : DisplayText.Clean(i.DeviceId, 120))).ToArray();
            Adapters.ItemsSource = choices;
            Adapters.SelectedItem = choices.FirstOrDefault(i => i.Id == previous);
            Status.Text = choices.Length == 0 ? L("No capture adapter with a local IP address.", "No hay un adaptador de captura con IP local.") :
                L("Select an adapter and enter 1–64 ports separated by commas.", "Seleccione un adaptador e indique entre 1 y 64 puertos separados por comas.");
        }
        catch (Exception ex) when (SourceError(ex))
        {
            Adapters.ItemsSource = null;
            Status.Text = L("Cannot list capture adapters. Check Npcap and access permissions.", "No se pudo leer la lista de adaptadores. Compruebe Npcap y los permisos.");
        }
        finally { listing = false; UpdateControls(); }
    }

    private void UpdateScope(object sender, RoutedEventArgs e) => UpdateControls();

    private void RefreshPortChoices(object? sender, EventArgs e)
    {
        var selected = PortChoices.SelectedValue;
        var observed = observedPorts().ToHashSet();
        PortChoices.ItemsSource = observed.Union([80, 443, 1433, 3389]).Order().Select(port =>
        {
            var service = port switch { 80 => "HTTP", 443 => "HTTPS", 1433 => "SQL Server", 3389 => "RDP", _ => "" };
            var label = service.Length == 0 ? $"{port}" : $"{port}  ·  {service}";
            if (observed.Contains(port)) label += L("  ·  Observed locally", "  ·  Observado en este equipo");
            return new PortChoice(port, label);
        }).ToArray();
        PortChoices.SelectedValue = selected;
    }

    private void AddSelectedPort(object sender, RoutedEventArgs e)
    {
        if (!AddPort.IsEnabled || PortChoices.SelectedValue is not int port) return;
        Ports.Text = string.Join(", ", ParsePorts(Ports.Text).Append(port).Distinct().Order());
    }

    private void UpdateControls()
    {
        if (PortHelp is null) return;
        var editable = session is null && !closed;
        var idle = elevated && !listing && editable;
        var ports = ParsePorts(Ports.Text);
        var invalid = ports.Length == 0 && !string.IsNullOrWhiteSpace(Ports.Text);
        Ports.IsEnabled = PortChoices.IsEnabled = editable;
        AddPort.IsEnabled = editable && !invalid && ports.Length < 64 && PortChoices.SelectedValue is int port && !ports.Contains(port);
        PortHelp.Text = invalid ? L("Enter 1–64 ports from 1 to 65535, separated by commas.", "Indique entre 1 y 64 puertos del 1 al 65535, separados por comas.") :
            L("Type ports separated by commas, or select from the list and click Add port.", "Escriba los puertos separados por comas, o elija uno de la lista y pulse Añadir puerto.");
        Adapters.IsEnabled = Reload.IsEnabled = idle;
        Start.IsEnabled = idle && Adapters.SelectedItem is Choice && ports.Length > 0;
        Stop.IsEnabled = Pause.IsEnabled = session is { IsCancellationRequested: false };
    }

    private async void StartCapture(object sender, RoutedEventArgs e) => await RunCaptureAsync();

    internal async Task RunCaptureAsync()
    {
        if (!elevated || listing || closed || session != null || Adapters.SelectedItem is not Choice choice) return;
        var ports = ParsePorts(Ports.Text);
        if (ports.Length == 0) return;
        using var stop = new CancellationTokenSource();
        session = stop;
        Volatile.Write(ref latest, Array.Empty<TrafficInterval>());
        displayed = null;
        Pause.IsChecked = false;
        RenderLatest();
        Scope.Text = $"{choice.Label}   ·   TCP/UDP {string.Join(", ", ports)}";
        Status.Text = L("Starting capture…", "Iniciando captura…");
        UpdateControls();
        timer.Start();
        try
        {
            await Task.Run(() => run(choice.Id, ports, snapshot =>
            {
                if (snapshot.History is { } intervals) Volatile.Write(ref latest, intervals);
            }, stop.Token));
            Status.Text = L("Capture stopped.", "Captura detenida.");
        }
        catch (OperationCanceledException) when (stop.IsCancellationRequested) { Status.Text = L("Capture stopped.", "Captura detenida."); }
        catch (Exception ex) when (SourceError(ex))
        {
            Status.Text = L("Capture unavailable or interrupted. Check the adapter, Npcap and permissions.",
                "Captura no disponible o interrumpida. Compruebe el adaptador, Npcap y los permisos.");
        }
        finally
        {
            timer.Stop();
            session = null;
            Pause.IsChecked = false;
            RenderLatest();
            UpdateControls();
            if (closing && !closed) Close();
        }
    }

    private void StopCapture(object sender, RoutedEventArgs e)
    {
        session?.Cancel();
        Status.Text = L("Stopping capture…", "Deteniendo captura…");
        UpdateControls();
    }

    private void PauseChanged(object sender, RoutedEventArgs e)
    {
        if (session == null) return;
        if (Pause.IsChecked == true) Status.Text = L("Chart paused. Capture continues.", "Gráfica en pausa. La captura continúa.");
        else
        {
            Status.Text = L("Capturing…", "Capturando…");
            RenderLatest();
        }
    }

    internal void RenderLatest()
    {
        if (Pause.IsChecked == true || closed) return;
        var history = Volatile.Read(ref latest);
        if (ReferenceEquals(displayed, history)) return;
        displayed = history;
        var peak = history.Select(i => Math.Max(i.ReceivedBytesPerSecond ?? 0, i.SentBytesPerSecond ?? 0)).DefaultIfEmpty().Max();
        Rows.ItemsSource = history.Reverse().Select(i =>
        {
            var received = i.ReceivedBytesPerSecond;
            var sent = i.SentBytesPerSecond;
            var coverage = i.Coverage switch
            {
                "observed" => L("Observed", "Observada"),
                "unknown" => L("Unknown · driver counter unavailable", "Desconocida · sin contador del controlador"),
                _ => L("Gap", "Intervalo sin medición") + " · " + string.Join(", ", i.GapReasons.Select(GapLabel))
            };
            var details = $"{i.StartUtc:u} – {i.EndUtc:u}   ↓ {i.ReceivedBytes:N0} B   ↑ {i.SentBytes:N0} B   {string.Join(", ", i.GapReasons)}";
            return new IntervalRow($"{i.StartUtc:HH:mm:ss.fff} – {i.EndUtc:HH:mm:ss.fff}", received?.ToString("N1") ?? "—",
                sent?.ToString("N1") ?? "—", peak > 0 ? (received ?? 0) / peak : 0, peak > 0 ? (sent ?? 0) / peak : 0,
                coverage, details.TrimEnd(), i.Coverage == "gap");
        }).ToArray();
        if (session is { IsCancellationRequested: false } && history.Count > 0) Status.Text = L("Capturing · newest interval first", "Capturando · intervalo más reciente primero");
    }

    private string GapLabel(string reason) => reason switch
    {
        "capture-stopped" => L("capture interrupted", "captura interrumpida"),
        "sample-delayed" => L("delayed reading", "lectura tardía"),
        "clock-discontinuity" => L("clock discontinuity", "discontinuidad del reloj"),
        "skipped-packets" => L("skipped packets", "paquetes omitidos"),
        "driver-counter-reset" => L("driver counter reset", "reinicio del contador"),
        "driver-drops" => L("driver drops", "descartes del controlador"),
        _ => reason
    };

    private void OnClosing(object? sender, CancelEventArgs e)
    {
        if (session is null) return;
        closing = e.Cancel = true;
        session.Cancel();
        UpdateControls();
    }

    private void OnClosed(object? sender, EventArgs e)
    {
        closed = true;
        timer.Stop();
        session?.Cancel();
    }
}
