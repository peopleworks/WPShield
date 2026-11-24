using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using WPShield.Cli;

namespace WPShield.Desktop;

public partial class ListenerWindow : Window
{
    private readonly DispatcherTimer timer = new() { Interval = TimeSpan.FromSeconds(5) };
    private readonly bool spanish;
    private ListenerRow[] inventory = [];
    private bool reading;
    private bool initialized;
    private bool closed;
    private AdapterTrafficWindow? trafficWindow;
    private PortTrafficWindow? portTrafficWindow;
    private AuditReferenceWindow? auditWindow;
    private IReadOnlyList<LocalListenerInventory.Table> latest = [];

    public ListenerWindow()
    {
        var args = Environment.GetCommandLineArgs();
        spanish = args.Contains("--es") || (!args.Contains("--en") && CultureInfo.CurrentUICulture.TwoLetterISOLanguageName == "es");
        InitializeComponent();
        Title = "WPShield | " + L("Local network monitor", "Monitor de red local");
        Heading.Text = L("Local ports", "Puertos locales");
        SourceLabel.Text = L("Network monitor  /  Windows", "Monitor de red  /  Windows");
        NavLabel.Text = L("Inventory", "Inventario");
        TrafficButton.Content = L("Adapter traffic", "Tráfico por adaptador");
        PortTrafficButton.Content = L("Port traffic", "Tráfico por puertos");
        AuditButton.Content = L("Audit references", "Referencias de auditoría");
        AllProtocols.Content = L("All protocols", "Todos los protocolos");
        PreviewLabel.Text = L("Research preview", "Vista previa de investigación");
        RefreshButton.Content = L("Refresh", "Actualizar");
        TcpLabel.Text = L("TCP listeners", "Escuchas TCP");
        UdpLabel.Text = L("Bound UDP sockets", "Sockets UDP vinculados");
        SearchLabel.Content = L("_Search", "_Buscar");
        Search.ToolTip = L("Address, exact port, PID or port name", "Dirección, puerto exacto, PID o nombre de puerto");
        AutoRefresh.Content = L("Every 5 s", "Cada 5 s");
        string[] headers = [L("Protocol", "Protocolo"), L("Local address", "Dirección local"), L("Port", "Puerto"),
            L("Family", "Familia"), L("Port name", "Nombre de puerto"), "PID"];
        for (int i = 0; i < headers.Length; i++) Rows.Columns[i].Header = headers[i];
        timer.Tick += OnRefresh;
        initialized = true;
    }

    private string L(string english, string es) => spanish ? es : english;

    private void OpenTraffic(object sender, RoutedEventArgs e)
    {
        if (trafficWindow is null)
        {
            trafficWindow = new AdapterTrafficWindow(spanish) { Owner = this };
            trafficWindow.Closed += (_, _) => trafficWindow = null;
            trafficWindow.Show();
        }
        else
        {
            if (trafficWindow.WindowState == WindowState.Minimized) trafficWindow.WindowState = WindowState.Normal;
            trafficWindow.Activate();
        }
    }

    private async void OnLoaded(object sender, RoutedEventArgs e) => await RefreshAsync();

    private void OpenPortTraffic(object sender, RoutedEventArgs e)
    {
        if (portTrafficWindow is null)
        {
            portTrafficWindow = new PortTrafficWindow(spanish, () => inventory.Select(row => row.Port)) { Owner = this };
            portTrafficWindow.Closed += (_, _) => portTrafficWindow = null;
            portTrafficWindow.Show();
        }
        else
        {
            if (portTrafficWindow.WindowState == WindowState.Minimized) portTrafficWindow.WindowState = WindowState.Normal;
            portTrafficWindow.Activate();
        }
    }

    private void OpenAudit(object sender, RoutedEventArgs e)
    {
        if (auditWindow is null)
        {
            auditWindow = new AuditReferenceWindow(spanish) { Owner = this };
            auditWindow.Closed += (_, _) => auditWindow = null;
            auditWindow.Show();
        }
        else
        {
            if (auditWindow.WindowState == WindowState.Minimized) auditWindow.WindowState = WindowState.Normal;
            auditWindow.Activate();
        }
    }

    private async void OnRefresh(object? sender, EventArgs e) => await RefreshAsync();

    private async Task RefreshAsync()
    {
        if (reading || closed) return;
        reading = true;
        RefreshButton.IsEnabled = false;
        Footer.Text = L("Reading Windows socket tables…", "Leyendo las tablas de sockets de Windows…");
        try
        {
            var tables = await Task.Run(() => LocalListenerInventory.ReadTables(LocalListenerInventory.ReadTcp,
                LocalListenerInventory.ReadUdp, null, new HashSet<int>(), null, ListenerOwners.Read, true));
            if (closed) return;
            foreach (var table in tables)
            {
                var tcp = table.Protocol == "TCP";
                var ipv4 = table.Endpoints.Count(e => e.Family == "IPv4");
                var ipv6 = table.Endpoints.Count - ipv4;
                var meter = tcp ? TcpMeter : UdpMeter;
                meter.ColumnDefinitions[0].Width = new GridLength(ipv4, GridUnitType.Star);
                meter.ColumnDefinitions[1].Width = new GridLength(ipv6, GridUnitType.Star);
                meter.Visibility = table.Endpoints.Count > 0 ? Visibility.Visible : Visibility.Hidden;
                (tcp ? TcpFamilies : UdpFamilies).Text = table.Status == "unavailable" ? "—" : $"IPv4  {ipv4}     ·     IPv6  {ipv6}";
                (tcp ? TcpCount : UdpCount).Text = table.Status == "unavailable" ? "—" : table.Endpoints.Count.ToString(CultureInfo.CurrentCulture);
                var state = table.Status switch
                {
                    "unavailable" => L("Unavailable", "Sin acceso") + $" ({table.Reason})",
                    "limited" => L("Row limit reached", "Límite de filas alcanzado"),
                    _ => L("Table read", "Tabla leída")
                };
                if (table.OwnerReadFailed) state += L(" · Partial PID data", " · Lectura parcial de PID");
                (tcp ? TcpState : UdpState).Text = $"{table.ObservedAtUtc:HH:mm:ss} UTC  ·  {state}";
            }
            latest = tables;
            inventory = tables.SelectMany(table => table.Endpoints.Select(e =>
            {
                var owner = e.Owner;
                var pid = owner?.ProcessId?.ToString(CultureInfo.InvariantCulture) ?? "—";
                var detail = owner is null ? "—" : $"{owner.ObservedAtUtc:u}  ·  {owner.Reason ?? pid}";
                return new ListenerRow(table.Protocol, e.Address, e.Port, e.Family,
                    e.PortHints is { Count: > 0 } hints ? string.Join(", ", hints) : "—", owner?.ProcessId, pid, detail);
            })).ToArray();
            ShowRows();
        }
        finally
        {
            reading = false;
            RefreshButton.IsEnabled = true;
        }
    }

    private void OnFilterChanged(object sender, RoutedEventArgs e)
    {
        if (initialized) ShowRows();
    }

    private void ShowRows()
    {
        string? protocol = Protocols.SelectedIndex switch { 1 => "TCP", 2 => "UDP", _ => null };
        var previous = (Rows.SelectedItem as ListenerRow)?.Key;
        var query = Search.Text.Trim();
        var visible = inventory.Where(row => row.Matches(protocol, query)).ToArray();
        Rows.ItemsSource = visible;
        if (previous.HasValue) Rows.SelectedItem = visible.FirstOrDefault(row => row.Key == previous.Value);
        var hasReadableTable = latest.Any(t => (protocol is null || t.Protocol == protocol) && t.Status != "unavailable");
        Empty.Text = hasReadableTable ? L("No matches in the observed rows", "Sin coincidencias en las filas observadas") :
            L("Socket table unavailable", "Tabla de sockets no disponible");
        Empty.Visibility = visible.Length == 0 ? Visibility.Visible : Visibility.Collapsed;
        Footer.Text = L($"{visible.Length} of {inventory.Length} observed sockets", $"{visible.Length} de {inventory.Length} sockets observados");
    }

    private void OnAutoChanged(object sender, RoutedEventArgs e) => timer.IsEnabled = AutoRefresh.IsChecked == true;

    private void OnClosed(object? sender, EventArgs e)
    {
        closed = true;
        timer.Stop();
    }
}
