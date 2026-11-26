using System.ComponentModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using WPShield.Cli;
using WPShield.Evidence;

namespace WPShield.Desktop;

/// <summary>
/// What WPShield is doing about this host, in the shape of RdpGuard's main window but only with what is
/// true: whether the collector is recording, the Windows service beside it, the mode, the sensors, and the
/// decision engine's records. Monitor only - nothing is blocked, and Block is never offered.
/// </summary>
/// <remarks>
/// <para>
/// Every fact comes from one read-only open of the evidence store (<see cref="IProtectionStore"/>) and one
/// read of the service controller, off the interface thread, every 15 seconds while the window is open.
/// The decisions are the store's own definition of "in force" (<see cref="EvidenceQueries.ActiveDecisions"/>),
/// checked against their expiry when drawn.
/// </para>
/// <para>
/// A store that could not be read shows "—" in every count and says why, with the remedy; it never shows 0.
/// The service and the collector are separate facts, and <see cref="ProtectionStatus"/> words them so they
/// never contradict each other.
/// </para>
/// </remarks>
public partial class ProtectionWindow : Window
{
    internal static readonly TimeSpan RefreshInterval = TimeSpan.FromSeconds(15);
    private static readonly Brush Green = Frozen("#1A9E6E");
    private static readonly Brush Amber = Frozen("#D99A2B");
    private static readonly Brush Grey = Frozen("#A9B8C0");

    private readonly bool spanish;
    private readonly IProtectionStore? store;
    private readonly Func<ServiceReading> service;
    private readonly Action? openAttacks;
    private readonly Action? openSettings;
    private readonly DispatcherTimer timer = new() { Interval = RefreshInterval };
    private ProtectionRead? read;
    private EvidenceProblem? problem;
    private string? problemMessage;
    private ServiceReading serviceRead = new(ServiceState.Unknown, "not read yet");
    private DecisionTab tab = DecisionTab.InForce;
    private DateTimeOffset? readAt;
    private Task? loading;
    private bool closed;

    public ProtectionWindow(bool spanish, Action openAttacks, Action openSettings)
        : this(spanish, new EvidenceProtectionStore(EvidenceStore.DefaultPath, EvidenceAccess.IsElevated), ServiceReader.Read,
            openAttacks, openSettings)
    {
    }

    internal ProtectionWindow(bool spanish, IProtectionStore? store, Func<ServiceReading> service, Action? openAttacks = null,
        Action? openSettings = null)
    {
        this.spanish = spanish;
        this.store = store;
        this.service = service;
        this.openAttacks = openAttacks;
        this.openSettings = openSettings;
        InitializeComponent();
        Title = "WPShield | " + L("Protection", "Protección");
        SourceLabel.Text = L("Protection  /  this host", "Protección  /  este servidor");
        Heading.Text = L("Protection", "Protección");
        Subtitle.Text = L("What WPShield records and decides on this host. Monitor: nothing is blocked.",
            "Lo que WPShield registra y decide en este servidor. Monitor: no se bloquea nada.");
        RefreshButton.Content = L("Refresh", "Actualizar");
        ElevateButton.Content = L("Reopen as administrator", "Abrir como administrador");
        AttacksLink.Content = L("Open Attacks", "Abrir Ataques");
        SettingsLink.Content = L("Open Settings (defense.*)", "Abrir Ajustes (defense.*)");
        AttacksLink.Visibility = openAttacks is null ? Visibility.Collapsed : Visibility.Visible;
        SettingsLink.Visibility = openSettings is null ? Visibility.Collapsed : Visibility.Visible;
        CollectorCaption.Text = L("Evidence collector (from the store)", "Recolector de evidencia (según el almacén)");
        ServiceCaption.Text = L("Windows service (read only)", "Servicio de Windows (solo lectura)");
        ModeCaption.Text = L("Mode (defense.mode)", "Modo (defense.mode)");
        BlockText.Text = L("Block - not available", "Block: no disponible");
        BlockChip.ToolTip = ProtectionStatus.BlockNotAvailable(spanish);
        SensorsCaption.Text = L("Sensors", "Sensores");
        WouldBlockLabel.Text = L("Would block now", "Bloquearía ahora");
        WouldBlockNote.Text = L("In force now. Monitor: nothing is blocked.", "Vigentes ahora. Monitor: no se bloquea nada.");
        ProtectedLabel.Text = L("Protected, 24 h", "Protegidas, 24 h");
        ProtectedNote.Text = L("A rule fired on an address the engine never decides against.",
            "Una regla se activó con una dirección contra la que el motor nunca decide.");
        RefusedLabel.Text = L("Refused, 24 h", "Rechazadas, 24 h");
        RefusedNote.Text = L("A rule fired and the engine could not check what it must.",
            "Una regla se activó y el motor no pudo comprobar lo necesario.");
        ReportLabel.Text = L("Reports, 24 h", "Informes, 24 h");
        ReportNote.Text = L("HOST-AUTH-004: one existing account from many addresses. Never blocks.",
            "HOST-AUTH-004: una cuenta existente desde muchas direcciones. Nunca bloquea.");
        SearchLabel.Content = L("_Search", "_Buscar");
        Search.ToolTip = L("Target, label or rule", "Destino, etiqueta o regla");
        string[] headers = [L("Target", "Destino"), L("Label", "Etiqueta"), L("Rule", "Regla"), L("Action", "Acción"),
            L("Reason", "Motivo"), L("Since (UTC)", "Desde (UTC)"), L("Until (UTC)", "Hasta (UTC)")];
        for (var i = 0; i < headers.Length; i++) Rows.Columns[i].Header = headers[i];
        GridExport.Attach(Rows, "protection", spanish);
        var planned = ProtectionStatus.Planned(spanish);
        (SqlText.Text, SqlStatus.Text, SqlChip.ToolTip) = (planned[0].Name, planned[0].Status, planned[0].Tooltip);
        (GatewayText.Text, GatewayStatus.Text, GatewayChip.ToolTip) = (planned[1].Name, planned[1].Status, planned[1].Tooltip);
        AutomationProperties.SetName(SqlChip, planned[0].Name + ": " + planned[0].Status);
        AutomationProperties.SetName(GatewayChip, planned[1].Name + ": " + planned[1].Status);
        TabInForce.IsChecked = true;
        timer.Tick += OnTick;
        Render();
    }

    private string L(string english, string es) => spanish ? es : english;

    internal DecisionTab Tab => tab;

    /// <summary>Every caller waits for the same read; the timer never starts a second one beside it.</summary>
    internal Task LoadAsync() => loading is { IsCompleted: false } ? loading : loading = LoadCoreAsync();

    private async Task LoadCoreAsync()
    {
        if (closed) return;
        RefreshButton.IsEnabled = false;
        if (readAt is null) Footer.Text = L("Reading the evidence store…", "Leyendo el almacén de evidencia…");
        var now = DateTimeOffset.UtcNow;
        var asked = Task.Run(ReadService);
        ProtectionRead? next = null;
        EvidenceProblem? failed = null;
        string? message = null;
        try
        {
            if (store is null)
            {
                failed = EvidenceProblem.Missing;
                message = null;
            }
            else next = await Task.Run(() => store.Read(now));
        }
        catch (EvidenceAccessException ex)
        {
            failed = ex.Problem;
            message = ex.Message;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            failed = EvidenceProblem.Unreadable;
            message = ex.GetType().Name + ": " + ex.Message;
        }
        var answer = await asked;
        if (closed) return;
        // The newest read decides. A read that failed after one that worked shows "—", never the older numbers.
        read = next;
        problem = failed;
        problemMessage = message;
        serviceRead = answer;
        readAt = now;
        Render();
        RefreshButton.IsEnabled = true;
    }

    /// <summary>The service controller's answer, or "could not be read" with the reason: a failed read must not hide the store.</summary>
    private ServiceReading ReadService()
    {
        try
        {
            return service();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            return new(ServiceState.Unknown, ex.GetType().Name);
        }
    }

    private void Render()
    {
        if (readAt is null)
        {
            RenderReading();
            return;
        }
        var now = DateTimeOffset.UtcNow;
        var collector = ProtectionStatus.Collector(read);
        Paint(ProtectionStatus.CollectorLine(collector, spanish), CollectorText, CollectorDetail, CollectorDot);
        Paint(ProtectionStatus.ServiceLine(serviceRead, collector, spanish), ServiceText, ServiceDetail, ServiceDot);
        var mode = ProtectionStatus.ModeLine(read, spanish);
        ModeText.Text = mode.Title;
        ModeDetail.Text = mode.Detail;

        Banner.Visibility = read is null && readAt is not null ? Visibility.Visible : Visibility.Collapsed;
        BannerText.Text = read is null ? ProtectionStatus.StoreRemedy(problem, problemMessage, spanish) : "";
        ElevateButton.Visibility = read is null && problem == EvidenceProblem.NotElevated ? Visibility.Visible : Visibility.Collapsed;

        var logons = ProtectionStatus.Logons(collector, serviceRead, spanish);
        LogonText.Text = logons.Name;
        LogonStatus.Text = logons.Status;
        LogonDot.Fill = Brush(logons.Tone);
        LogonChip.ToolTip = logons.Tooltip;
        AutomationProperties.SetName(LogonChip, logons.Name + ": " + logons.Status);
        AutomationProperties.SetHelpText(LogonChip, logons.Tooltip);

        var counts = ProtectionStatus.Counts(read, now);
        WouldBlockValue.Text = counts.WouldBlock;
        ProtectedValue.Text = counts.Protected;
        RefusedValue.Text = counts.Refused;
        ReportValue.Text = counts.Report;

        TabInForce.Content = ProtectionStatus.TabTitle(DecisionTab.InForce, ProtectionStatus.TabCount(read, DecisionTab.InForce, now), spanish);
        TabDay.Content = ProtectionStatus.TabTitle(DecisionTab.Day, ProtectionStatus.TabCount(read, DecisionTab.Day, now), spanish);
        TabMonth.Content = ProtectionStatus.TabTitle(DecisionTab.Month, ProtectionStatus.TabCount(read, DecisionTab.Month, now), spanish);

        var query = Search.Text.Trim();
        var all = ProtectionStatus.Rows(read, tab, "", spanish, now);
        var rows = query.Length == 0 ? all : ProtectionStatus.Rows(read, tab, query, spanish, now);
        GridRefresh.Replace(Rows, rows, RowKey);
        Empty.Text = ProtectionStatus.Empty(read, tab, searching: all.Count > 0, spanish);
        Empty.Visibility = rows.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        Footer.Text = FooterText(rows.Count, all.Count);
    }

    /// <summary>Before the first read: nothing is claimed, neither a failure nor a value.</summary>
    private void RenderReading()
    {
        var reading = L("Reading…", "Leyendo…");
        foreach (var (title, detail, dot) in new[] { (CollectorText, CollectorDetail, CollectorDot), (ServiceText, ServiceDetail, ServiceDot) })
        {
            title.Text = reading;
            detail.Text = "";
            dot.Fill = Grey;
        }
        ModeText.Text = "—";
        ModeDetail.Text = "";
        Banner.Visibility = Visibility.Collapsed;
        LogonText.Text = ProtectionStatus.Logons(ProtectionStatus.Collector(null), serviceRead, spanish).Name;
        LogonStatus.Text = reading;
        LogonDot.Fill = Grey;
        LogonChip.ToolTip = null;
        foreach (var value in new[] { WouldBlockValue, ProtectedValue, RefusedValue, ReportValue }) value.Text = "—";
        TabInForce.Content = ProtectionStatus.TabTitle(DecisionTab.InForce, "—", spanish);
        TabDay.Content = ProtectionStatus.TabTitle(DecisionTab.Day, "—", spanish);
        TabMonth.Content = ProtectionStatus.TabTitle(DecisionTab.Month, "—", spanish);
        GridRefresh.Replace(Rows, Array.Empty<ProtectionRow>(), RowKey);
        Empty.Text = L("Reading the evidence store…", "Leyendo el almacén de evidencia…");
        Empty.Visibility = Visibility.Visible;
        Footer.Text = Empty.Text;
    }

    /// <summary>A decision row is the same row across refreshes when its target, rule, action and start match.</summary>
    private static object? RowKey(object row) => row is ProtectionRow r ? (r.Target, r.Rule, r.Action, r.Since) : null;

    private string FooterText(int shown, int listed)
    {
        var refresh = readAt is { } at
            ? L($"Read at {at:HH:mm:ss} UTC; refreshes every 15 s while open.", $"Leído a las {at:HH:mm:ss} UTC; se actualiza cada 15 s mientras está abierta.")
            : L("Reading the evidence store…", "Leyendo el almacén de evidencia…");
        if (read is null) return refresh;
        var tabText = tab == DecisionTab.InForce
            ? L($"{shown:N0} of {listed:N0} decisions in force shown", $"{shown:N0} de {listed:N0} decisiones vigentes") +
              (read.Active.Truncated
                  ? L($" (the newest {EvidenceQueries.MaxDecisionScan:N0} records were read; older ones in force may be missing)",
                      $" (se leyeron los {EvidenceQueries.MaxDecisionScan:N0} registros más recientes; pueden faltar otros vigentes)")
                  : "")
            : L($"{shown:N0} of {listed:N0} records shown", $"{shown:N0} de {listed:N0} registros") +
              (ProtectionStatus.Truncated(read, tab)
                  ? L($" (the newest {EvidenceProtectionStore.Shown:N0} are listed; the tab counts them all)",
                      $" (se listan los {EvidenceProtectionStore.Shown:N0} más recientes; la pestaña los cuenta todos)")
                  : "");
        return tabText + L(" · Monitor: nothing is blocked · ", " · Monitor: no se bloquea nada · ") + refresh;
    }

    private static void Paint(StatusLine line, TextBlock title, TextBlock detail, System.Windows.Shapes.Ellipse dot)
    {
        title.Text = line.Title;
        detail.Text = line.Detail;
        dot.Fill = Brush(line.Tone);
    }

    private static Brush Brush(Tone tone) => tone switch { Tone.Green => Green, Tone.Amber => Amber, _ => Grey };

    /// <summary>Shows one tab, as a click on it would.</summary>
    internal void SelectTab(DecisionTab wanted) =>
        (wanted switch { DecisionTab.Day => TabDay, DecisionTab.Month => TabMonth, _ => TabInForce }).IsChecked = true;

    private void OnTab(object sender, RoutedEventArgs e)
    {
        tab = sender == TabDay ? DecisionTab.Day : sender == TabMonth ? DecisionTab.Month : DecisionTab.InForce;
        if (IsInitialized && Rows is not null) Render();
    }

    private void OnSearch(object sender, TextChangedEventArgs e)
    {
        if (IsInitialized) Render();
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        await LoadAsync();
        if (!closed) timer.Start();
    }

    private async void OnRefresh(object sender, RoutedEventArgs e) => await LoadAsync();

    private void OnTick(object? sender, EventArgs e)
    {
        if (loading is { IsCompleted: false }) return;
        _ = LoadAsync();
    }

    private void OnOpenAttacks(object sender, RoutedEventArgs e) => openAttacks?.Invoke();

    private void OnOpenSettings(object sender, RoutedEventArgs e) => openSettings?.Invoke();

    private void OnElevate(object sender, RoutedEventArgs e)
    {
        try
        {
            var path = Environment.ProcessPath ?? throw new InvalidOperationException("no process path");
            Process.Start(new ProcessStartInfo(path)
            {
                UseShellExecute = true,
                Verb = "runas",
                Arguments = (spanish ? "--es" : "--en") + " --protection"
            });
            Application.Current.Shutdown();
        }
        catch (Win32Exception)
        {
            // The operator declined the elevation prompt; keep this window as it is.
            Footer.Text = L("Elevation was cancelled.", "Se canceló la elevación.");
        }
    }

    private void OnClosed(object? sender, EventArgs e)
    {
        closed = true;
        timer.Stop();
    }

    private static Brush Frozen(string color)
    {
        var brush = (Brush)new BrushConverter().ConvertFromString(color)!;
        brush.Freeze();
        return brush;
    }
}
