using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Threading;
using WPShield.SecurityMonitor;

namespace WPShield.Desktop;

/// <summary>
/// Failed Windows logons over the last day, then live: who is trying, how often, which accounts.
/// </summary>
/// <remarks>
/// Reads the Security log, which needs administrator rights. Without them the window says so and
/// offers to reopen elevated; it never shows an empty board as if nobody were trying. Live records are
/// queued from the event-log thread and applied once a second, so a burst of thousands of failures
/// cannot flood the interface.
/// </remarks>
public partial class AttacksWindow : Window
{
    private const int MaxLiveBatch = 5000;
    private const double DetailWidth = 430;
    private static readonly Brush Other = Frozen("#B33A3A");
    private static readonly Brush Unknown = Frozen("#E0A23A");
    private static readonly Brush Gap = Frozen("#C9D3D8");

    private readonly bool spanish;
    private readonly Func<DateTimeOffset, AuthFailureSnapshot> read;
    private readonly Func<Action<AuthFailure>, Action<string, string>, IDisposable> watch;
    private readonly AttackBoard board = new();
    private readonly ConcurrentQueue<AuthFailure> pending = new();
    private readonly DispatcherTimer flush = new() { Interval = TimeSpan.FromSeconds(1) };
    private IDisposable? subscription;
    private AttackRange range = AttackRange.Day;
    private AttackView? view;
    private string? selected;
    private Task? loading;
    private bool securityReadable;
    private bool reading;
    private bool closed;
    private int ticks;

    public AttacksWindow(bool spanish) : this(spanish, end => AuthFailureFeed.ReadRecent(end, TimeSpan.FromHours(24)),
        AuthFailureFeed.Watch)
    {
    }

    internal AttacksWindow(bool spanish, Func<DateTimeOffset, AuthFailureSnapshot> read,
        Func<Action<AuthFailure>, Action<string, string>, IDisposable> watch)
    {
        this.spanish = spanish;
        this.read = read;
        this.watch = watch;
        InitializeComponent();
        Title = "WPShield | " + L("Attacks", "Ataques");
        SourceLabel.Text = L("Security  /  Windows", "Seguridad  /  Windows");
        Heading.Text = L("Attacks", "Ataques");
        Subtitle.Text = L("Failed Windows logons: Remote Desktop, SMB and network logons (Security 4625, RdpCoreTS 140).",
            "Inicios de sesión fallidos de Windows: Escritorio remoto, SMB e inicios de red (Seguridad 4625, RdpCoreTS 140).");
        Live.Content = L("Live", "En vivo");
        Live.IsChecked = true;
        RefreshButton.Content = L("Refresh", "Actualizar");
        ElevateButton.Content = L("Reopen as administrator", "Abrir como administrador");
        AttemptsLabel.Text = L("Failed attempts", "Intentos fallidos");
        SourcesLabel.Text = L("Source addresses", "Direcciones de origen");
        UnknownLabel.Text = L("Accounts that do not exist", "Cuentas que no existen");
        HourLabel.Text = L("Last hour", "Última hora");
        LegendOther.Text = L("wrong password or other", "contraseña incorrecta u otro");
        LegendUnknown.Text = L("account does not exist", "cuenta inexistente");
        LegendGap.Text = L("no data", "sin datos");
        SearchLabel.Content = L("_Search", "_Buscar");
        Search.ToolTip = L("Address, network or account", "Dirección, red o cuenta");
        CopyAddress.Content = L("Copy address", "Copiar dirección");
        DetailCaption.Text = L("Source", "Origen");
        DetailTimelineLabel.Text = L("Attempts over time", "Intentos en el tiempo");
        DetailAccountsLabel.Text = L("Accounts tried", "Cuentas probadas");
        DetailNeighborsLabel.Text = L("Other addresses in the same network", "Otras direcciones de la misma red");
        DetailRecentLabel.Text = L("Latest attempts", "Últimos intentos");
        string[] headers = [L("Address", "Dirección"), L("Attempts", "Intentos"), L("Accounts", "Cuentas"),
            L("Most tried", "Más probadas"), L("Nonexistent", "Inexistentes"), L("Type", "Tipo"), L("Network", "Red"),
            L("Neighbors", "Vecinas"), L("Last (UTC)", "Último (UTC)")];
        for (var i = 0; i < headers.Length; i++) Rows.Columns[i].Header = headers[i];
        RangeDay.IsChecked = true;
        flush.Tick += OnFlush;
    }

    private string L(string english, string es) => spanish ? es : english;

    internal AttackBoard Board => board;

    /// <summary>Every caller waits for the same read; a second click never starts a parallel one.</summary>
    internal Task LoadAsync() => loading is { IsCompleted: false } ? loading : loading = LoadCoreAsync();

    private async Task LoadCoreAsync()
    {
        if (reading || closed) return;
        reading = true;
        RefreshButton.IsEnabled = false;
        Footer.Text = L("Reading the last 24 hours of the Security log…", "Leyendo las últimas 24 horas del registro de seguridad…");
        try
        {
            var now = DateTimeOffset.UtcNow;
            var snapshot = await Task.Run(() => read(now));
            if (closed) return;
            board.Reset(snapshot.Failures, CoveredFrom(snapshot));
            securityReadable = snapshot.Coverage.Any(c => c.Channel == AuthFailureFeed.SecurityChannel && c.Status != "unavailable");
            ShowCoverage(snapshot);
            // Following a log this process cannot read would only fail again; the banner already says why.
            if (Live.IsChecked == true && securityReadable) StartLive();
            Render();
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            if (closed) return;
            Footer.Text = L("The Security log could not be read: ", "No se pudo leer el registro de seguridad: ") +
                DisplayText.Clean(ex.GetType().Name + ": " + ex.Message, 200);
        }
        finally
        {
            reading = false;
            RefreshButton.IsEnabled = true;
        }
    }

    /// <summary>
    /// The earliest moment this board can speak for. Before it the log was unreadable, had already
    /// rolled over, or a bound stopped the read.
    /// </summary>
    internal static DateTimeOffset CoveredFrom(AuthFailureSnapshot snapshot)
    {
        var security = snapshot.Coverage.FirstOrDefault(c => c.Channel == AuthFailureFeed.SecurityChannel);
        if (security is null || security.Status == "unavailable") return snapshot.WindowEnd;
        var from = snapshot.WindowStart;
        if (security.LogStartsAt > from) from = security.LogStartsAt.Value;
        if (security.Status == "limited" && security.OldestRead > from) from = security.OldestRead.Value;
        return from;
    }

    private void ShowCoverage(AuthFailureSnapshot snapshot)
    {
        var security = snapshot.Coverage.FirstOrDefault(c => c.Channel == AuthFailureFeed.SecurityChannel);
        var rdp = snapshot.Coverage.FirstOrDefault(c => c.Channel == AuthFailureFeed.RdpCoreChannel);
        var messages = new List<string>();
        var elevate = false;
        if (security?.Status == "unavailable")
        {
            elevate = security.Reason == "access-denied";
            messages.Add(elevate
                ? L("Reading the Security log needs administrator rights. Nothing below means nobody tried; it means this window could not look.",
                    "Leer el registro de seguridad requiere permisos de administrador. Que no aparezca nada no significa que nadie lo intentara: esta ventana no pudo mirar.")
                : L("The Security log could not be read", "No se pudo leer el registro de seguridad") + $" ({Reason(security.Reason)}).");
        }
        else if (security is not null)
        {
            var covered = CoveredFrom(snapshot);
            if (covered > snapshot.WindowStart)
                messages.Add(L($"Data starts at {covered:yyyy-MM-dd HH:mm} UTC", $"Los datos empiezan el {covered:yyyy-MM-dd HH:mm} UTC") +
                    (security.Status == "limited"
                        ? L($": the {security.Count:N0} newest failures were read and the reading stopped there.",
                            $": se leyeron los {security.Count:N0} fallos más recientes y la lectura se detuvo ahí.")
                        : L(": the Security log does not reach back further. Under brute force it fills quickly; enlarging it is a manual server setting.",
                            ": el registro de seguridad no llega más atrás. Con ataques de fuerza bruta se llena rápido; ampliarlo es un ajuste manual del servidor.")));
        }
        if (rdp?.Status == "unavailable" && rdp.Reason != "access-denied")
            messages.Add(L("Remote Desktop's own log was not available", "El registro propio de Escritorio remoto no estaba disponible") +
                $" ({Reason(rdp.Reason)}). " + L("Attempts recorded without an address stay unattributed.",
                    "Los intentos registrados sin dirección quedan sin atribuir."));
        Banner.Visibility = messages.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        BannerText.Text = string.Join("  ", messages);
        ElevateButton.Visibility = elevate ? Visibility.Visible : Visibility.Collapsed;
    }

    private void StartLive()
    {
        if (subscription is not null || closed) return;
        subscription = watch(failure => pending.Enqueue(failure),
            (channel, reason) => Dispatcher.BeginInvoke(() =>
            {
                if (closed) return;
                Footer.Text = (channel == AuthFailureFeed.SecurityChannel
                        ? L("Live updates stopped for the Security log", "Se detuvo la actualización en vivo del registro de seguridad")
                        : L("Live updates stopped for Remote Desktop's log", "Se detuvo la actualización en vivo del registro de Escritorio remoto")) +
                    $" ({Reason(reason)}).";
            }));
        flush.Start();
    }

    private void StopLive()
    {
        flush.Stop();
        subscription?.Dispose();
        subscription = null;
    }

    private void OnFlush(object? sender, EventArgs e)
    {
        var added = 0;
        while (added < MaxLiveBatch && pending.TryDequeue(out var failure))
        {
            board.Add(failure);
            added++;
        }
        // The window moves with the clock even when nobody is trying, so redraw every ten seconds anyway.
        if (added > 0 || ++ticks % 10 == 0) Render();
    }

    private void Render()
    {
        view = board.View(DateTimeOffset.UtcNow, range, Search.Text.Trim());
        RenderCards(view);
        RenderChart(view.Buckets);
        var previous = selected;
        Rows.ItemsSource = view.Rows;
        if (previous is not null) Rows.SelectedItem = view.Rows.FirstOrDefault(r => r.Address == previous);
        Empty.Text = !securityReadable
            ? L("No data: the Security log could not be read.", "Sin datos: no se pudo leer el registro de seguridad.")
            : L("No failed logons with a source address in this period.", "Sin inicios de sesión fallidos con dirección de origen en este periodo.");
        Empty.Visibility = view.Rows.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        Footer.Text = L($"{view.Rows.Count:N0} of {view.MatchingRows:N0} sources shown · {board.Count:N0} records in memory",
            $"{view.Rows.Count:N0} de {view.MatchingRows:N0} orígenes · {board.Count:N0} registros en memoria");
        if (selected is not null) RenderDetail(selected);
    }

    private void RenderCards(AttackView view)
    {
        if (!securityReadable)
        {
            // Zero would say "nobody tried". The truth is "nobody could look".
            foreach (var value in new[] { AttemptsValue, SourcesValue, UnknownValue, HourValue }) value.Text = "—";
            foreach (var note in new[] { AttemptsNote, SourcesNote, UnknownNote, HourNote })
                note.Text = L("Not read", "Sin lectura");
            return;
        }
        AttemptsValue.Text = view.Attempts.ToString("N0", CultureInfo.CurrentCulture);
        AttemptsNote.Text = view.WithoutAddress > 0
            ? L($"{view.WithoutAddress:N0} without a source address", $"{view.WithoutAddress:N0} sin dirección de origen")
            : RangeText();
        SourcesValue.Text = view.Sources.ToString("N0", CultureInfo.CurrentCulture);
        SourcesNote.Text = view.TopAccount.Length > 0
            ? L("Most tried account: ", "Cuenta más probada: ") + DisplayText.Clean(view.TopAccount, 40)
            : RangeText();
        UnknownValue.Text = view.Attempts == 0 ? "—" : view.UnknownShare.ToString("P0", CultureInfo.CurrentCulture);
        UnknownNote.Text = L("Guessing names, not a known user mistyping", "Adivinan nombres; no es un usuario conocido equivocándose");
        HourValue.Text = view.LastHour.ToString("N0", CultureInfo.CurrentCulture);
        HourNote.Text = subscription is not null ? L("Updating live", "Actualizando en vivo") : L("Not live", "Sin actualización en vivo");
    }

    private string RangeText() => range switch
    {
        AttackRange.Hour => L("Last hour", "Última hora"),
        AttackRange.SixHours => L("Last 6 hours", "Últimas 6 horas"),
        _ => L("Last 24 hours", "Últimas 24 horas")
    };

    private void RenderChart(IReadOnlyList<AttackBucket> buckets)
    {
        var (_, size) = AttackBoard.Layout(range);
        var unit = size.TotalMinutes switch { 1 => L("minute", "minuto"), 5 => L("5 minutes", "5 minutos"), _ => L("15 minutes", "15 minutos") };
        var peak = buckets.Select(b => b.Total).DefaultIfEmpty().Max();
        ChartTitle.Text = L($"Attempts per {unit}", $"Intentos por {unit}") + (peak > 0 ? $"   ·   {L("Peak", "Máximo")} {peak:N0}" : "");
        // Across a day both ends share a clock time, so the date tells them apart.
        var format = range == AttackRange.Day ? "yyyy-MM-dd HH:mm" : "HH:mm";
        ChartStart.Text = buckets.Count > 0 ? buckets[0].Start.ToString(format, CultureInfo.InvariantCulture) + " UTC" : "";
        ChartEnd.Text = buckets.Count > 0 ? buckets[^1].End.ToString(format, CultureInfo.InvariantCulture) + " UTC" : "";
        Fill(Plot, buckets, peak, Plot.ActualHeight);
    }

    private void Fill(UniformGrid plot, IReadOnlyList<AttackBucket> buckets, int peak, double height)
    {
        plot.Columns = Math.Max(1, buckets.Count);
        plot.Children.Clear();
        foreach (var bucket in buckets)
        {
            var stack = new StackPanel { VerticalAlignment = VerticalAlignment.Bottom, Margin = new Thickness(1, 0, 1, 0) };
            string label;
            if (!bucket.Covered)
            {
                stack.Children.Add(new Border { Background = Gap, Height = 6 });
                label = $"{bucket.Start:HH:mm}–{bucket.End:HH:mm} UTC  ·  {L("no data", "sin datos")}";
            }
            else
            {
                if (peak > 0 && bucket.UnknownAccount > 0)
                    stack.Children.Add(new Border { Background = Unknown, Height = bucket.UnknownAccount / (double)peak * height });
                if (peak > 0 && bucket.Other > 0)
                    stack.Children.Add(new Border { Background = Other, Height = bucket.Other / (double)peak * height });
                label = $"{bucket.Start:HH:mm}–{bucket.End:HH:mm} UTC  ·  {bucket.Total:N0} " + L("attempts", "intentos") +
                    (bucket.UnknownAccount > 0 ? $" ({bucket.UnknownAccount:N0} {L("nonexistent accounts", "cuentas inexistentes")})" : "");
            }
            var cell = new Grid { Background = Brushes.Transparent, ToolTip = label };
            cell.Children.Add(stack);
            AutomationProperties.SetName(cell, label);
            plot.Children.Add(cell);
        }
    }

    private void OnPlotResized(object sender, SizeChangedEventArgs e)
    {
        if (view is not null) RenderChart(view.Buckets);
    }

    private void OnRowSelected(object sender, SelectionChangedEventArgs e)
    {
        if (Rows.SelectedItem is not AttackSource source || source.Address == selected) return;
        selected = source.Address;
        RenderDetail(source.Address);
        Slide(DetailWidth);
    }

    private void RenderDetail(string address)
    {
        if (board.Detail(address, DateTimeOffset.UtcNow, range) is not { } detail)
        {
            DetailSummary.Text = L("No attempts from this address in the selected period.", "Sin intentos desde esta dirección en el periodo elegido.");
            DetailAccounts.ItemsSource = DetailNeighbors.ItemsSource = DetailRecent.ItemsSource = null;
            DetailPlot.Children.Clear();
            return;
        }
        var s = detail.Source;
        DetailAddress.Text = s.Address;
        DetailSummary.Text = L($"{s.Attempts:N0} attempts, first {s.First:yyyy-MM-dd HH:mm:ss} and last {s.Last:HH:mm:ss} UTC. ",
                $"{s.Attempts:N0} intentos, el primero {s.First:yyyy-MM-dd HH:mm:ss} y el último {s.Last:HH:mm:ss} UTC. ") +
            L($"{s.Accounts:N0} different accounts, {s.UnknownShare:P0} of them attempts on names that do not exist. ",
                $"{s.Accounts:N0} cuentas distintas; el {s.UnknownShare:P0} de los intentos fue a nombres que no existen. ") +
            L("Logon types: ", "Tipos de inicio: ") + LogonTypes(s.LogonTypes) + ". " + Neighbors(s);
        var peak = detail.Timeline.Select(b => b.Total).DefaultIfEmpty().Max();
        Fill(DetailPlot, detail.Timeline, peak, 66);
        DetailAccounts.ItemsSource = detail.Accounts.Count == 0
            ? new[] { L("The records name no account.", "Los registros no indican cuenta.") }
            : detail.Accounts.Select(a => $"{DisplayText.Clean(a.Account, 48)}   ·   {a.Count:N0}").ToArray();
        DetailNeighbors.ItemsSource = detail.Neighbors.Count == 0
            ? new[] { L("None in this period.", "Ninguna en este periodo.") }
            : detail.Neighbors.Select(n => $"{n.Address}   ·   {n.Attempts:N0}").ToArray();
        DetailRecent.ItemsSource = detail.Recent.Select(f =>
            $"{f.Timestamp:HH:mm:ss}   {(f.Account.Length > 0 ? DisplayText.Clean(f.Account, 32) : "—")}   ·   {AuthReason(f.Reason)}" +
            (f.LogonType is int t ? $"   ·   {LogonTypes(t.ToString(CultureInfo.InvariantCulture))}" : "")).ToArray();
    }

    private string Neighbors(AttackSource s) => s.Neighbors switch
    {
        0 => L($"No other address of {s.Network} is attacking.", $"Ninguna otra dirección de {s.Network} está atacando."),
        1 => L($"One more address of {s.Network} is attacking.", $"Otra dirección de {s.Network} también está atacando."),
        _ => L($"{s.Neighbors:N0} more addresses of {s.Network} are attacking.", $"Otras {s.Neighbors:N0} direcciones de {s.Network} también están atacando.")
    };

    private string LogonTypes(string types) => string.Join(", ", types.Split(", ", StringSplitOptions.RemoveEmptyEntries).Select(t => t switch
    {
        "2" => L("local", "local"),
        "3" => L("network (NLA or SMB)", "red (NLA o SMB)"),
        "8" => L("network, clear text (IIS basic)", "red en texto claro (IIS básica)"),
        "10" => L("remote desktop", "escritorio remoto"),
        _ => L("type ", "tipo ") + t
    })) is { Length: > 0 } text ? text : "—";

    internal static string AuthReason(string code, bool spanish) => code switch
    {
        "unknown-account" => spanish ? "cuenta inexistente" : "account does not exist",
        "bad-password" => spanish ? "contraseña incorrecta" : "wrong password",
        "bad-credentials" => spanish ? "usuario o contraseña incorrectos" : "wrong user name or password",
        "locked-out" => spanish ? "cuenta bloqueada" : "account locked out",
        "disabled" => spanish ? "cuenta deshabilitada" : "account disabled",
        "account-expired" => spanish ? "cuenta caducada" : "account expired",
        "password-expired" => spanish ? "contraseña caducada" : "password expired",
        "password-must-change" => spanish ? "debe cambiar la contraseña" : "password must change",
        "outside-hours" => spanish ? "fuera del horario permitido" : "outside allowed hours",
        "workstation-restricted" => spanish ? "equipo no permitido" : "workstation not allowed",
        "logon-type-denied" => spanish ? "tipo de inicio no permitido" : "logon type not granted",
        "clock-skew" => spanish ? "reloj desfasado" : "clock skew",
        _ => spanish ? "otro motivo" : "other reason"
    };

    private string AuthReason(string code) => AuthReason(code, spanish);

    private string Reason(string? code) => code switch
    {
        "access-denied" => L("access denied", "acceso denegado"),
        "channel-missing" => L("log not present on this system", "registro no presente en este sistema"),
        "query-failed" => L("query failed", "la consulta falló"),
        null => "—",
        _ => DisplayText.Clean(code, 40)
    };

    private void Slide(double to)
    {
        var animation = new DoubleAnimation(to, TimeSpan.FromMilliseconds(180)) { EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut } };
        Detail.BeginAnimation(WidthProperty, animation);
    }

    private void OnCloseDetail(object sender, RoutedEventArgs e) => HideDetail();

    private void HideDetail()
    {
        selected = null;
        Rows.SelectedItem = null;
        Slide(0);
    }

    private void OnKey(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Escape && selected is not null)
        {
            HideDetail();
            e.Handled = true;
        }
    }

    private void OnCopyAddress(object sender, RoutedEventArgs e)
    {
        if (selected is null) return;
        try
        {
            Clipboard.SetText(selected);
        }
        catch (System.Runtime.InteropServices.ExternalException)
        {
            // Another program holds the clipboard; the address is still on screen.
        }
    }

    private void OnRange(object sender, RoutedEventArgs e)
    {
        range = sender == RangeHour ? AttackRange.Hour : sender == RangeSix ? AttackRange.SixHours : AttackRange.Day;
        if (IsLoaded) Render();
    }

    private void OnSearch(object sender, TextChangedEventArgs e)
    {
        if (IsLoaded) Render();
    }

    private void OnLive(object sender, RoutedEventArgs e)
    {
        if (!IsLoaded) return;
        if (Live.IsChecked == true && securityReadable) StartLive(); else StopLive();
        Render();
    }

    private async void OnLoaded(object sender, RoutedEventArgs e) => await LoadAsync();

    private async void OnRefresh(object sender, RoutedEventArgs e)
    {
        StopLive();
        while (pending.TryDequeue(out _)) { }
        await LoadAsync();
    }

    private void OnElevate(object sender, RoutedEventArgs e)
    {
        try
        {
            var path = Environment.ProcessPath ?? throw new InvalidOperationException("no process path");
            Process.Start(new ProcessStartInfo(path)
            {
                UseShellExecute = true,
                Verb = "runas",
                Arguments = (spanish ? "--es" : "--en") + " --attacks"
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
        StopLive();
    }

    private static Brush Frozen(string color)
    {
        var brush = (Brush)new BrushConverter().ConvertFromString(color)!;
        brush.Freeze();
        return brush;
    }
}
