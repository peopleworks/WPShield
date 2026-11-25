using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Threading;
using WPShield.Cli;
using WPShield.Evidence;
using WPShield.Evidence.Decisions;
using WPShield.SecurityMonitor;

namespace WPShield.Desktop;

/// <summary>
/// Failed Windows logons over the last day, then live: who is trying, how often, which accounts. With
/// the WPShield service's evidence store, also the last 7 and 30 days.
/// </summary>
/// <remarks>
/// <para>
/// Reads the Security log, which needs administrator rights. Without them the window says so and
/// offers to reopen elevated; it never shows an empty board as if nobody were trying. Live records are
/// queued from the event-log thread and applied once a second, so a burst of thousands of failures
/// cannot flood the interface.
/// </para>
/// <para>
/// 1 h, 6 h and 24 h come from the Security log exactly as before. 7 d and 30 d come from the evidence
/// store through <see cref="IAttackStore"/>, read off the interface thread and kept until the next
/// refresh; when the store cannot be opened those chips are disabled and say why. Labels from the
/// store's <c>labels.addresses</c> setting are shown in every range when the store can be read.
/// </para>
/// <para>
/// The decision engine's records (ADR 0009) are shown the same way: a column marks each source with the
/// decision in force about it or its network - "—" when the store could not be read, empty when nothing
/// is in force - and a source's detail lists its decisions. Monitor only: the words say "would block".
/// </para>
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
    private readonly IAttackStore? store;
    private readonly AttackBoard board = new();
    private readonly ConcurrentQueue<AuthFailure> pending = new();
    private readonly DispatcherTimer flush = new() { Interval = TimeSpan.FromSeconds(1) };
    private readonly Dictionary<AttackRange, StoredAttacks> stored = [];
    private readonly Dictionary<AttackRange, Task> storedReads = [];
    private IDisposable? subscription;
    private AttackRange range = AttackRange.Day;
    private AttackView? view;
    private string? selected;
    private Task? loading;
    private AddressLabels labels = AddressLabels.None;
    private EvidenceProblem? storeProblem;
    private bool defaultApplied;
    private string? storedError;
    private StoredDetail? storedDetail;
    private Task? storedDetailRead;
    private ActiveDecisions? decisions;
    private DecisionDetail? decisionDetail;
    private Task? decisionDetailRead;
    private bool probing;
    private bool securityReadable;
    private bool reading;
    private bool closed;
    private int ticks;

    /// <summary>The detail of one source in a stored range: read, being read, or failed.</summary>
    private sealed record StoredDetail(AttackRange Range, string Address, AttackDetail? Detail, bool Loading, string? Error);

    /// <summary>One source's decisions from the store: read, being read, or failed.</summary>
    private sealed record DecisionDetail(string Address, IReadOnlyList<DecisionRecord>? Rows, bool Loading, string? Error);

    public AttacksWindow(bool spanish) : this(spanish, end => AuthFailureFeed.ReadRecent(end, TimeSpan.FromHours(24)),
        AuthFailureFeed.Watch, new EvidenceAttackStore(EvidenceStore.DefaultPath, EvidenceAccess.IsElevated))
    {
    }

    internal AttacksWindow(bool spanish, Func<DateTimeOffset, AuthFailureSnapshot> read,
        Func<Action<AuthFailure>, Action<string, string>, IDisposable> watch) : this(spanish, read, watch, null)
    {
    }

    internal AttacksWindow(bool spanish, Func<DateTimeOffset, AuthFailureSnapshot> read,
        Func<Action<AuthFailure>, Action<string, string>, IDisposable> watch, IAttackStore? store)
    {
        this.spanish = spanish;
        this.read = read;
        this.watch = watch;
        this.store = store;
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
        Search.ToolTip = L("Address, network, label or account", "Dirección, red, etiqueta o cuenta");
        CopyAddress.Content = L("Copy address", "Copiar dirección");
        DetailCaption.Text = L("Source", "Origen");
        DetailTimelineLabel.Text = L("Attempts over time", "Intentos en el tiempo");
        DetailAccountsLabel.Text = L("Accounts tried", "Cuentas probadas");
        DetailNeighborsLabel.Text = L("Other addresses in the same network", "Otras direcciones de la misma red");
        DetailRecentLabel.Text = L("Latest attempts", "Últimos intentos");
        string[] headers = [L("Address", "Dirección"), L("Label", "Etiqueta"), L("Attempts", "Intentos"), L("Accounts", "Cuentas"),
            L("Most tried", "Más probadas"), L("Nonexistent", "Inexistentes"), L("Type", "Tipo"), L("Network", "Red"),
            L("Neighbors", "Vecinas"), L("Decision", "Decisión"), L("Last (UTC)", "Último (UTC)")];
        DetailDecisionsLabel.Text = L("Decisions, last 30 days (Monitor: nothing is blocked)", "Decisiones, últimos 30 días (Monitor: no se bloquea nada)");
        for (var i = 0; i < headers.Length; i++) Rows.Columns[i].Header = headers[i];
        RangeWeek.ToolTip = RangeMonth.ToolTip = L("Checking the WPShield evidence store…", "Comprobando el almacén de evidencia de WPShield…");
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
        // The store is asked at the same time; it decides the 7 d / 30 d chips and the labels.
        var probe = ProbeStoreAsync();
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
        await probe;
    }

    /// <summary>
    /// Opens the store once per load to learn whether it can be read, its labels and the range to open
    /// with. A refresh forgets what was read from it, so the next 7 d or 30 d view asks again.
    /// </summary>
    private async Task ProbeStoreAsync()
    {
        stored.Clear();
        storedDetail = null;
        decisionDetail = null;
        if (store is null)
        {
            ShowStore(EvidenceProblem.Missing);
            return;
        }
        probing = true;
        try
        {
            var status = await Task.Run(() => store.Probe(DateTimeOffset.UtcNow));
            if (closed) return;
            labels = status.Labels;
            decisions = status.Decisions;
            ShowStore(null);
            if (!defaultApplied)
            {
                defaultApplied = true;
                SelectRange(StoredAttackBoard.Parse(status.DefaultRange));
            }
        }
        catch (EvidenceAccessException ex)
        {
            if (closed) return;
            ShowStore(ex.Problem);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            if (closed) return;
            ShowStore(EvidenceProblem.Unreadable);
        }
        finally
        {
            probing = false;
        }
        if (closed || !IsLoaded) return;
        if (StoredAttackBoard.IsStored(range)) await LoadStoredAsync();
        // Only redraw a board that was drawn: after a failed live read the footer holds the reason.
        else if (!reading && view is not null) Render();
    }

    /// <summary>Enables the 7 d and 30 d chips, or disables them with the reason in their tooltip.</summary>
    private void ShowStore(EvidenceProblem? problem)
    {
        storeProblem = problem;
        if (problem is not null) decisions = null;
        var available = problem is null;
        RangeWeek.IsEnabled = RangeMonth.IsEnabled = available;
        RangeWeek.ToolTip = RangeMonth.ToolTip = problem switch
        {
            null => L("From the WPShield evidence store: hourly and daily history kept by the service.",
                "Del almacén de evidencia de WPShield: el historial por horas y días que guarda el servicio."),
            EvidenceProblem.NotElevated or EvidenceProblem.AccessDenied =>
                L("Needs the WPShield service's evidence store; run as administrator.",
                    "Necesita el almacén de evidencia del servicio WPShield; ejecute como administrador."),
            EvidenceProblem.Missing => L("Needs the WPShield service's evidence store, which is not on this server yet: install the service with 'wpshield install'.",
                "Necesita el almacén de evidencia del servicio WPShield, que aún no está en este servidor: instale el servicio con 'wpshield install'."),
            EvidenceProblem.Schema => L("The evidence store was written by another version of WPShield; use the desktop that came with the installed service.",
                "Otra versión de WPShield escribió el almacén de evidencia; use el monitor que vino con el servicio instalado."),
            _ => L("The WPShield evidence store could not be read.", "No se pudo leer el almacén de evidencia de WPShield.")
        };
        if (!available && StoredAttackBoard.IsStored(range)) SelectRange(AttackRange.Day);
    }

    private void SelectRange(AttackRange wanted)
    {
        var chip = wanted switch
        {
            AttackRange.Hour => RangeHour,
            AttackRange.SixHours => RangeSix,
            AttackRange.Week => RangeWeek,
            AttackRange.Month => RangeMonth,
            _ => RangeDay
        };
        if (chip.IsEnabled) chip.IsChecked = true;
    }

    /// <summary>Reads the evidence store for the selected 7 d or 30 d range, unless that read is already running.</summary>
    internal Task LoadStoredAsync()
    {
        var wanted = range;
        if (!StoredAttackBoard.IsStored(wanted) || store is null || storeProblem is not null) return Task.CompletedTask;
        if (storedReads.TryGetValue(wanted, out var running) && !running.IsCompleted) return running;
        if (stored.ContainsKey(wanted)) return Task.CompletedTask;
        return storedReads[wanted] = ReadStoredAsync(wanted);
    }

    private async Task ReadStoredAsync(AttackRange wanted)
    {
        storedError = null;
        if (range == wanted) Render();
        try
        {
            var now = DateTimeOffset.UtcNow;
            var data = await Task.Run(() => store!.Read(wanted, now));
            if (closed) return;
            stored[wanted] = data;
            labels = data.Labels;
            storedDetail = null;
        }
        catch (EvidenceAccessException ex)
        {
            if (closed) return;
            storedError = DisplayText.Clean(ex.Message, 300);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            if (closed) return;
            storedError = DisplayText.Clean(ex.GetType().Name + ": " + ex.Message, 300);
        }
        if (!closed && range == wanted) Render();
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
        var isStored = StoredAttackBoard.IsStored(range);
        var data = isStored && stored.TryGetValue(range, out var cached) ? cached : null;
        view = isStored
            ? data is null ? null : StoredAttackBoard.View(data, Search.Text.Trim())
            : board.View(DateTimeOffset.UtcNow, range, Search.Text.Trim(), labels: labels);
        // Across 7 or 30 days "last" needs its date. Rebinding only when the format changes keeps the grid's cells.
        var lastFormat = isStored ? "yyyy-MM-dd HH:mm" : "HH:mm:ss";
        if (Rows.Columns[^1] is DataGridTextColumn { Binding: Binding { StringFormat: var current } } last && current != lastFormat)
        {
            last.Binding = new Binding(nameof(AttackSource.Last)) { StringFormat = lastFormat };
            last.Width = new DataGridLength(isStored ? 150 : 100);
        }
        if (view is null)
        {
            // Nothing read yet, or the store failed: the cards say nothing was read, never zero.
            RenderUnread(storedError is null
                ? L("Reading the evidence store…", "Leyendo el almacén de evidencia…")
                : L("No data: the evidence store could not be read. ", "Sin datos: no se pudo leer el almacén de evidencia. ") + storedError);
            return;
        }
        // Nobody could look is "—", never an empty cell that would read as "no decision".
        view = AttackDecisions.Apply(view, storeProblem is null ? decisions : null, spanish, DateTimeOffset.UtcNow);
        RenderCards(view);
        RenderChart(view.Buckets);
        var previous = selected;
        Rows.ItemsSource = view.Rows;
        if (previous is not null) Rows.SelectedItem = view.Rows.FirstOrDefault(r => r.Address == previous);
        Empty.Text = isStored
            ? view.NoData
                ? L("No data: the WPShield service recorded nothing for this period. That is not the same as no attacks.",
                    "Sin datos: el servicio WPShield no registró nada en este periodo. No es lo mismo que no haber ataques.")
                : L("No failed logons with a source address were recorded in this period.",
                    "No se registraron inicios de sesión fallidos con dirección de origen en este periodo.")
            : !securityReadable
                ? L("No data: the Security log could not be read.", "Sin datos: no se pudo leer el registro de seguridad.")
                : L("No failed logons with a source address in this period.", "Sin inicios de sesión fallidos con dirección de origen en este periodo.");
        Empty.Visibility = view.Rows.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        Footer.Text = isStored
            ? L($"{view.Rows.Count:N0} of {view.MatchingRows:N0} sources shown · from the WPShield evidence store",
                    $"{view.Rows.Count:N0} de {view.MatchingRows:N0} orígenes · del almacén de evidencia de WPShield") +
                (view.Detailed ? "" : L(" · hourly aggregates: account names are no longer kept for this period",
                    " · agregados por hora: los nombres de cuenta ya no se guardan para este periodo"))
            : L($"{view.Rows.Count:N0} of {view.MatchingRows:N0} sources shown · {board.Count:N0} records in memory",
                $"{view.Rows.Count:N0} de {view.MatchingRows:N0} orígenes · {board.Count:N0} registros en memoria");
        Footer.Text += " · " + (probing && store is not null
            ? L("decisions: reading…", "decisiones: leyendo…")
            : AttackDecisions.Status(storeProblem is null && store is not null ? decisions : null, spanish, DateTimeOffset.UtcNow));
        if (selected is not null) RenderDetail(selected);
    }

    private void RenderUnread(string message)
    {
        foreach (var value in new[] { AttemptsValue, SourcesValue, UnknownValue, HourValue }) value.Text = "—";
        foreach (var note in new[] { AttemptsNote, SourcesNote, UnknownNote, HourNote }) note.Text = L("Not read", "Sin lectura");
        ChartTitle.Text = ChartStart.Text = ChartEnd.Text = "";
        Plot.Children.Clear();
        Rows.ItemsSource = Array.Empty<AttackSource>();
        Empty.Text = message;
        Empty.Visibility = Visibility.Visible;
        Footer.Text = message;
    }

    private void RenderCards(AttackView view)
    {
        var isStored = StoredAttackBoard.IsStored(range);
        if (isStored ? view.NoData : !securityReadable)
        {
            // Zero would say "nobody tried". The truth is "nobody could look", or nothing was recorded.
            foreach (var value in new[] { AttemptsValue, SourcesValue, UnknownValue, HourValue }) value.Text = "—";
            foreach (var note in new[] { AttemptsNote, SourcesNote, UnknownNote, HourNote })
                note.Text = isStored ? L("Nothing recorded", "Nada registrado") : L("Not read", "Sin lectura");
            return;
        }
        AttemptsValue.Text = view.Attempts.ToString("N0", CultureInfo.CurrentCulture);
        AttemptsNote.Text = view.WithoutAddress > 0
            ? L($"{view.WithoutAddress:N0} without a source address", $"{view.WithoutAddress:N0} sin dirección de origen")
            : RangeText();
        SourcesValue.Text = view.Sources.ToString("N0", CultureInfo.CurrentCulture);
        SourcesNote.Text = view.TopAccount.Length > 0
            ? L("Most tried account: ", "Cuenta más probada: ") + DisplayText.Clean(view.TopAccount, 40)
            : !view.Detailed ? L("Account names are not kept for this period", "Los nombres de cuenta no se guardan para este periodo")
            : RangeText();
        UnknownValue.Text = view.Attempts == 0 ? "—" : view.UnknownShare.ToString("P0", CultureInfo.CurrentCulture);
        UnknownNote.Text = L("Guessing names, not a known user mistyping", "Adivinan nombres; no es un usuario conocido equivocándose");
        HourValue.Text = view.LastHourKnown ? view.LastHour.ToString("N0", CultureInfo.CurrentCulture) : "—";
        HourNote.Text = !view.LastHourKnown ? L("Nothing recorded in the last hour", "Nada registrado en la última hora")
            : isStored ? L("From the evidence store", "Del almacén de evidencia")
            : subscription is not null ? L("Updating live", "Actualizando en vivo") : L("Not live", "Sin actualización en vivo");
    }

    private string RangeText() => range switch
    {
        AttackRange.Hour => L("Last hour", "Última hora"),
        AttackRange.SixHours => L("Last 6 hours", "Últimas 6 horas"),
        AttackRange.Week => L("Last 7 days", "Últimos 7 días"),
        AttackRange.Month => L("Last 30 days", "Últimos 30 días"),
        _ => L("Last 24 hours", "Últimas 24 horas")
    };

    private void RenderChart(IReadOnlyList<AttackBucket> buckets)
    {
        var size = buckets.Count > 0 ? buckets[0].End - buckets[0].Start : AttackBoard.Layout(range).Size;
        var unit = size.TotalMinutes switch
        {
            1 => L("minute", "minuto"),
            5 => L("5 minutes", "5 minutos"),
            15 => L("15 minutes", "15 minutos"),
            60 => L("hour", "hora"),
            _ => L("day", "día")
        };
        var peak = buckets.Select(b => b.Total).DefaultIfEmpty().Max();
        ChartTitle.Text = L($"Attempts per {unit}", $"Intentos por {unit}") + (peak > 0 ? $"   ·   {L("Peak", "Máximo")} {peak:N0}" : "");
        // Across a day or more both ends share a clock time, so the date tells them apart.
        var format = range == AttackRange.Month ? "yyyy-MM-dd" : range is AttackRange.Hour or AttackRange.SixHours ? "HH:mm" : "yyyy-MM-dd HH:mm";
        ChartStart.Text = buckets.Count > 0 ? buckets[0].Start.ToString(format, CultureInfo.InvariantCulture) + " UTC" : "";
        ChartEnd.Text = buckets.Count > 0 ? buckets[^1].End.ToString(format, CultureInfo.InvariantCulture) + " UTC" : "";
        Fill(Plot, buckets, peak, Plot.ActualHeight);
    }

    /// <summary>A bucket's time as its tooltip and screen reader name say it: the date appears once a bucket spans hours.</summary>
    internal static string BucketTime(AttackBucket bucket)
    {
        var size = bucket.End - bucket.Start;
        if (size >= TimeSpan.FromDays(1)) return bucket.Start.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) + " UTC";
        var start = bucket.Start.ToString(size >= TimeSpan.FromHours(1) ? "yyyy-MM-dd HH:mm" : "HH:mm", CultureInfo.InvariantCulture);
        return $"{start}–{bucket.End.ToString("HH:mm", CultureInfo.InvariantCulture)} UTC";
    }

    private void Fill(UniformGrid plot, IReadOnlyList<AttackBucket> buckets, int peak, double height)
    {
        plot.Columns = Math.Max(1, buckets.Count);
        plot.Children.Clear();
        foreach (var bucket in buckets)
        {
            var stack = new StackPanel { VerticalAlignment = VerticalAlignment.Bottom, Margin = new Thickness(buckets.Count > 100 ? 0 : 1, 0, buckets.Count > 100 ? 0 : 1, 0) };
            string label;
            if (!bucket.Covered)
            {
                stack.Children.Add(new Border { Background = Gap, Height = 6 });
                label = $"{BucketTime(bucket)}  ·  {L("no data", "sin datos")}" +
                    (bucket.Total > 0 ? $" ({bucket.Total:N0} {L("attempts recorded in part of it", "intentos registrados en parte")})" : "");
            }
            else
            {
                if (peak > 0 && bucket.UnknownAccount > 0)
                    stack.Children.Add(new Border { Background = Unknown, Height = bucket.UnknownAccount / (double)peak * height });
                if (peak > 0 && bucket.Other > 0)
                    stack.Children.Add(new Border { Background = Other, Height = bucket.Other / (double)peak * height });
                label = $"{BucketTime(bucket)}  ·  {bucket.Total:N0} " + L("attempts", "intentos") +
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
        var isStored = StoredAttackBoard.IsStored(range);
        AttackDetail? detail;
        if (isStored)
        {
            if (storedDetail is not { } state || state.Range != range || state.Address != address)
            {
                _ = LoadStoredDetailAsync(address);
                return;
            }
            if (state.Loading || state.Error is not null)
            {
                ClearDetail(address, state.Error ?? L("Reading the evidence store…", "Leyendo el almacén de evidencia…"));
                return;
            }
            detail = state.Detail;
        }
        else detail = board.Detail(address, DateTimeOffset.UtcNow, range, labels);

        if (detail is null)
        {
            ClearDetail(address, L("No attempts from this address in the selected period.", "Sin intentos desde esta dirección en el periodo elegido."));
            return;
        }
        var s = detail.Source;
        DetailAddress.Text = s.Address;
        DetailLabel.Text = s.Label;
        DetailLabel.Visibility = s.Label.Length > 0 ? Visibility.Visible : Visibility.Collapsed;
        DetailNote.Text = L("From hourly aggregates: the counts are exact, but account names and single attempts are no longer kept for this period.",
            "De agregados por hora: los recuentos son exactos, pero los nombres de cuenta y los intentos individuales ya no se guardan para este periodo.");
        DetailNoteBox.Visibility = detail.Detailed ? Visibility.Collapsed : Visibility.Visible;
        var last = isStored ? "yyyy-MM-dd HH:mm" : "HH:mm:ss";
        var first = isStored ? "yyyy-MM-dd HH:mm" : "yyyy-MM-dd HH:mm:ss";
        DetailSummary.Text = L($"{s.Attempts:N0} attempts, first {s.First.ToString(first, CultureInfo.InvariantCulture)} and last {s.Last.ToString(last, CultureInfo.InvariantCulture)} UTC. ",
                $"{s.Attempts:N0} intentos, el primero {s.First.ToString(first, CultureInfo.InvariantCulture)} y el último {s.Last.ToString(last, CultureInfo.InvariantCulture)} UTC. ") +
            (s.Accounts is int accounts
                ? L($"{accounts:N0} different accounts, {s.UnknownShare:P0} of them attempts on names that do not exist. ",
                    $"{accounts:N0} cuentas distintas; el {s.UnknownShare:P0} de los intentos fue a nombres que no existen. ")
                : L($"{s.UnknownShare:P0} of the attempts were on names that do not exist. ",
                    $"El {s.UnknownShare:P0} de los intentos fue a nombres que no existen. ")) +
            (s.LogonTypes == StoredAttackBoard.NotAsked ? "" : L("Logon types: ", "Tipos de inicio: ") + LogonTypes(s.LogonTypes) + ". ") +
            Neighbors(s) +
            (detail.FirstSeen is { } seen
                ? " " + L($"First seen by WPShield {seen:yyyy-MM-dd HH:mm} UTC, on {detail.DaysSeen:N0} different days.",
                    $"WPShield lo vio por primera vez el {seen:yyyy-MM-dd HH:mm} UTC, en {detail.DaysSeen:N0} días distintos.")
                : "");
        var peak = detail.Timeline.Select(b => b.Total).DefaultIfEmpty().Max();
        Fill(DetailPlot, detail.Timeline, peak, 66);
        DetailAccounts.ItemsSource = !detail.Detailed
            ? new[] { L("Not kept for this period.", "No se guardan para este periodo.") }
            : detail.Accounts.Count == 0
                ? new[] { L("The records name no account.", "Los registros no indican cuenta.") }
                : detail.Accounts.Select(a => $"{DisplayText.Clean(a.Account, 48)}   ·   {a.Count:N0}").ToArray();
        DetailNeighbors.ItemsSource = detail.Neighbors.Count == 0
            ? new[] { L("None in this period.", "Ninguna en este periodo.") }
            : detail.Neighbors.Select(n =>
            {
                var label = AttackBoard.LabelFor(labels, n.Address);
                return $"{n.Address}{(label.Length > 0 ? $"  ({label})" : "")}   ·   {n.Attempts:N0}";
            }).ToArray();
        var time = isStored ? "yyyy-MM-dd HH:mm:ss" : "HH:mm:ss";
        DetailRecent.ItemsSource = !detail.Detailed
            ? new[] { L("Single attempts are not kept for this period.", "Los intentos individuales no se guardan para este periodo.") }
            : detail.Recent.Select(f =>
                $"{f.Timestamp.ToString(time, CultureInfo.InvariantCulture)}   {(f.Account.Length > 0 ? DisplayText.Clean(f.Account, 32) : "—")}   ·   {AuthReason(f.Reason)}" +
                (f.LogonType is int t ? $"   ·   {LogonTypes(t.ToString(CultureInfo.InvariantCulture))}" : "")).ToArray();
        RenderDecisions(address);
    }

    /// <summary>The selected source's decisions, read from the store off the interface thread.</summary>
    private void RenderDecisions(string address)
    {
        if (store is null || storeProblem is not null)
        {
            DetailDecisions.ItemsSource = new[] { L("Not read: the evidence store is not available, so nobody could look.",
                "Sin lectura: el almacén de evidencia no está disponible, así que nadie pudo mirar.") };
            return;
        }
        if (decisionDetail is not { } state || state.Address != address)
        {
            _ = LoadDecisionDetailAsync(address);
            return;
        }
        DetailDecisions.ItemsSource = state.Loading
            ? new[] { L("Reading the evidence store…", "Leyendo el almacén de evidencia…") }
            : state.Error is not null
                ? new[] { state.Error }
                : state.Rows!.Count == 0
                    ? new[] { L("No decision about this address or its network.", "Ninguna decisión sobre esta dirección o su red.") }
                    : state.Rows.Select(d => AttackDecisions.Line(d, spanish)).ToArray();
    }

    /// <summary>Asks the store for one source's decisions, unless that read is already running.</summary>
    internal Task LoadDecisionDetailAsync(string address)
    {
        if (decisionDetail is { Loading: true } running && running.Address == address && decisionDetailRead is not null)
            return decisionDetailRead;
        return decisionDetailRead = ReadDecisionDetailAsync(address);
    }

    private async Task ReadDecisionDetailAsync(string address)
    {
        if (store is null || storeProblem is not null) return;
        decisionDetail = new DecisionDetail(address, null, true, null);
        DetailDecisions.ItemsSource = new[] { L("Reading the evidence store…", "Leyendo el almacén de evidencia…") };
        try
        {
            var now = DateTimeOffset.UtcNow;
            var rows = await Task.Run(() => store.Decisions(address, now - AttackDecisions.DetailSpan, now.AddMinutes(1)));
            if (closed) return;
            decisionDetail = new DecisionDetail(address, rows, false, null);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            if (closed) return;
            decisionDetail = new DecisionDetail(address, null, false,
                L("The evidence store could not be read: ", "No se pudo leer el almacén de evidencia: ") + DisplayText.Clean(ex.Message, 200));
        }
        if (selected == address) RenderDecisions(address);
    }

    private void ClearDetail(string address, string message)
    {
        DetailAddress.Text = address;
        DetailLabel.Visibility = Visibility.Collapsed;
        DetailNoteBox.Visibility = Visibility.Collapsed;
        DetailSummary.Text = message;
        DetailAccounts.ItemsSource = DetailNeighbors.ItemsSource = DetailRecent.ItemsSource = DetailDecisions.ItemsSource = null;
        DetailPlot.Children.Clear();
    }

    /// <summary>Asks the store for one source's history in the selected range, unless that read is already running.</summary>
    internal Task LoadStoredDetailAsync(string address)
    {
        if (storedDetail is { Loading: true } running && running.Range == range && running.Address == address && storedDetailRead is not null)
            return storedDetailRead;
        return storedDetailRead = ReadStoredDetailAsync(address);
    }

    private async Task ReadStoredDetailAsync(string address)
    {
        var wanted = range;
        if (store is null || !stored.TryGetValue(wanted, out var data)) return;
        storedDetail = new StoredDetail(wanted, address, null, true, null);
        ClearDetail(address, L("Reading the evidence store…", "Leyendo el almacén de evidencia…"));
        try
        {
            var history = await Task.Run(() => store.History(address, data.Window));
            if (closed) return;
            storedDetail = new StoredDetail(wanted, address, StoredAttackBoard.Detail(data, history), false, null);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            if (closed) return;
            storedDetail = new StoredDetail(wanted, address, null, false,
                L("The evidence store could not be read: ", "No se pudo leer el almacén de evidencia: ") + DisplayText.Clean(ex.Message, 200));
        }
        if (selected == address && range == wanted) RenderDetail(address);
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
        range = sender == RangeHour ? AttackRange.Hour
            : sender == RangeSix ? AttackRange.SixHours
            : sender == RangeWeek ? AttackRange.Week
            : sender == RangeMonth ? AttackRange.Month
            : AttackRange.Day;
        if (!IsLoaded) return;
        if (StoredAttackBoard.IsStored(range) && !stored.ContainsKey(range)) _ = LoadStoredAsync();
        else Render();
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
