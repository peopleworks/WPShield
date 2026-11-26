using System.ComponentModel;
using System.Globalization;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Threading;
using WPShield.Cli;
using WPShield.Evidence;

namespace WPShield.Desktop;

public partial class AttacksWindow
{
    private const int DisplayedPathLength = 200;
    private readonly EvidenceWebStore? webStore;
    private readonly DispatcherTimer webLive = new() { Interval = TimeSpan.FromSeconds(10) };
    private bool showingWeb;
    private bool restoringRange;
    private bool bindingWeb;
    private bool webReload;
    private bool webDetailReload;
    private AttackRange webRange = AttackRange.Day;
    private long? webSiteId;
    private string? webSelected;
    private Task? webRead;
    private Task? webDetailRead;
    private StoredWebEvidence? webSnapshot;

    private string? SelectedAddress => showingWeb ? webSelected : selected;

    internal sealed record WebSiteChoice(long? Id, string Name);
    internal sealed record WebCard(string Title, string Value, string? Note = null, bool Alert = false);
    internal sealed record WebRow(WebSource Source, string Label)
    {
        public long Observations => Source.Observations + Source.LoginPosts + Source.XmlrpcPosts;

        /// <summary>What the address column sorts by: the address as a number (<see cref="AddressOrder"/>).</summary>
        public string AddressSortKey => AddressOrder.Key(Source.Address);

        /// <summary>What the network column sorts by.</summary>
        public string NetworkSortKey => AddressOrder.Key(Source.Network);
    }
    internal sealed record WebFindingLine(string Context, string Path, string Ids);

    private void InitializeWeb()
    {
        AttackTab.Header = L("Attacks", "Ataques");
        WebTab.Header = "Web";
        WebSiteLabel.Content = L("_Site", "_Sitio");
        WebCoverageTitle.Text = L("IIS log coverage", "Cobertura de los logs de IIS");
        WebElevate.Content = ElevateButton.Content;
        WebLegendFindings.Text = L("rule findings", "hallazgos de reglas");
        WebLegendObservations.Text = WebObservationIds.PhpOutsideEntryPoints;
        WebLegendGap.Text = L("no data", "sin datos");
        WebDetailRulesLabel.Text = L("Rules and observations", "Reglas y observaciones");
        WebDetailFindingsLabel.Text = L("Latest findings · paths are untrusted text", "Últimos hallazgos · rutas como texto no confiable");

        (string Title, string Short, string? Property, int Width, bool Expand)[] columns =
        [
            (L("Address", "Dirección"), L("Address", "Dirección"), "Source.Address", 132, true),
            (L("Label", "Etiqueta"), L("Label", "Etiqueta"), nameof(WebRow.Label), 100, true),
            (L("Requests", "Peticiones"), L("Req.", "Pet."), "Source.Requests", 67, false),
            (L("Client errors (4xx)", "Errores de cliente (4xx)"), "4xx", "Source.ClientErrors", 56, false),
            (L("Rule findings", "Hallazgos de reglas"), L("Finds", "Hall."), "Source.Findings", 65, false),
            (L("Observations", "Observaciones"), "Obs.", nameof(WebRow.Observations), 64, false),
            (L("Login POST", "POST de acceso"), L("Login", "Acceso"), "Source.LoginPosts", 72, false),
            ("XML-RPC POST", "XML-RPC", "Source.XmlrpcPosts", 82, false),
            (L("Network", "Red"), L("Network", "Red"), "Source.Network", 130, true),
            (L("Neighbors", "Vecinas"), L("Neigh.", "Vec."), "Source.Neighbors", 66, false),
            (L("Decision", "Decisión"), L("Decision", "Decisión"), null, 87, false),
            (L("Last (UTC)", "Último (UTC)"), L("Last", "Último"), "Source.Last", 145, false)
        ];
        var cellText = (Style)FindResource("CellText");
        foreach (var (title, shortTitle, property, width, expand) in columns)
        {
            var header = new TextBlock { Text = shortTitle, ToolTip = title, TextTrimming = TextTrimming.CharacterEllipsis };
            AutomationProperties.SetName(header, title);
            var column = new DataGridTextColumn
            {
                Header = header,
                Width = expand ? new DataGridLength(1, DataGridLengthUnitType.Star) : new DataGridLength(width),
                MinWidth = width,
                ElementStyle = cellText
            };
            if (property is null)
            {
                var reason = L("Web evidence does not feed decisions yet.", "La evidencia web aún no alimenta las decisiones.");
                header.ToolTip = title + " · " + reason;
                column.CellStyle = new Style(typeof(DataGridCell));
                column.CellStyle.Setters.Add(new Setter(ToolTipService.ToolTipProperty, reason));
                column.CanUserSort = false;
            }
            else
            {
                column.Binding = new Binding(property) { StringFormat = property == "Source.Last" ? "yyyy-MM-dd HH:mm" : null };
                // Addresses and networks sort as numbers, so .7 comes before .20.
                if (property == "Source.Address") column.SortMemberPath = nameof(WebRow.AddressSortKey);
                if (property == "Source.Network") column.SortMemberPath = nameof(WebRow.NetworkSortKey);
            }
            WebRows.Columns.Add(column);
        }
        // Busiest first: the address that sent the most requests leads, then the one with more findings, then by
        // address so equal rows keep a stable order. The operator's own sort replaces it, and survives a refresh.
        GridRefresh.SetDefaultSort(WebRows,
            new SortDescription("Source.Requests", ListSortDirection.Descending),
            new SortDescription("Source.Findings", ListSortDirection.Descending),
            new SortDescription(nameof(WebRow.AddressSortKey), ListSortDirection.Ascending));
        GridExport.Attach(WebRows, "web", spanish);
        BindWebSites([]);
        RenderWebUnread(L("Reading the evidence store…", "Leyendo el almacén de evidencia…"));
        webLive.Tick += (_, _) =>
        {
            if (webRead is not { IsCompleted: false }) _ = LoadWebAsync();
        };
    }

    internal void OpenWebView() => Views.SelectedItem = WebTab;

    internal void OpenAttacksView() => Views.SelectedItem = AttackTab;

    private void OnViewChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!IsLoaded || e.Source != Views) return;
        var web = Views.SelectedItem == WebTab;
        if (web == showingWeb) return;

        HideDetail();
        showingWeb = web;
        AttackDetailContent.Visibility = web ? Visibility.Collapsed : Visibility.Visible;
        WebDetailContent.Visibility = web ? Visibility.Visible : Visibility.Collapsed;
        SetViewHeading(web);

        RefreshButton.IsEnabled = web || !reading;
        restoringRange = true;
        if (web)
        {
            RangeWeek.IsEnabled = RangeMonth.IsEnabled = true;
            RangeWeek.ToolTip = RangeMonth.ToolTip = L("IIS log evidence from the store.", "Evidencia de los logs de IIS guardada en el almacén.");
        }
        else UpdateAttackRangeChips();
        CheckRangeChip(web ? webRange : range);
        restoringRange = false;

        UpdateWebLive();
        if (web)
        {
            StopLive();
            _ = LoadWebAsync();
        }
        else
        {
            Render();
            _ = RefreshAttacksAsync();
        }
    }

    private void SetViewHeading(bool web)
    {
        Heading.Text = web ? "Web" : L("Attacks", "Ataques");
        Title = "WPShield | " + Heading.Text;
        SourceLabel.Text = web ? L("IIS logs  /  HTTP and HTTPS", "Logs de IIS  /  HTTP y HTTPS") : L("Security  /  Windows", "Seguridad  /  Windows");
        Subtitle.Text = web
            ? L("Requests and findings from the IIS logs.", "Peticiones y hallazgos de los logs de IIS.")
            : L("Failed Windows logons: Remote Desktop, SMB and network logons (Security 4625, RdpCoreTS 140).",
                "Inicios de sesión fallidos de Windows: Escritorio remoto, SMB e inicios de red (Seguridad 4625, RdpCoreTS 140).");
    }

    private void UpdateWebLive()
    {
        if (showingWeb && Live.IsChecked == true) webLive.Start();
        else webLive.Stop();
    }

    private void OnWebSiteChanged(object sender, SelectionChangedEventArgs e)
    {
        if (bindingWeb || !showingWeb || !IsLoaded || WebSite.SelectedItem is not WebSiteChoice choice || choice.Id == webSiteId) return;
        webSiteId = choice.Id;
        ResetWebFilter();
    }

    private void ResetWebFilter()
    {
        HideDetail();
        RenderWebUnread(L("Reading the selected range and site…", "Leyendo el periodo y el sitio seleccionados…"));
        webReload = true;
        _ = LoadWebAsync();
    }

    internal Task LoadWebAsync()
    {
        if (!showingWeb || closed) return Task.CompletedTask;
        if (webRead is { IsCompleted: false }) return webRead;
        webReload = true;
        return webRead = ReadWebAsync();
    }

    private async Task ReadWebAsync()
    {
        while (webReload && showingWeb && !closed)
        {
            webReload = false;
            if (webStore is null)
            {
                RenderWebUnread(StoreMessage(EvidenceProblem.Missing));
                return;
            }

            var wanted = (Range: webRange, Site: webSiteId);
            var access = ReadSettingsAsync();
            try
            {
                var data = await Task.Run(() => webStore.Read(wanted.Range, wanted.Site));
                await access;
                if (closed || !showingWeb || wanted != (webRange, webSiteId)) continue;
                if (wanted.Site is not null && !data.Sites.Any(site => site.SiteId == wanted.Site))
                {
                    webSiteId = null;
                    BindWebSites(data.Sites);
                    ResetWebFilter();
                    continue;
                }
                RenderWeb(data);
            }
            catch (EvidenceAccessException error)
            {
                if (closed || !showingWeb || wanted != (webRange, webSiteId)) continue;
                RenderWebUnread(StoreMessage(error.Problem));
                WebElevate.Visibility = error.Problem == EvidenceProblem.NotElevated ? Visibility.Visible : Visibility.Collapsed;
            }
            catch (Exception error) when (error is not OutOfMemoryException)
            {
                if (closed || !showingWeb || wanted != (webRange, webSiteId)) continue;
                RenderWebUnread(StoreMessage(EvidenceProblem.Unreadable));
            }
        }
    }

    private string StoreMessage(EvidenceProblem problem) => problem switch
    {
        EvidenceProblem.Missing => L("No data. The evidence store is missing. Install WPShield and start 'wpshield evidence collect' on the IIS host.",
            "Sin datos. Falta el almacén de evidencia. Instale WPShield e inicie 'wpshield evidence collect' en el servidor IIS."),
        EvidenceProblem.NotElevated => L("No data. Open WPShield as administrator to read the evidence store.",
            "Sin datos. Abra WPShield como administrador para leer el almacén de evidencia."),
        EvidenceProblem.AccessDenied => L("No data. Access to the evidence store was denied. Check the folder permissions.",
            "Sin datos. Se denegó el acceso al almacén de evidencia. Compruebe los permisos de la carpeta."),
        EvidenceProblem.Schema => L("No data. The evidence store has a different schema. Use the matching build. For an older store, start the current collector to migrate it, then refresh.",
            "Sin datos. El almacén de evidencia tiene otro esquema. Use la versión correspondiente. Si el almacén es anterior, inicie el recolector actual para migrarlo y luego actualice."),
        _ => L("No data. The evidence store could not be read. Check the store and refresh.",
            "Sin datos. No se pudo leer el almacén de evidencia. Compruebe el almacén y actualice.")
    };

    private void BindWebSites(IReadOnlyList<WebSiteCoverage> sites)
    {
        WebSiteChoice[] choices = [new(null, L("All sites", "Todos los sitios")),
            .. sites.OrderBy(site => site.Name, StringComparer.CurrentCultureIgnoreCase)
                .Select(site => new WebSiteChoice(site.SiteId, WebSiteName(site)))];
        if (WebSite.ItemsSource is WebSiteChoice[] existing && existing.SequenceEqual(choices)) return;
        bindingWeb = true;
        WebSite.ItemsSource = choices;
        WebSite.SelectedItem = choices.FirstOrDefault(choice => choice.Id == webSiteId) ?? choices[0];
        bindingWeb = false;
    }

    private static string WebSiteName(WebSiteCoverage site)
    {
        var name = DisplayText.Clean(site.Name, 100);
        return name.Length > 0 ? name : site.SiteId.ToString(CultureInfo.InvariantCulture);
    }

    private IEnumerable<WebCard> WebMetrics(StoredWebEvidence? data)
    {
        var summary = data is { HasData: true } ? data.Summary : null;
        var php = summary?.Observations;
        var observations = summary is null ? (long?)null : summary.Observations + summary.LoginPosts + summary.XmlrpcPosts;
        var sites = data?.Sites.Where(site => data.SiteId is null || site.SiteId == data.SiteId).ToArray();
        yield return new(L("Requests", "Peticiones"), Number(summary?.Requests));
        yield return new(L("Rule findings", "Hallazgos de reglas"), Number(summary?.Findings));
        yield return new(L("Observations", "Observaciones"), Number(observations));
        yield return new(L("Addresses kept", "Direcciones guardadas"), Number(summary?.Sources));
        yield return new(L("Sites read", "Sitios leídos"), sites is { Length: > 0 }
            ? $"{sites.Count(s => s.Status == "collected"):N0} / {sites.Length:N0}" : "—",
            L("Latest reported log status for the selected sites.", "Último estado de lectura registrado para los sitios seleccionados."));
        yield return new(WebObservationIds.PhpOutsideEntryPoints, Number(php),
            L("2xx response from PHP outside WordPress entry points. Possible web shell activity.",
                "Respuesta 2xx de PHP fuera de los puntos de entrada de WordPress. Posible actividad de un web shell."), php > 0);
    }

    private static string Number(long? count) => count?.ToString("N0", CultureInfo.CurrentCulture) ?? "—";

    private void RenderWeb(StoredWebEvidence data)
    {
        webSnapshot = data;
        BindWebSites(data.Sites);
        WebElevate.Visibility = Visibility.Collapsed;
        WebCoverage.Text = CoverageText(data);
        WebCards.ItemsSource = WebMetrics(data).ToArray();
        RenderWebChart();

        var rows = data.Sources.Select(source => new WebRow(source, AttackBoard.LabelFor(data.Labels, source.Address))).ToArray();
        var current = rows.FirstOrDefault(row => row.Source.Address == webSelected);
        bindingWeb = true;
        GridRefresh.Replace(WebRows, rows);
        WebRows.SelectedItem = current;
        bindingWeb = false;
        if (current is not null)
        {
            ShowWebAddress(current);
            webDetailReload = true;
            _ = LoadWebDetailAsync();
        }
        else if (webSelected is not null) HideDetail();
        WebEmpty.Text = !data.HasData
            ? L("No data for this range and site selection.", "Sin datos para este periodo y esta selección de sitios.")
            : L("No addresses were kept in the recorded part of this selection.", "No se guardaron direcciones en la parte registrada de esta selección.");
        WebEmpty.Visibility = rows.Length == 0 ? Visibility.Visible : Visibility.Collapsed;

        var summary = data.Summary;
        WebFooter.Text = EvidenceOnly + "  ·  " +
            L($"{rows.Length:N0} of {summary.Sources:N0} addresses shown. Whole-hour totals from {Minute(summary.HoursFrom)} to {Minute(summary.HoursTo)} UTC.",
                $"{rows.Length:N0} de {summary.Sources:N0} direcciones visibles. Totales por horas completas de {Minute(summary.HoursFrom)} a {Minute(summary.HoursTo)} UTC.");
        if (!data.HasData) WebFooter.Text = EvidenceOnly;
    }

    private string EvidenceOnly => L("Evidence only: nothing is decided or blocked from web evidence.",
        "Solo evidencia: la evidencia web no genera decisiones ni bloqueos.");

    private void RenderWebUnread(string message)
    {
        webSnapshot = null;
        if (showingWeb && webSelected is not null) HideDetail();
        WebElevate.Visibility = Visibility.Collapsed;
        WebCards.ItemsSource = WebMetrics(null).ToArray();
        WebCoverage.Text = WebEmpty.Text = message;
        WebEmpty.Visibility = Visibility.Visible;
        GridRefresh.Replace(WebRows, null);
        WebPlot.Children.Clear();
        WebChartTitle.Text = WebChartStart.Text = WebChartEnd.Text = "";
        WebFooter.Text = EvidenceOnly;
    }

    private string CoverageText(StoredWebEvidence data)
    {
        var lines = new List<string>();
        if (!data.HasData)
            lines.Add(L("No data in this range. Run 'wpshield evidence collect' on the IIS host.",
                "Sin datos en este periodo. Ejecute 'wpshield evidence collect' en el servidor IIS."));
        if (data.Sites.Count == 0)
            lines.Add(L("The sensor has recorded no site inventory.", "El sensor aún no ha registrado un inventario de sitios."));
        foreach (var site in data.Sites.Where(site => (data.SiteId is null || data.SiteId == site.SiteId) && site.Status != "collected"))
        {
            var status = site.Status == "ignored" ? L("ignored", "omitido") : L("not read", "sin lectura");
            var remedy = DisplayText.Clean(site.Remedy, 500);
            lines.Add($"{WebSiteName(site)} · {status} · {WebReason(site.Reason)}" +
                (remedy.Length == 0 ? "" : $" · {L("Remedy", "Remedio")} · {remedy}"));
        }

        AppendCoverageGaps(lines, data.Coverage);
        if (data.SiteCoverage is { } logs && data.Coverage.State != CoverageReport.None &&
            !logs.Gaps.Select(gap => (gap.From, gap.To)).SequenceEqual(data.Coverage.Gaps.Select(gap => (gap.From, gap.To))))
            AppendCoverageGaps(lines, logs);
        if (lines.Count == 0)
            lines.Add(L("The selected range was recorded.", "Se registró el periodo seleccionado."));
        return string.Join(Environment.NewLine, lines);
    }

    private void AppendCoverageGaps(List<string> lines, CoverageReport coverage)
    {
        foreach (var gap in coverage.Gaps)
            lines.Add($"{L("No data", "Sin datos")} · {Minute(gap.From)} – {Minute(gap.To)} UTC · {WebReason(gap.Reason)}");
        if (coverage.Omitted > 0)
            lines.Add(L($"{coverage.Omitted:N0} more gaps in this range.", $"{coverage.Omitted:N0} huecos más en este periodo."));
    }

    private string WebReason(string? reason) => reason switch
    {
        null => L("no interval recorded", "sin intervalo registrado"),
        "access-denied" => L("access denied", "acceso denegado"),
        "central-logging-mode" => L("IIS uses central logging", "IIS usa registro centralizado"),
        "iis-configuration-unreadable" => L("IIS configuration could not be read", "no se pudo leer la configuración de IIS"),
        "no-http-binding" => L("no HTTP or HTTPS binding", "sin binding HTTP ni HTTPS"),
        "logging-disabled" => L("logging disabled", "registro deshabilitado"),
        "log-format-not-w3c" => L("the log format is not W3C", "el formato del log no es W3C"),
        "no-log-directory" => L("no log directory configured", "sin carpeta de logs configurada"),
        "no-log-folder" => L("log folder is missing", "falta la carpeta de logs"),
        "no-log-file" => L("log file is missing", "falta el archivo de log"),
        "no-fields-directive" => L("missing W3C field list", "falta la lista de campos W3C"),
        "not-read-yet" => L("the log has not been read yet", "el log aún no se ha leído"),
        "not-in-configuration" => L("site is absent from the current IIS configuration", "el sitio no figura en la configuración actual de IIS"),
        "catch-up-bound" => L("catch-up limit reached", "se alcanzó el límite de lectura histórica"),
        "file-restarted" => L("the log file was restarted", "se reinició el archivo de log"),
        _ => DisplayText.Clean(reason, 100)
    };

    private static string Minute(DateTimeOffset time) => time.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);

    private void OnWebPlotResized(object sender, SizeChangedEventArgs e) => RenderWebChart();

    private void RenderWebChart()
    {
        if (webSnapshot is not { } data) return;
        var size = StoredAttackBoard.IsStored(webRange) ? data.Window.Bucket : AttackBoard.Layout(webRange).Size;
        var unit = size.TotalMinutes switch
        {
            1 => L("minute", "minuto"),
            5 => L("5 minutes", "5 minutos"),
            15 => L("15 minutes", "15 minutos"),
            60 => L("hour", "hora"),
            _ => L("day", "día")
        };
        WebChartTitle.Text = L($"Evidence per {unit}", $"Evidencia por {unit}");
        WebChartStart.Text = Minute(data.Window.From) + " UTC";
        WebChartEnd.Text = Minute(data.Window.To) + " UTC";
        var peak = data.Timeline.Where(b => b.Covered).Select(b => (double)b.Findings + b.Observations).DefaultIfEmpty().Max();
        FillPlot(WebPlot, data.Timeline, peak, WebPlot.ActualHeight, b => (b.Findings, b.Observations, b.Covered), b =>
        {
            var at = BucketTime(b.Start, b.End);
            var counts = L($"{b.Findings:N0} rule findings · {b.Observations:N0} {WebObservationIds.PhpOutsideEntryPoints}",
                $"{b.Findings:N0} hallazgos de reglas · {b.Observations:N0} {WebObservationIds.PhpOutsideEntryPoints}");
            if (b.Covered) return $"{at} · {counts}";
            return $"{at} · {L("no data", "sin datos")}" +
                (b.Findings > 0 || b.Observations > 0 ? $" · {L("recorded in part", "registrado en parte")} · {counts}" : "");
        });
    }

    private void OnWebRowSelected(object sender, SelectionChangedEventArgs e)
    {
        if (bindingWeb || !showingWeb || WebRows.SelectedItem is not WebRow row || row.Source.Address == webSelected) return;
        webSelected = row.Source.Address;
        ShowWebAddress(row);
        Slide(DetailWidth);
        webDetailReload = true;
        _ = LoadWebDetailAsync();
    }

    private void ShowWebAddress(WebRow row)
    {
        DetailAddress.Text = row.Source.Address;
        DetailLabel.Text = row.Label;
        DetailLabel.Visibility = row.Label.Length > 0 ? Visibility.Visible : Visibility.Collapsed;
        RenderActions(row.Source.Address);
    }

    internal Task LoadWebDetailAsync()
    {
        if (webDetailRead is { IsCompleted: false }) return webDetailRead;
        return webDetailRead = ReadWebDetailAsync();
    }

    private async Task ReadWebDetailAsync()
    {
        while (webDetailReload && showingWeb && !closed && webStore is not null &&
               webSnapshot is { } snapshot && webSelected is { } address)
        {
            webDetailReload = false;
            WebDetailRules.ItemsSource = WebDetailFindings.ItemsSource = null;
            WebDetailStatus.Text = L("Reading the address history…", "Leyendo el historial de la dirección…");
            try
            {
                var data = await Task.Run(() => webStore.ReadDetail(snapshot, address));
                if (closed || !showingWeb || address != webSelected || snapshot != webSnapshot) continue;
                RenderWebDetail(snapshot, data);
            }
            catch (Exception error) when (error is not OutOfMemoryException)
            {
                if (!closed && showingWeb && address == webSelected && snapshot == webSnapshot)
                    WebDetailStatus.Text = L("No data. The address history could not be read.", "Sin datos. No se pudo leer el historial de la dirección.");
            }
        }
    }

    private void RenderWebDetail(StoredWebEvidence snapshot, StoredWebDetail data)
    {
        WebDetailRules.ItemsSource = data.Counts.Select(count =>
            $"{DisplayText.Clean(count.Id, 32)} · {count.Requests:N0} · " +
            (count.Observation ? L("observation", "observación") : L("rule", "regla"))).ToArray();
        var sites = snapshot.Sites.ToDictionary(site => site.SiteId);
        WebDetailFindings.ItemsSource = data.Findings.Take(EvidenceWebStore.DetailLimit).Select(finding =>
        {
            var site = sites.TryGetValue(finding.SiteId, out var known) ? WebSiteName(known) : finding.SiteId.ToString(CultureInfo.InvariantCulture);
            return new WebFindingLine($"{Minute(finding.Timestamp)} UTC · {site} · {DisplayText.Clean(finding.Method, 12)} · {finding.Status}",
                DisplayText.Clean(finding.Path, DisplayedPathLength),
                DisplayText.Clean(string.Join(", ", finding.Hits.Select(hit => hit.Id)), 160));
        }).ToArray();
        WebDetailStatus.Text = data.Findings.Count switch
        {
            0 => L("No individual findings were kept for this selection.", "No se guardaron hallazgos individuales para esta selección."),
            > EvidenceWebStore.DetailLimit => L($"Showing the latest {EvidenceWebStore.DetailLimit} findings.",
                $"Se muestran los últimos {EvidenceWebStore.DetailLimit} hallazgos."),
            _ => ""
        };
        if (snapshot.Summary.FindingsFrom is { } pruned)
            WebDetailStatus.Text += " " + L($"Individual findings before {Minute(pruned)} UTC were pruned.",
                $"Se eliminaron los hallazgos individuales anteriores al {Minute(pruned)} UTC.");
    }
}
