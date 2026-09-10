using System.Globalization;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;

namespace WPShield.Cli.Report;

/// <summary>
/// Lays out a <see cref="ReportModel"/> as a PDF. It only draws — every number it shows was decided
/// by <see cref="ReportAggregator"/>, so the document has no logic worth testing beyond "it renders".
/// </summary>
/// <remarks>
/// QuestPDF is the engine the operator's own pen-test reports render through, so a WPShield report
/// looks like the reports its owner already files: a cover with the scope and the window, an
/// executive summary, the findings broken down by rule and by site, and a SHA-256 evidence appendix
/// that is the chain of custody for what the report was built from.
/// </remarks>
internal sealed class ReportPdf(ReportModel model) : IDocument
{
    private readonly ReportModel _model = model ?? throw new ArgumentNullException(nameof(model));

    private const string Ink = "#12171D";
    private const string Grey = "#6B7684";
    private const string Faint = "#9AA4B2";
    private const string Primary = "#512BD4";
    private const string PrimaryWash = "#F2F1FB";
    private const string Red = "#B42318";
    private const string Amber = "#B45309";
    private const string Green = "#15803D";
    private const string Rule = "#E3E7ED";

    public DocumentMetadata GetMetadata() => new()
    {
        Title = "WPShield Evidence Report",
        Author = "WPShield",
        Subject = "Findings and verdicts from the gateway evidence log"
    };

    public void Compose(IDocumentContainer container)
    {
        container.Page(page =>
        {
            page.Size(PageSizes.A4);
            page.Margin(36);
            page.DefaultTextStyle(text => text.FontSize(9.5f).FontColor(Ink).LineHeight(1.25f));

            page.Header().Element(Header);
            page.Content().Element(Content);
            page.Footer().Element(Footer);
        });
    }

    private void Header(IContainer container)
    {
        container.PaddingBottom(8).BorderBottom(1).BorderColor(Rule).Row(row =>
        {
            row.RelativeItem().Text(text =>
            {
                text.Span("WPShield").SemiBold().FontColor(Primary);
                text.Span("  Evidence Report").FontColor(Grey);
            });

            row.ConstantItem(220).AlignRight().Text("RESEARCH PREVIEW — NOT FOR PRODUCTION")
                .FontSize(7.5f).SemiBold().FontColor(Amber);
        });
    }

    private void Footer(IContainer container)
    {
        container.PaddingTop(6).BorderTop(1).BorderColor(Rule).Row(row =>
        {
            row.RelativeItem().Text(text =>
            {
                text.Span("Generated ").FontSize(7.5f).FontColor(Faint);
                text.Span(Utc(_model.GeneratedAt)).FontSize(7.5f).FontColor(Grey);
            });

            row.RelativeItem().AlignRight().Text(text =>
            {
                text.Span("Page ").FontSize(7.5f).FontColor(Faint);
                text.CurrentPageNumber().FontSize(7.5f).FontColor(Grey);
                text.Span(" of ").FontSize(7.5f).FontColor(Faint);
                text.TotalPages().FontSize(7.5f).FontColor(Grey);
            });
        });
    }

    private void Content(IContainer container)
    {
        container.PaddingVertical(14).Column(column =>
        {
            column.Spacing(14);

            Title(column);
            ExecutiveSummary(column);
            Counters(column);
            HonestyNote(column);

            if (_model.Empty)
            {
                column.Item().Text(
                    "No findings or verdicts were recorded in this window. In Monitor mode the log is " +
                    "the only artefact WPShield produces, so an empty window means either a quiet period " +
                    "or a gateway that is not in the traffic path — 'wpshield status' tells which.")
                    .FontColor(Grey).Italic();
            }
            else
            {
                RulesTable(column);
                SitesTable(column);
                PathsTable(column);
            }

            EvidenceAppendix(column);
        });
    }

    private void Title(ColumnDescriptor column)
    {
        var scope = _model.HostScope.Count == 0 ? "All sites" : string.Join(", ", _model.HostScope);
        var window = _model.WindowStart is { } start && _model.WindowEnd is { } end
            ? $"{Utc(start)}  to  {Utc(end)}"
            : "no events in range";

        column.Item().Text("Evidence Report").FontSize(22).SemiBold().FontColor(Ink);
        column.Item().Text(text =>
        {
            text.Span("What WPShield saw and did — ").FontColor(Grey);
            text.Span(scope).SemiBold().FontColor(Ink);
        });
        column.Item().Text(text =>
        {
            text.Span("Window  ").FontSize(8.5f).FontColor(Faint);
            text.Span(window).FontSize(8.5f).FontColor(Grey);
        });
    }

    private void ExecutiveSummary(ColumnDescriptor column)
    {
        var modes = _model.ModesSeen.Count == 0 ? "none recorded" : string.Join(" and ", _model.ModesSeen);
        var summary = _model.Empty
            ? "This report covers a window in which the gateway recorded no findings and no verdicts."
            : $"Across {Plural(_model.Sites.Count, "site")}, WPShield recorded " +
              $"{Plural(_model.Findings, "finding")} and reached {Plural(_model.TotalEvents, "logged event")}. " +
              $"It blocked {_model.Blocked} and observed {_model.Observed}; " +
              $"{Plural(_model.AllowedUploads, "clean upload")} passed inspection. " +
              $"Protection mode seen on verdicts: {modes}." +
              (_model.Blocked == 0 && _model.ModesSeen.Contains("Monitor")
                  ? " Nothing was blocked because the sites seen were in Monitor mode, where a crossing score is recorded and the request is still forwarded."
                  : string.Empty);

        column.Item().Text("Executive summary").FontSize(12).SemiBold().FontColor(Primary);
        column.Item().Text(summary);
    }

    private void Counters(ColumnDescriptor column)
    {
        column.Item().Row(row =>
        {
            row.Spacing(8);
            Card(row, "findings", _model.Findings.ToString(CultureInfo.InvariantCulture), Ink);
            Card(row, "observed", _model.Observed.ToString(CultureInfo.InvariantCulture), Amber);
            Card(row, "blocked", _model.Blocked.ToString(CultureInfo.InvariantCulture), Red);
            Card(row, "clean uploads", _model.AllowedUploads.ToString(CultureInfo.InvariantCulture), Green);
            Card(row, "dropped log lines", _model.Dropped.ToString(CultureInfo.InvariantCulture), _model.Dropped > 0 ? Red : Grey);
        });
    }

    private static void Card(RowDescriptor row, string label, string value, string color)
    {
        row.RelativeItem().Background(PrimaryWash).Padding(10).Column(card =>
        {
            card.Item().Text(value).FontSize(20).SemiBold().FontColor(color);
            card.Item().Text(label).FontSize(7.5f).FontColor(Grey);
        });
    }

    private void HonestyNote(ColumnDescriptor column)
    {
        column.Item().Background(PrimaryWash).Padding(10).Row(row =>
        {
            row.ConstantItem(3).Background(Primary);
            row.RelativeItem().PaddingLeft(8).Text(text =>
            {
                text.Span("What this does not count. ").SemiBold().FontColor(Ink);
                text.Span(
                    "These totals are what the gateway wrote down, not total traffic. A clean request " +
                    "that is not a multipart upload is never logged, and only an upload records a clean " +
                    "pass, so there is no request rate here — only findings, verdicts, and the uploads " +
                    "that were inspected and allowed.")
                    .FontColor(Grey);
            });
        });
    }

    private void RulesTable(ColumnDescriptor column)
    {
        column.Item().Text("Findings by rule").FontSize(12).SemiBold().FontColor(Primary);
        column.Item().Table(table =>
        {
            table.ColumnsDefinition(columns =>
            {
                columns.RelativeColumn(3);
                columns.RelativeColumn(1);
                columns.RelativeColumn(1);
                columns.RelativeColumn(1);
            });

            HeaderRow(table, "rule", "findings", "max score", "sites");

            foreach (var rule in _model.Rules)
            {
                BodyCell(table).Text(rule.RuleId).SemiBold();
                BodyCell(table).AlignRight().Text(rule.Findings.ToString(CultureInfo.InvariantCulture));
                BodyCell(table).AlignRight().Text(text =>
                    text.Span(rule.MaxScore.ToString(CultureInfo.InvariantCulture))
                        .FontColor(rule.MaxScore >= 80 ? Red : rule.MaxScore >= 30 ? Amber : Grey));
                BodyCell(table).AlignRight().Text(rule.Sites.ToString(CultureInfo.InvariantCulture));
            }
        });
    }

    private void SitesTable(ColumnDescriptor column)
    {
        column.Item().Text("By site").FontSize(12).SemiBold().FontColor(Primary);
        column.Item().Table(table =>
        {
            table.ColumnsDefinition(columns =>
            {
                columns.RelativeColumn(3);
                columns.RelativeColumn(1);
                columns.RelativeColumn(1);
                columns.RelativeColumn(1);
                columns.RelativeColumn(2);
            });

            HeaderRow(table, "site", "findings", "blocked", "observed", "top rule");

            foreach (var site in _model.Sites)
            {
                BodyCell(table).Text(site.Site);
                BodyCell(table).AlignRight().Text(site.Findings.ToString(CultureInfo.InvariantCulture));
                BodyCell(table).AlignRight().Text(text =>
                    text.Span(site.Blocked.ToString(CultureInfo.InvariantCulture)).FontColor(site.Blocked > 0 ? Red : Ink));
                BodyCell(table).AlignRight().Text(site.Observed.ToString(CultureInfo.InvariantCulture));
                BodyCell(table).Text(site.TopRule ?? "—").FontColor(site.TopRule is null ? Faint : Ink);
            }
        });
    }

    private void PathsTable(ColumnDescriptor column)
    {
        if (_model.TopPaths.Count == 0)
        {
            return;
        }

        column.Item().Text("Most-hit upload paths").FontSize(12).SemiBold().FontColor(Primary);
        column.Item().Text("Normalized request paths that drew an upload finding. Never a raw client value.")
            .FontSize(8).FontColor(Faint);
        column.Item().Table(table =>
        {
            table.ColumnsDefinition(columns =>
            {
                columns.RelativeColumn(5);
                columns.RelativeColumn(1);
            });

            HeaderRow(table, "path", "findings");

            foreach (var path in _model.TopPaths)
            {
                BodyCell(table).Text(path.Path).FontFamily(Fonts.Consolas).FontSize(8.5f);
                BodyCell(table).AlignRight().Text(path.Count.ToString(CultureInfo.InvariantCulture));
            }
        });
    }

    private void EvidenceAppendix(ColumnDescriptor column)
    {
        column.Item().PaddingTop(4).Text("Evidence appendix — chain of custody").FontSize(12).SemiBold().FontColor(Primary);
        column.Item().Text(
            "Every source file the report was built from, hashed with SHA-256 at read time. The same " +
            "log, read again, hashes the same; a report that names these hashes can be tied to the " +
            "exact evidence it summarised.")
            .FontSize(8.5f).FontColor(Grey);

        if (_model.Sources.Count == 0)
        {
            column.Item().Text("No source files were read.").FontColor(Faint).Italic();
            return;
        }

        foreach (var source in _model.Sources)
        {
            column.Item().PaddingTop(6).Column(entry =>
            {
                entry.Item().Text(text =>
                {
                    text.Span(source.FileName).SemiBold();
                    text.Span($"   {Bytes(source.SizeBytes)} · {source.TotalLines} lines · {source.ParsedEvents} events")
                        .FontSize(8).FontColor(Grey);
                });
                entry.Item().Text(source.Sha256).FontFamily(Fonts.Consolas).FontSize(8).FontColor(Ink);
            });
        }
    }

    // ---- table helpers -------------------------------------------------------------------------

    private static void HeaderRow(TableDescriptor table, params string[] headers)
    {
        table.Header(header =>
        {
            foreach (var (label, index) in headers.Select((label, index) => (label, index)))
            {
                var cell = header.Cell().PaddingVertical(4).PaddingHorizontal(2).BorderBottom(1).BorderColor(Primary);
                (index == 0 ? cell : cell.AlignRight())
                    .Text(label).FontSize(7.5f).SemiBold().FontColor(Grey);
            }
        });
    }

    private static IContainer BodyCell(TableDescriptor table) =>
        table.Cell().PaddingVertical(3).PaddingHorizontal(2).BorderBottom(1).BorderColor(Rule);

    private static string Utc(DateTimeOffset moment) =>
        moment.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture);

    private static string Plural(int count, string noun) =>
        count == 1 ? $"1 {noun}" : $"{count} {noun}s";

    private static string Bytes(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} B",
        < 1024 * 1024 => $"{bytes / 1024.0:0.#} KiB",
        _ => $"{bytes / (1024.0 * 1024):0.#} MiB"
    };
}
