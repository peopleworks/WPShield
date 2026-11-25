using System.Globalization;
using System.Text.RegularExpressions;

namespace WPShield.Analyst;

/// <summary>
/// Prints a stored report. Always from the stored row, so what the console shows and what the store
/// keeps cannot differ, and always under the label that says what it is: an opinion, not evidence.
/// </summary>
internal static partial class ReportRenderer
{
    public static string Label(bool spanish) => spanish ? "Análisis de IA: opinión, no evidencia" : "AI analysis: opinion, not evidence";

    public static void Render(AnalystReport report, TextWriter output)
    {
        var es = report.Spanish;
        output.WriteLine(Label(es));
        output.WriteLine(Heading(report));
        output.WriteLine(es
            ? $"Proveedor: {report.Provider}. Modelo pedido: {report.Model}; contestó: {report.AnsweredBy ?? "ninguno"}{(report.FellBack ? " (modelo de respaldo)" : "")}."
            : $"Provider: {report.Provider}. Model asked: {report.Model}; answered by: {report.AnsweredBy ?? "none"}{(report.FellBack ? " (fallback model)" : "")}.");
        output.WriteLine(es
            ? $"Estado: {report.Status}{Reason(report)}. {N(report.InputTokens)} tokens de entrada y {N(report.OutputTokens)} de salida{(report.OperatorPays ? "" : " (costo contado como cero)")}. {report.ToolCalls.Count} llamadas a herramientas."
            : $"Status: {report.Status}{Reason(report)}. {N(report.InputTokens)} input and {N(report.OutputTokens)} output tokens{(report.OperatorPays ? "" : " (cost counted as zero)")}. {report.ToolCalls.Count} tool calls.");
        output.WriteLine();

        foreach (var line in Outcome(report)) output.WriteLine(line);

        var (lines, loosening) = Mark(report.Text, es);
        if (loosening > 0)
        {
            output.WriteLine(es
                ? $"{loosening} línea(s) de abajo recomiendan aflojar la protección. Es justo lo que pediría un texto inyectado en la evidencia: compruébelas usted contra la evidencia y nunca las aplique desde este informe."
                : $"{loosening} line(s) below recommend loosening protection. That is exactly what text injected into the evidence would ask for: check each against the evidence yourself, and never apply one from this report.");
            output.WriteLine();
        }
        foreach (var line in lines) output.WriteLine(line);
        if (report.TextTruncated)
            output.WriteLine(es ? "[El texto se cortó en 64 KB al guardarlo.]" : "[The text was cut at 64 KB when it was stored.]");

        if (report.ToolCalls.Count > 0)
        {
            output.WriteLine();
            output.WriteLine(es ? "Llamadas a herramientas (solo lectura):" : "Tool calls (read-only):");
            foreach (var call in report.ToolCalls)
                output.WriteLine($"  {call.Sequence}. {call.Name} {call.Arguments}{(call.IsError ? (es ? "  -> error" : "  -> error") : "")}");
        }
    }

    /// <summary>One line per report, for <c>wpshield analyst reports</c>.</summary>
    public static string Summary(AnalystReport report) =>
        $"#{report.Id,-5} {Time(report.Started)}  {report.Role,-11} {report.Status,-10} {report.Provider,-9} " +
        $"{N(report.InputTokens),9} in  {Subject(report)}";

    private static string Heading(AnalystReport report)
    {
        var es = report.Spanish;
        var what = report.Role switch
        {
            "digest" => es ? $"resumen de las últimas {report.Subject}" : $"digest of the last {report.Subject}",
            "investigate" => es ? $"investigación de {report.Subject}" : $"investigation of {report.Subject}",
            _ => es ? "pregunta" : "question"
        };
        var heading = $"#{report.Id} - {what} - {Time(report.Started)}";
        return report.Question is null ? heading : heading + Environment.NewLine + (es ? "Pregunta: " : "Question: ") + report.Question;
    }

    private static string Subject(AnalystReport report)
    {
        var subject = report.Role == "ask" ? report.Question ?? "" : report.Subject ?? "";
        return subject.Length <= 80 ? subject : subject[..77] + "...";
    }

    private static string Reason(AnalystReport report) => report.StopReason is null ? "" : $" ({report.StopReason})";

    private static IEnumerable<string> Outcome(AnalystReport report)
    {
        var es = report.Spanish;
        switch (report.Status)
        {
            case ReportStatus.Completed:
                yield break;
            case ReportStatus.Refused:
                yield return es
                    ? $"El modelo se negó a contestar (categoría: {report.RefusalCategory ?? "ninguna"}). Es una negativa, no un informe vacío: no se concluyó nada."
                    : $"The model declined this request (category: {report.RefusalCategory ?? "none given"}). This is a refusal, not an empty report: nothing was concluded.";
                if (report.RefusalExplanation is { } explanation) yield return (es ? "Explicación: " : "Explanation: ") + explanation;
                break;
            case ReportStatus.Truncated:
                yield return es
                    ? $"La respuesta se cortó en el límite de {report.Bound}: lo que sigue está incompleto."
                    : $"The answer was cut off at the bound of {report.Bound}: what follows is incomplete.";
                break;
            case ReportStatus.Stopped:
                yield return (es ? "Detenido por un límite: " : "Stopped by a bound: ") + report.Bound;
                if (report.Error is { } stopped) yield return stopped;
                break;
            case ReportStatus.Running:
                yield return es
                    ? "Esta ejecución no terminó: el proceso acabó antes de registrar cómo terminó. No es un análisis."
                    : "This run did not finish: the process ended before it recorded an outcome. It is not an analysis.";
                break;
            default:
                if (report.Bound is { } bound) yield return (es ? "Límite: " : "Bound: ") + bound;
                yield return report.Error ?? (es ? "La ejecución falló." : "The run failed.");
                break;
        }
        yield return "";
    }

    /// <summary>
    /// Marks every line that recommends loosening protection. A line the model marked keeps its marker
    /// and is flagged; a line that names a setting or wording whose change can loosen protection is
    /// flagged even though the model did not mark it, because the case that matters - the model writing
    /// under the influence of injected text - is the case where it will not.
    /// </summary>
    internal static (List<string> Lines, int Loosening) Mark(string text, bool spanish)
    {
        var lines = new List<string>();
        var count = 0;
        if (text.Length == 0) return (lines, 0);
        foreach (var line in text.Split('\n'))
        {
            var body = ListPrefix().Replace(line, "");
            if (body.StartsWith(AnalystPrompts.LooseningMarker(false), StringComparison.OrdinalIgnoreCase) ||
                body.StartsWith(AnalystPrompts.LooseningMarker(true), StringComparison.OrdinalIgnoreCase))
            {
                count++;
                lines.Add("!! " + line);
            }
            else if (MayLoosen().IsMatch(line))
            {
                count++;
                lines.Add((spanish ? "[puede aflojar la protección: compruébelo] " : "[may loosen protection: check it] ") + line);
            }
            else
            {
                lines.Add(line);
            }
        }
        return (lines, count);
    }

    private static string N(long value) => value.ToString("N0", CultureInfo.InvariantCulture);

    private static string Time(DateTimeOffset time) => time.UtcDateTime.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) + " UTC";

    [GeneratedRegex(@"^\s*(?:[-*•]|\d{1,2}[.)])?\s*")]
    private static partial Regex ListPrefix();

    [GeneratedRegex(@"\bdefense\.[a-z0-9_.]+|\ballow[- ]?list|\bwhite[- ]?list|\bunblock|\bexempt|\blista (?:de permitid|blanca)|\bdesbloque|\beximi|\bexent|\b(?:disable|turn off|switch off|stop|desactiv\w*|deshabilit\w*|apag\w*|deten\w*)\b[^\n]{0,60}\b(?:sensor|collector|recolector|service|servicio|evidence|evidencia|monitor)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex MayLoosen();
}
