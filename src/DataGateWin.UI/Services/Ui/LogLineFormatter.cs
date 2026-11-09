using System.Text.RegularExpressions;
using DataGateWin.Localization;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Documents;
using Microsoft.UI.Xaml.Media;
using Windows.UI;

namespace DataGateWin.Services.Ui;

internal static class LogLineFormatter
{
    private static readonly Regex LogErrorPattern = new(
        @"\b(fatal|failed|failure|exception|auth_failed|access_denied)\b|\berror\b(?!""?\s*[:=]\s*(?:null|false|0)\b)|\berr\s*=\s*[1-9]\d*\b|ошибк|не удалось",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly Regex LogTagPattern = new(
        @"\G\s*\[[a-z][a-z0-9_-]*\]",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
    private static readonly Regex LogWarningPattern = new(
        @"\b(warn|warning|retry|retrying|timeout|timed out)\b|предупрежд",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly Regex LogSuccessPattern = new(
        @"\b(UI attached|Engine connected|connect OK|client connected|Initialization Sequence Completed|success|succeeded)\b",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly Regex LogFieldPattern = new(
        @"\b[a-zA-Z][a-zA-Z0-9_]*(?==)",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);


    public static Paragraph CreateParagraph(string original, bool dark)
    {
        // Bound display work; the original log remains available in the backing buffer.
        var line = original.Length > 2048 ? original[..2048] + " …" : original;
        var paragraph = new Paragraph { Margin = new Thickness(0) };
            var normal = dark ? Microsoft.UI.Colors.Gainsboro : Microsoft.UI.Colors.Black;
            var timestamp = dark ? Microsoft.UI.Colors.CornflowerBlue : Microsoft.UI.Colors.RoyalBlue;
            var success = dark ? Microsoft.UI.Colors.LightGreen : Microsoft.UI.Colors.DarkGreen;
            var error = dark ? Microsoft.UI.Colors.LightCoral : Microsoft.UI.Colors.Firebrick;
            var warning = dark ? Microsoft.UI.Colors.Khaki : Microsoft.UI.Colors.SaddleBrown;
            var tags = dark ? Microsoft.UI.Colors.LightSkyBlue : Microsoft.UI.Colors.DarkSlateBlue;
            var fieldColor = dark ? Microsoft.UI.Colors.Silver : Microsoft.UI.Colors.DimGray;
            var isWarning = LogWarningPattern.IsMatch(line);
            var isError = !isWarning && LogErrorPattern.IsMatch(line);
            var isSuccess = !isWarning && !isError && (LogSuccessPattern.IsMatch(line)
                || line.EndsWith(Loc.T("Home_Log_UiAttached"), StringComparison.Ordinal));
            var baseColor = isWarning ? warning : isError ? error : isSuccess ? success : normal;
            var spans = new List<(int Start, int End, Color Color, bool Bold)>();
            if (line.Length >= 10 && line[0] == '[' && line[9] == ']')
            {
                spans.Add((0, 10, isSuccess ? success : timestamp, false));
                var tag = LogTagPattern.Match(line, 10);
                while (tag.Success)
                {
                    var color = tag.Value.Trim().ToLowerInvariant() switch
                    {
                        "[engine]" => dark ? Microsoft.UI.Colors.Plum : Microsoft.UI.Colors.DarkMagenta,
                        "[ipc]" or "[control]" or "[events]" => dark ? Microsoft.UI.Colors.Turquoise : Microsoft.UI.Colors.Teal,
                        "[dns]" => dark ? Microsoft.UI.Colors.PeachPuff : Microsoft.UI.Colors.SaddleBrown,
                        _ => tags,
                    };
                    spans.Add((tag.Index, tag.Index + tag.Length, color, false));
                    tag = tag.NextMatch();
                }
            }
            if (isWarning || isError || isSuccess)
            {
                var pattern = isWarning ? LogWarningPattern : isError ? LogErrorPattern : LogSuccessPattern;
                foreach (Match match in pattern.Matches(line))
                    spans.Add((match.Index, match.Index + match.Length, baseColor, true));
            }
            else
            {
                var end = line.IndexOf('{');
                foreach (Match match in LogFieldPattern.Matches(end >= 0 ? line[..end] : line))
                    spans.Add((match.Index, match.Index + match.Length, fieldColor, false));
            }
            paragraph.Inlines.Clear();
            var position = 0;
            void Add(string part, Color color, bool bold)
            {
                paragraph.Inlines.Add(new Run { Text = part, Foreground = new SolidColorBrush(color),
                    FontWeight = bold ? Microsoft.UI.Text.FontWeights.SemiBold : Microsoft.UI.Text.FontWeights.Normal });
            }
            foreach (var span in spans.OrderBy(s => s.Start))
            {
                if (span.Start < position) continue;
                if (span.Start > position) Add(line[position..span.Start], baseColor, false);
                Add(line[span.Start..span.End], span.Color, span.Bold);
                position = span.End;
            }
            if (position < line.Length) Add(line[position..], baseColor, false);
        return paragraph;
    }
}
