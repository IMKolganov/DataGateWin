using System.Globalization;
using DataGateWin.Services.VpnServers;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Documents;
using Microsoft.UI.Xaml.Media;

namespace DataGateWin.Services.Ui;

/// <summary>Renders server names with the leading flag emoji as a larger “icon”.</summary>
internal static class ServerNameUi
{
    private const double FlagFontSize = 20;
    private static readonly FontFamily EmojiFont = new("Segoe UI Emoji");

    public static FrameworkElement CreateRow(string? serverName, double nameFontSize = 14, bool muted = false)
    {
        var panel = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            Spacing = 8,
            VerticalAlignment = VerticalAlignment.Center,
        };

        if (ServerNameFlag.TrySplit(serverName, out var flag, out var rest))
        {
            panel.Children.Add(CreateFlagText(flag));
            if (!string.IsNullOrEmpty(rest))
            {
                panel.Children.Add(new TextBlock
                {
                    Text = rest,
                    FontSize = nameFontSize,
                    VerticalAlignment = VerticalAlignment.Center,
                    TextTrimming = TextTrimming.CharacterEllipsis,
                    Opacity = muted ? 0.75 : 1,
                });
            }
        }
        else
        {
            panel.Children.Add(new TextBlock
            {
                Text = string.IsNullOrWhiteSpace(serverName) ? "?" : serverName.Trim(),
                FontSize = nameFontSize,
                VerticalAlignment = VerticalAlignment.Center,
                TextTrimming = TextTrimming.CharacterEllipsis,
                Opacity = muted ? 0.75 : 1,
            });
        }

        return panel;
    }

    public static void SetLabeledServer(TextBlock target, string labelPrefix, string? serverName)
    {
        target.Inlines.Clear();
        target.Inlines.Add(new Run { Text = labelPrefix });

        if (string.IsNullOrWhiteSpace(serverName))
        {
            target.Inlines.Add(new Run { Text = "?" });
            return;
        }

        if (ServerNameFlag.TrySplit(serverName, out var flag, out var rest))
        {
            target.Inlines.Add(new Run
            {
                Text = flag + (string.IsNullOrEmpty(rest) ? "" : " "),
                FontSize = FlagFontSize,
                FontFamily = EmojiFont,
            });
            if (!string.IsNullOrEmpty(rest))
                target.Inlines.Add(new Run { Text = rest });
            return;
        }

        target.Inlines.Add(new Run { Text = serverName.Trim() });
    }

    /// <summary>Any flag emoji in the string is drawn larger (status lines, etc.).</summary>
    public static void SetTextEnlargingFlags(TextBlock target, string text)
    {
        target.Inlines.Clear();
        if (string.IsNullOrEmpty(text))
            return;

        var enumerator = StringInfo.GetTextElementEnumerator(text);
        while (enumerator.MoveNext())
        {
            var element = enumerator.GetTextElement();
            if (ServerNameFlag.IsFlagGrapheme(element))
            {
                target.Inlines.Add(new Run
                {
                    Text = element,
                    FontSize = FlagFontSize,
                    FontFamily = EmojiFont,
                });
            }
            else
            {
                target.Inlines.Add(new Run { Text = element });
            }
        }
    }

    private static TextBlock CreateFlagText(string flagEmoji)
        => new()
        {
            Text = flagEmoji,
            FontSize = FlagFontSize,
            FontFamily = EmojiFont,
            VerticalAlignment = VerticalAlignment.Center,
            IsTextSelectionEnabled = false,
        };
}
