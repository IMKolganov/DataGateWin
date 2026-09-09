using System.Globalization;
using DataGateWin.Services.VpnServers;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Documents;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Imaging;

namespace DataGateWin.Services.Ui;

/// <summary>
/// Renders server names with a country flag image.
/// Windows Segoe UI Emoji has no national-flag glyphs, so emoji text shows as letters (FI/DE).
/// </summary>
internal static class ServerNameUi
{
    private const double FlagWidth = 22;
    private const double FlagHeight = 16.5;

    /// <summary>PNG bytes only — never cache <see cref="BitmapImage"/> (one source → many Images = FailFast).</summary>
    private static readonly Dictionary<string, byte[]?> FlagBytesCache = new(StringComparer.OrdinalIgnoreCase);
    private static readonly object FlagCacheLock = new();

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
            var flagImage = CreateFlagImage(flag);
            if (flagImage is not null)
                panel.Children.Add(flagImage);
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
            AppendFlagInline(target, flag);
            if (!string.IsNullOrEmpty(rest))
                target.Inlines.Add(new Run { Text = rest });
            return;
        }

        target.Inlines.Add(new Run { Text = serverName.Trim() });
    }

    /// <summary>Any flag emoji in the string is replaced with a flag image.</summary>
    public static void SetTextEnlargingFlags(TextBlock target, string text)
    {
        // Do not use on long/status strings — hundreds of Inlines FailFast WinUI.
        target.Inlines.Clear();
        if (string.IsNullOrEmpty(text))
            return;

        var enumerator = StringInfo.GetTextElementEnumerator(text);
        while (enumerator.MoveNext())
        {
            var element = enumerator.GetTextElement();
            if (ServerNameFlag.IsFlagGrapheme(element))
                AppendFlagInline(target, element);
            else
                target.Inlines.Add(new Run { Text = element });
        }
    }

    /// <summary>Fresh <see cref="BitmapImage"/> every call (safe for ComboBox + network footer).</summary>
    public static ImageSource? TryGetFlagImage(string? serverNameOrFlagEmoji)
        => TryCreateFlagBitmap(serverNameOrFlagEmoji);

    private static void AppendFlagInline(TextBlock target, string flagEmoji)
    {
        var image = CreateFlagImage(flagEmoji);
        if (image is null)
            return;
        target.Inlines.Add(new InlineUIContainer
        {
            Child = image,
        });
        target.Inlines.Add(new Run { Text = " " });
    }

    private static Image? CreateFlagImage(string? serverNameOrFlagEmoji)
    {
        var bmp = TryCreateFlagBitmap(serverNameOrFlagEmoji);
        if (bmp is null)
            return null;
        var image = new Image
        {
            Width = FlagWidth,
            Height = FlagHeight,
            Stretch = Stretch.Uniform,
            VerticalAlignment = VerticalAlignment.Center,
        };
        return UiSafeImage.TryAssign(image, bmp, "ServerNameUi.CreateFlagImage") ? image : null;
    }

    private static BitmapImage? TryCreateFlagBitmap(string? serverNameOrFlagEmoji)
    {
        var bytes = TryGetFlagBytes(serverNameOrFlagEmoji);
        return bytes is null ? null : UiFileBitmap.TryLoadFromBytes(bytes, decodePixelWidth: 48);
    }

    private static byte[]? TryGetFlagBytes(string? serverNameOrFlagEmoji)
    {
        if (!ServerNameFlag.TryGetIso2(serverNameOrFlagEmoji, out var iso))
            return null;

        lock (FlagCacheLock)
        {
            if (FlagBytesCache.TryGetValue(iso, out var cached))
                return cached;
        }

        try
        {
            var path = Path.Combine(AppContext.BaseDirectory, "Assets", "Flags", iso.ToLowerInvariant() + ".png");
            var bytes = File.Exists(path) ? UiFileBytes.TryReadImage(path) : null;
            lock (FlagCacheLock)
                FlagBytesCache[iso] = bytes;
            return bytes;
        }
        catch
        {
            lock (FlagCacheLock)
                FlagBytesCache[iso] = null;
            return null;
        }
    }
}
