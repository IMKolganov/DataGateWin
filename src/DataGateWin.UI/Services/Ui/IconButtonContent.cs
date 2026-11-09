using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace DataGateWin.Services.Ui;

/// <summary>Fluent System Icons glyphs (subset font) and icon+label content for command buttons.</summary>
internal static class IconButtonContent
{
    public static readonly Microsoft.UI.Xaml.Media.FontFamily IconFont =
        new("ms-appx:///Assets/Fonts/FluentIcons.ttf#FluentSystemIcons-Regular");

    public const string Connect = "\uE99A";
    public const string Disconnect = "\uF60A";
    public const string Refresh = "\uF191";
    public const string Delete = "\uF34D";
    public const string Save = "\uF680";
    public const string Accept = "\uF295";
    public const string Reset = "\uF1A0";
    public const string OpenFile = "\uF42F";
    public const string Paste = "\uF2D6";
    public const string Copy = "\uF32C";
    public const string Mail = "\uF507";
    public const string Send = "\uF69A";
    public const string Contact = "\uF5D3";
    public const string Code = "\uF2F0";
    public const string Back = "\uF15C";
    public const string Info = "\uF4A4";
    public const string SignOut = "\U000F08E6";
    public const string Download = "\uF151";
    public const string Globe = "\uF45B";
    public const string People = "\uF5A9";
    public const string Calendar = "\U000F0285";
    public const string Settings = "\uF6AA";
    public const string Cancel = "\uF36A";
    public const string OpenExternal = "\uF583";
    public const string Home = "\uF481";
    public const string Folder = "\uF15A";
    public const string Chart = "\uF340";
    public const string Language = "\uF834";
    public const string Appearance = "\uF2F6";
    public const string Network = "\uF562";
    public const string Account = "\uF5BE";
    public const string Lock = "\uE790";
    public const string Wifi = "\uF8AD";
    public const string List = "\uF4EE";
    public const string Clock = "\uF2DE";
    public const string Shield = "\uF6BF";
    public const string Key = "\uF4B7";
    public const string Warning = "\uF86A";

    public static UIElement Heading(string glyph, string text, double fontSize = 20)
    {
        var panel = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10 };
        panel.Children.Add(new FontIcon
        {
            FontFamily = IconFont,
            Glyph = glyph,
            FontSize = fontSize >= 20 ? 18 : 16,
            VerticalAlignment = VerticalAlignment.Center,
        });
        panel.Children.Add(new TextBlock
        {
            Text = text,
            FontSize = fontSize,
            FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
            VerticalAlignment = VerticalAlignment.Center,
            TextWrapping = TextWrapping.Wrap,
        });
        return panel;
    }

    public static UIElement Create(string glyph, string text, double fontSize = 14)
    {
        var panel = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
        panel.Children.Add(new FontIcon
        {
            FontFamily = IconFont,
            Glyph = glyph,
            FontSize = fontSize,
            VerticalAlignment = VerticalAlignment.Center,
        });
        panel.Children.Add(new TextBlock
        {
            Text = text,
            VerticalAlignment = VerticalAlignment.Center,
            TextWrapping = TextWrapping.NoWrap,
        });
        return panel;
    }

    public static void Apply(Button button, string glyph, string text)
        => button.Content = Create(glyph, text);
}
