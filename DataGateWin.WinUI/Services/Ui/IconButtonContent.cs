using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace DataGateWin.Services.Ui;

/// <summary>Segoe MDL2 glyphs and icon+label content for command buttons.</summary>
internal static class IconButtonContent
{
    public const string Connect = "\uE704";
    public const string Disconnect = "\uE8CD";
    public const string Refresh = "\uE72C";
    public const string Delete = "\uE74D";
    public const string Save = "\uE74E";
    public const string Accept = "\uE73E";
    public const string Reset = "\uE8F2";
    public const string OpenFile = "\uE8E5";
    public const string Paste = "\uE77F";
    public const string Copy = "\uE8C8";
    public const string Mail = "\uE715";
    public const string Send = "\uE724";
    public const string Contact = "\uE8BD";
    public const string Code = "\uE943";
    public const string Back = "\uE72B";
    public const string Info = "\uE946";
    public const string SignOut = "\uE7E8";
    public const string Download = "\uE896";
    public const string Globe = "\uE774";
    public const string People = "\uE716";
    public const string Calendar = "\uE787";
    public const string Settings = "\uE713";
    public const string Cancel = "\uE711";
    public const string OpenExternal = "\uE8A7";
    public const string Home = "\uE80F";
    public const string Folder = "\uE8B7";
    public const string Chart = "\uE9D9";
    public const string Language = "\uE8C1";
    public const string Appearance = "\uE790";
    public const string Network = "\uE968";
    public const string Account = "\uE77B";
    public const string Lock = "\uE72E";
    public const string Wifi = "\uE701";
    public const string List = "\uE8FD";
    public const string Clock = "\uE823";
    public const string Shield = "\uEA18";
    public const string Key = "\uE192";
    public const string Warning = "\uE7BA";

    public static UIElement Heading(string glyph, string text, double fontSize = 20)
    {
        var panel = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10 };
        panel.Children.Add(new FontIcon
        {
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
