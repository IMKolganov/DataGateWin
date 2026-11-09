using System;
using DataGateWin.Localization;
using DataGateWin.Pages.Home;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using Windows.UI;

namespace DataGateWin.Services.Ui;

// Build a fresh visual tree and image sources for each template instance, including
// the selection presenter. Never share ImageSource instances between ComboBox rows.
public sealed class ServerPickerRowConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        if (value is not HomePage.HomeVpnServerListItem item)
            return value;
        var row = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 10, VerticalAlignment = VerticalAlignment.Center };
        row.Children.Add(ServerNameUi.CreateRow(item.Name, protocolIcon: ProtocolIconUi.Create(item.IsXray, !item.IsXray)));
        row.Children.Add(new TextBlock
        {
            Text = Loc.T("Home_ServerRowFmt", "", item.Clients, "").Trim(' ', '·'),
            Opacity = 0.65,
            VerticalAlignment = VerticalAlignment.Center,
        });
        var brush = new SolidColorBrush(item.Online
            ? Color.FromArgb(255, 61, 192, 92) : Color.FromArgb(255, 224, 84, 84));
        row.Children.Add(new Ellipse { Width = 6, Height = 6, Fill = brush, VerticalAlignment = VerticalAlignment.Center });
        row.Children.Add(new TextBlock
        {
            Text = Loc.T(item.Online ? "Common_Online" : "Common_Offline"),
            Foreground = brush,
            VerticalAlignment = VerticalAlignment.Center,
        });
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(row, item.Label);
        return row;
    }

    public object ConvertBack(object value, Type targetType, object parameter, string language)
        => throw new NotSupportedException();
}
