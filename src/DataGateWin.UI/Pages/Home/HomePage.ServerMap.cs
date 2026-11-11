using DataGateWin.Models.Ipc;
using System.Globalization;
using DataGateWin.Localization;
using DataGateWin.Services.Ui;
using DataGateWin.Services.VpnServers;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace DataGateWin.Pages.Home;

public sealed partial class HomePage
{
    private void UpdateServerMap()
    {
        RefreshMapButton.IsEnabled = _controller.LastUiState == UiState.Idle;
        ToolTipService.SetToolTip(RefreshMapButton, Loc.T("Home_Refresh"));
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(RefreshMapButton, Loc.T("Home_Refresh"));
        ServerMapTitle.Text = Loc.T("Home_Map_Title");
        ServerMapHint.Text = Loc.T("Home_Map_Hint");
        MapLegendServers.Text = Loc.T("Home_Map_LegendServers");
        MapLegendYou.Text = Loc.T("Home_Map_LegendYou");
        MapLegendConnected.Text = Loc.T("Home_Map_LegendConnected");
        ServerMapMarkers.Children.Clear();
        AddUserLocationMarker();
        UpdateMapMarkerScale();
        ServerMapLocations.Items.Clear();
        var rows = _cachedServerRows;
        if (rows is not { Count: > 0 })
        {
            ServerMapStatus.Text = Loc.T("Home_Map_Empty");
            return;
        }

        var groups = rows.GroupBy(row =>
        {
            var country = ServerNameFlag.TryGetIso2(row.Name, out var iso) ? iso : "";
            var hasCoordinates = MapViewportMath.HasCoordinates(row.Latitude, row.Longitude);
            return (Country: country, Latitude: hasCoordinates ? row.Latitude : null,
                Longitude: hasCoordinates ? row.Longitude : null);
        }).OrderBy(group => group.Key.Country);
        var mapped = 0;
        foreach (var group in groups)
        {
            var country = group.Key.Country;
            var servers = group.ToList();
            var title = Loc.T("Home_Map_Unknown");
            if (country.Length == 2)
            {
                try { title = new RegionInfo(country).DisplayName; }
                catch (ArgumentException) { title = country; }
            }
            if (group.Key.Latitude.HasValue)
                title = servers[0].Name;
            // Render flags with the bundled images: Windows displays flag emoji as letters.
            if (ServerNameFlag.TrySplit(title, out _, out var titleWithoutFlag))
                title = titleWithoutFlag;
            var locationLabel = $"{title} · {servers.Count}";
            var flaggedLocationLabel = country.Length == 2 ? $"{country} {locationLabel}" : locationLabel;
            var selected = ServerModeCombo.SelectedIndex == 1 && servers.Any(row =>
                row.Id == (ManualServerCombo.SelectedItem as HomeVpnServerListItem)?.Id);
            var connected = _controller.LastUiState == UiState.Connected && servers.Any(row =>
                _heroServerId > 0 ? row.Id == _heroServerId : row.Name == _heroServerName);
            var color = connected ? Microsoft.UI.Colors.YellowGreen
                : selected ? Microsoft.UI.Colors.DeepSkyBlue
                : servers.Any(row => row.Online) ? Microsoft.UI.Colors.DodgerBlue : Microsoft.UI.Colors.Gray;

            Button CreatePicker(bool marker)
            {
                var button = new Button
                {
                    Content = marker ? null : ServerNameUi.CreateRow(flaggedLocationLabel),
                    Padding = marker ? new Thickness(0) : new Thickness(12, 8, 12, 8),
                    Margin = marker ? new Thickness(0) : new Thickness(0, 0, 8, 8),
                    CornerRadius = new CornerRadius(marker ? 8 : 12),
                    // Keep markers colored while connected; disable selection in the menu.
                    IsEnabled = marker || _controller.LastUiState == UiState.Idle,
                };
                if (marker)
                {
                    button.Width = button.Height = 14;
                    button.MinWidth = button.MinHeight = 0;
                    // Draw the marker as content, so Button's hover/pressed states cannot
                    // replace its status color with the standard grey background.
                    button.Content = new Microsoft.UI.Xaml.Shapes.Ellipse
                    {
                        Width = 14,
                        Height = 14,
                        Fill = new SolidColorBrush(color),
                        Stroke = new SolidColorBrush(Microsoft.UI.Colors.White),
                        StrokeThickness = selected || connected ? 2 : 1,
                    };
                    button.Background = new SolidColorBrush(Microsoft.UI.Colors.Transparent);
                    button.BorderThickness = new Thickness(0);
                    foreach (var key in new[] { "ButtonBackgroundPointerOver", "ButtonBackgroundPressed" })
                        button.Resources[key] = new SolidColorBrush(Microsoft.UI.Colors.Transparent);
                }
                ToolTipService.SetToolTip(button, locationLabel);
                Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(button, title);
                var flyout = new MenuFlyout();
                foreach (var row in servers)
                {
                    var item = new MenuFlyoutItem
                    {
                        Text = CreateServerListItem(row).Label,
                        IsEnabled = row.Online && _controller.LastUiState == UiState.Idle,
                    };
                    item.Click += (_, _) => SelectMapServer(row.Id);
                    flyout.Items.Add(item);
                }
                button.Flyout = flyout;
                return button;
            }

            ServerMapLocations.Items.Add(CreatePicker(false));
            (double X, double Y) point;
            if (group.Key.Latitude is double latitude && group.Key.Longitude is double longitude)
                point = MapViewportMath.Project(latitude, longitude);
            else if (!CountryMapPoints.TryGetValue(country, out point))
                continue;
            mapped += servers.Count;
            var marker = CreatePicker(true);
            marker.RenderTransformOrigin = new Windows.Foundation.Point(0.5, 0.5);
            marker.RenderTransform = new ScaleTransform();
            Canvas.SetLeft(marker, point.X - 7);
            Canvas.SetTop(marker, point.Y - 7);
            ServerMapMarkers.Children.Add(marker);
        }
        UpdateMapMarkerScale();
        ServerMapStatus.Text = Loc.T("Home_Map_Count", mapped, rows.Count);
    }

    private void SelectMapServer(int id)
    {
        if (_controller.LastUiState != UiState.Idle)
            return;
        ServerModeCombo.SelectedIndex = 1;
        foreach (HomeVpnServerListItem item in ManualServerCombo.Items)
        {
            if (item.Id != id) continue;
            ManualServerCombo.SelectedItem = item;
            break;
        }
        UpdateServerMap();
    }
}
