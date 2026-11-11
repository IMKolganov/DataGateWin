using DataGateWin.Localization;
using DataGateWin.Services.VpnServers;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace DataGateWin.Pages.Home;

public sealed partial class HomePage
{
    private static readonly IpLocationClient LocationClient = new(new System.Net.Http.HttpClient
    {
        MaxResponseContentBufferSize = 16 * 1024,
    });
    private readonly IpLocationSession _userLocationSession = new(LocationClient.TryGetAsync);

    private async Task LoadUserLocationAsync()
    {
        try
        {
            if (await _userLocationSession.TryLoadAsync() && IsLoaded)
                UpdateServerMap();
        }
        catch (Exception)
        {
            // Includes UI teardown: optional marker failures must stay isolated.
        }
    }

    private void CancelUserLocationRequest()
    {
        _userLocationSession.Cancel();
    }

    private void AddUserLocationMarker()
    {
        if (_userLocationSession.Location is not { } location) return;
        try
        {
            var label = Loc.T("Home_Map_YourIpLocation");
            var marker = new Button
            {
                Width = 20, Height = 20, MinWidth = 0, MinHeight = 0,
                Padding = new Thickness(0), CornerRadius = new CornerRadius(10),
                Background = new SolidColorBrush(Microsoft.UI.Colors.MediumOrchid),
                BorderBrush = new SolidColorBrush(Microsoft.UI.Colors.White),
                BorderThickness = new Thickness(3),
                RenderTransformOrigin = new Windows.Foundation.Point(0.5, 0.5),
                RenderTransform = new ScaleTransform(),
                Flyout = new Flyout
                {
                    Content = new TextBlock { Text = label, TextWrapping = TextWrapping.Wrap, MaxWidth = 280 },
                },
            };
            foreach (var key in new[] { "ButtonBackgroundPointerOver", "ButtonBackgroundPressed" })
                marker.Resources[key] = new SolidColorBrush(Microsoft.UI.Colors.MediumOrchid);
            ToolTipService.SetToolTip(marker, label);
            Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(marker, label);
            Canvas.SetLeft(marker, (location.Longitude + 180) * 2 - 10);
            Canvas.SetTop(marker, (90 - location.Latitude) * 2 - 10);
            Canvas.SetZIndex(marker, 10);
            ServerMapMarkers.Children.Add(marker);
        }
        catch (Exception)
        {
            // A failed user marker must not affect the server markers.
        }
    }
}
