using DataGateWin.Localization;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
namespace DataGateWin.Services.Ui;
internal static class ProtocolIconUi
{
    public static FrameworkElement? Create(bool xray, bool openVpn)
    {
        if (!xray && !openVpn)
            return null;
        FrameworkElement icon;
        if (xray)
        {
            // Official Project X logo geometry: XTLS/XTLS.github.io/logo-light.svg.
            var canvas = new Canvas { Width = 1000, Height = 1000 };
            foreach (var points in new double[][]
            {
                [530,530,900,530,650,650,530,1000],
                [470,530,470,900,350,650,0,530],
                [530,470,530,100,650,350,1000,470],
                [470,470,100,470,350,350,470,0],
            })
            {
                var polygon = new Polygon { Fill = new TextBlock().Foreground };
                for (var i = 0; i < points.Length; i += 2)
                    polygon.Points.Add(new Windows.Foundation.Point(points[i], points[i + 1]));
                canvas.Children.Add(polygon);
            }
            icon = new Viewbox { Width = 20, Height = 20, Child = canvas };
        }
        else
        {
            var image = new Image { Width = 20, Height = 20, Stretch = Stretch.Uniform };
            var bitmap = UiFileBitmap.TryLoad(System.IO.Path.Combine(AppContext.BaseDirectory, "Assets", "Protocols", "openvpn.png"), 40);
            if (bitmap is null || !UiSafeImage.TryAssign(image, bitmap, "AccessPage.ProtocolIcon"))
                return null;
            icon = image;
        }
        icon.VerticalAlignment = VerticalAlignment.Center;
        var label = Loc.T(xray ? "Import_Protocol_Xray" : "Import_Protocol_OpenVpn");
        ToolTipService.SetToolTip(icon, label);
        Microsoft.UI.Xaml.Automation.AutomationProperties.SetName(icon, label);
        return icon;
    }

}
