using System.Net.Http;
using DataGateWin.Services.Auth;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace DataGateWin;

/// <summary>
/// Code-only smoke window (no XAML LoadComponent) — prove WinUI process can show UI.
/// </summary>
public sealed class MainWindow : Window
{
    public MainWindow(AuthStateStore authState, HttpClient authedApiHttp)
    {
        _ = authState;
        _ = authedApiHttp;

        Title = "DataGate";
        Content = new Grid
        {
            Children =
            {
                new TextBlock
                {
                    Text = "DataGate WinUI OK (code)",
                    FontSize = 24,
                    HorizontalAlignment = HorizontalAlignment.Center,
                    VerticalAlignment = VerticalAlignment.Center
                }
            }
        };
    }
}
