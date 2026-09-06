using System.Globalization;
using DataGateWin.Localization;
using DataGateWin.Services.Access;
using DataGateWin.Services.Ui;
using DataGateWin.Services.VpnServers;
using DataGateWin.ViewModels;
using DataGateMonitor.SharedModels.DataGateMonitor.VpnServers.Dto;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace DataGateWin.Pages;

public sealed partial class AccessPage : Page
{
    private readonly AccessViewModel _vm;

    public AccessPage()
    {
        InitializeComponent();
        var http = App.AuthedApiHttp;
        _vm = new AccessViewModel(new OpenVpnServersApiClient(http), new UserVpnAccessClient(http), App.Session);
        _vm.PropertyChanged += (_, _) => ApplyVm();
        ApplyLocalizedChrome();
        ApplyVm();
        WinUiLanguageService.LanguageChanged += OnLang;
        Unloaded += (_, _) => WinUiLanguageService.LanguageChanged -= OnLang;
    }

    private void OnLang(object? sender, EventArgs e) => DispatcherQueue.TryEnqueue(() =>
    {
        ApplyLocalizedChrome();
        ApplyVm();
    });

    private void ApplyLocalizedChrome()
    {
        TitleText.Text = Loc.T("Access_Title");
        RefreshButtonText.Text = Loc.T("Btn_Refresh");
        PlanQuotasLabel.Text = Loc.T("Access_PlanQuotas");
        TrafficQuotaLabel.Text = Loc.T("Access_TrafficQuota");
        ColServer.Text = Loc.T("Access_Col_Server");
        ColClients.Text = Loc.T("Access_Col_Clients");
        ColIn.Text = Loc.T("Access_Col_In");
        ColOut.Text = Loc.T("Access_Col_Out");
        ColOnline.Text = Loc.T("Access_Col_Online");
        ColPlan.Text = Loc.T("Access_Col_PlanAccess");
    }

    private void ApplyVm()
    {
        PlanLineText.Text = _vm.PlanLineText;
        QuotaMetaText.Text = _vm.QuotaMetaText;
        QuotaMetaText.Visibility = _vm.QuotaMetaVisible ? Visibility.Visible : Visibility.Collapsed;
        TrafficQuotaLabel.Visibility = _vm.ShowTrafficQuotaTitle ? Visibility.Visible : Visibility.Collapsed;
        QuotaBar.Visibility = _vm.QuotaBarVisible ? Visibility.Visible : Visibility.Collapsed;
        QuotaBar.Value = _vm.QuotaBarValue;
        QuotaDetailsText.Text = _vm.QuotaDetailsText;
        QuotaDetailsText.Visibility = _vm.QuotaDetailsVisible ? Visibility.Visible : Visibility.Collapsed;
        ValidityFooterText.Text = _vm.ValidityFooterText;
        LoadingRing.IsActive = _vm.IsLoading;
        ErrorText.Text = _vm.ErrorText ?? "";
        TotalClientsLineText.Text = _vm.TotalClientsLineText;

        ServersList.Items.Clear();
        foreach (var s in _vm.Servers)
            ServersList.Items.Add(BuildServerRow(s));
    }

    private static Grid BuildServerRow(VpnServerWithStatusV2Dto s)
    {
        var server = s.VpnServerResponses?.VpnServer;
        var name = server?.ServerName ?? "?";
        var online = server?.IsOnline == true;
        var plan = server is not null && server.IsAccessibleForUserQuotaPlanOrDefault()
            ? Loc.T("PlanAccess_Yes")
            : Loc.T("PlanAccess_No");

        var grid = new Grid { Padding = new Thickness(12, 8, 12, 8), ColumnSpacing = 8 };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(72) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(88) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(88) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(72) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(80) });

        void Add(int col, string text, bool muted = false)
        {
            var tb = new TextBlock
            {
                Text = text,
                TextTrimming = TextTrimming.CharacterEllipsis,
                Opacity = muted ? 0.75 : 1,
            };
            Grid.SetColumn(tb, col);
            grid.Children.Add(tb);
        }

        var nameUi = ServerNameUi.CreateRow(name);
        Grid.SetColumn(nameUi, 0);
        grid.Children.Add(nameUi);
        Add(1, s.CountConnectedClients.ToString(CultureInfo.InvariantCulture));
        Add(2, FormatBytes(s.TotalBytesIn), muted: true);
        Add(3, FormatBytes(s.TotalBytesOut), muted: true);
        Add(4, online ? Loc.T("Common_Online") : Loc.T("Common_Offline"));
        Add(5, plan);

        return grid;
    }

    private static string FormatBytes(long bytes)
    {
        const double k = 1024.0;
        if (bytes < k) return $"{bytes.ToString(CultureInfo.InvariantCulture)} B";
        var kb = bytes / k;
        if (kb < k) return $"{kb:F1} KB";
        var mb = kb / k;
        if (mb < k) return $"{mb:F1} MB";
        var gb = mb / k;
        return $"{gb:F2} GB";
    }

    private void Refresh_OnClick(object sender, RoutedEventArgs e)
    {
        if (_vm.RefreshCommand.CanExecute(null))
            _vm.RefreshCommand.Execute(null);
    }
}
