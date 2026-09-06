using DataGateWin.Localization;
using DataGateWin.Services.Access;
using DataGateWin.Services.VpnServers;
using DataGateWin.ViewModels;
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
        RefreshButton.Content = Loc.T("Btn_Refresh");
        PlanQuotasLabel.Text = Loc.T("Access_PlanQuotas");
        TrafficQuotaLabel.Text = Loc.T("Access_TrafficQuota");
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
        {
            var name = s.VpnServerResponses?.VpnServer?.ServerName ?? "?";
            ServersList.Items.Add($"{name} · {s.CountConnectedClients}");
        }
    }

    private void Refresh_OnClick(object sender, RoutedEventArgs e)
    {
        if (_vm.RefreshCommand.CanExecute(null))
            _vm.RefreshCommand.Execute(null);
    }
}
