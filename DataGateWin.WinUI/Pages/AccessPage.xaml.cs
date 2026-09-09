using System.Globalization;
using DataGateWin.CrashReporting;
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
    private IList<VpnServerWithStatusV2Dto>? _renderedServers;

    public AccessPage()
    {
        InitializeComponent();
        UiThemeBrushes.ApplyMissingCardChrome(this);
        var http = App.AuthedApiHttp;
        _vm = new AccessViewModel(new OpenVpnServersApiClient(http), new UserVpnAccessClient(http), App.Session);
        _vm.PropertyChanged += (_, _) => QueueApplyVm();
        ApplyLocalizedChrome();
        ApplyVm();
        WinUiLanguageService.LanguageChanged += OnLang;
        Unloaded += (_, _) => WinUiLanguageService.LanguageChanged -= OnLang;
    }

    private void OnLang(object? sender, EventArgs e)
        => UiDispatch.Run(DispatcherQueue, () =>
        {
            ApplyLocalizedChrome();
            ApplyVm(forceRows: true);
        }, "AccessPage.OnLang");

    public void ApplyLanguage()
    {
        UiThemeBrushes.ApplyMissingCardChrome(this);
        ApplyLocalizedChrome();
        ApplyVm(forceRows: true);
    }

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

    private void QueueApplyVm()
        => UiDispatch.Run(DispatcherQueue, () => ApplyVm(), "AccessPage.ApplyVm");

    private void ApplyVm(bool forceRows = false)
    {
        try
        {
            PlanLineText.Text = UiSafeText.ForStatus(_vm.PlanLineText);
            QuotaMetaText.Text = UiSafeText.ForStatus(_vm.QuotaMetaText);
            QuotaMetaText.Visibility = _vm.QuotaMetaVisible ? Visibility.Visible : Visibility.Collapsed;
            TrafficQuotaHeader.Visibility = _vm.ShowTrafficQuotaTitle ? Visibility.Visible : Visibility.Collapsed;
            QuotaUsedCaptionText.Text = UiSafeText.ForStatus(_vm.QuotaUsedCaption);
            QuotaUsedCaptionText.Visibility = _vm.QuotaUsageCaptionsVisible ? Visibility.Visible : Visibility.Collapsed;
            QuotaRemainingCaptionText.Text = UiSafeText.ForStatus(_vm.QuotaRemainingCaption);
            QuotaRemainingCaptionText.Visibility = _vm.QuotaUsageCaptionsVisible ? Visibility.Visible : Visibility.Collapsed;
            QuotaBar.Visibility = _vm.QuotaBarVisible ? Visibility.Visible : Visibility.Collapsed;
            QuotaBar.Value = AccessQuotaBarMath.ClampPercent(_vm.QuotaBarValue);
            QuotaBar.ShowError = _vm.QuotaBarIsOver;
            QuotaDetailsText.Text = UiSafeText.ForStatus(_vm.QuotaDetailsText);
            QuotaDetailsText.Visibility = _vm.QuotaDetailsVisible ? Visibility.Visible : Visibility.Collapsed;
            ValidityFooterText.Text = UiSafeText.ForStatus(_vm.ValidityFooterText);
            LoadingRing.IsActive = _vm.IsLoading;
            LoadingRing.Visibility = _vm.IsLoading ? Visibility.Visible : Visibility.Collapsed;
            ErrorText.Text = UiSafeText.ForError(_vm.ErrorText);
            TotalClientsLineText.Text = UiSafeText.ForStatus(_vm.TotalClientsLineText);

            if (forceRows || !ReferenceEquals(_renderedServers, _vm.Servers))
            {
                _renderedServers = _vm.Servers;
                RebuildServerRows();
            }

            EmptyServersText.Text = Loc.T("Access_Dash");
            EmptyServersText.Visibility = _vm.Servers.Count == 0 && !_vm.IsLoading
                ? Visibility.Visible
                : Visibility.Collapsed;
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "AccessPage.ApplyVm");
        }
    }

    private void RebuildServerRows()
    {
        ServersHost.Children.Clear();
        foreach (var s in _vm.Servers)
        {
            try
            {
                ServersHost.Children.Add(BuildServerRow(s));
            }
            catch (Exception ex)
            {
                CrashReporter.ReportNonFatal(ex, "AccessPage.BuildServerRow");
            }
        }
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
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star), MinWidth = 160 });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(88) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(100) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(100) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(88) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(110) });

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

        FrameworkElement nameUi;
        try
        {
            nameUi = ServerNameUi.CreateRow(name);
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "AccessPage.CreateRow");
            nameUi = new TextBlock { Text = name, TextTrimming = TextTrimming.CharacterEllipsis };
        }

        if (server is not null && WssServerSelector.IsXrayWindowsSupported(server))
        {
            var stack = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
            stack.Children.Add(nameUi);
            stack.Children.Add(new TextBlock
            {
                Text = Loc.T("Import_Protocol_Xray"),
                Opacity = 0.65,
                VerticalAlignment = VerticalAlignment.Center,
                FontSize = 12,
            });
            Grid.SetColumn(stack, 0);
            grid.Children.Add(stack);
        }
        else if (server is not null && WssServerSelector.IsOpenVpnDirect(server))
        {
            var stack = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
            stack.Children.Add(nameUi);
            stack.Children.Add(new TextBlock
            {
                Text = Loc.T("Import_Protocol_OpenVpn"),
                Opacity = 0.65,
                VerticalAlignment = VerticalAlignment.Center,
                FontSize = 12,
            });
            Grid.SetColumn(stack, 0);
            grid.Children.Add(stack);
        }
        else
        {
            Grid.SetColumn(nameUi, 0);
            grid.Children.Add(nameUi);
        }
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

    /// <summary>Called when nav switches to Access (Loaded may not re-fire for a cached page).</summary>
    public void RefreshOnShown()
    {
        UiThemeBrushes.ApplyMissingCardChrome(this);
        ApplyLocalizedChrome();
        ApplyVm(forceRows: true);
        _vm.RequestReload();
    }

    private void Refresh_OnClick(object sender, RoutedEventArgs e)
        => RefreshOnShown();
}
