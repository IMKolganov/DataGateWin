using System.Globalization;
using DataGateWin.CrashReporting;
using DataGateWin.Localization;
using DataGateWin.Services.Access;
using DataGateWin.Services.Ui;
using DataGateWin.Services.VpnServers;
using DataGateWin.ViewModels;
using DataGateMonitor.SharedModels.DataGateMonitor.VpnServers.Dto;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using Windows.UI;

namespace DataGateWin.Pages;

public sealed partial class AccessPage : Page
{
    private readonly AccessViewModel _vm;
    private IList<VpnServerWithStatusV2Dto>? _renderedServers;

    private enum SortKey { Server, Clients, In, Out, Online, Plan }

    private SortKey _sortKey = SortKey.Server;
    private bool _sortAscending = true;

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
        ServersHeaderRow.Background = UiThemeBrushes.SecondaryFill();
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
        foreach (var (header, label) in new[] { (HdrServer, ColServer), (HdrClients, ColClients), (HdrIn, ColIn), (HdrOut, ColOut), (HdrOnline, ColOnline), (HdrPlan, ColPlan) })
            ToolTipService.SetToolTip(header, label.Text);
        UpdateSortIndicators();
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
            LoadStatusRow.Visibility = _vm.IsLoading || !string.IsNullOrWhiteSpace(ErrorText.Text) ? Visibility.Visible : Visibility.Collapsed;
            TotalClientsLineText.Text = UiSafeText.ForStatus(_vm.TotalClientsLineText);

            if (forceRows || !ReferenceEquals(_renderedServers, _vm.Servers))
            {
                _renderedServers = _vm.Servers;
                RebuildServerRows();
            }

            EmptyServersText.Text = Loc.T("Access_Dash");
            EmptyServersText.Visibility = ServersHost.Items.Count == 0 && !_vm.IsLoading
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
        ServersHost.Items.Clear();
        var all = _vm.Servers ?? new List<VpnServerWithStatusV2Dto>();
        var rows = ApplySort(all).ToList();
        ServerCountText.Text = all.Count.ToString(CultureInfo.InvariantCulture);

        EmptyServersText.Text = Loc.T("Access_Dash");
        EmptyServersText.Visibility = rows.Count == 0 && !_vm.IsLoading
            ? Visibility.Visible : Visibility.Collapsed;

        foreach (var s in rows)
        {
            try
            {
                var row = BuildServerRow(s);
                if (ServersHost.Items.Count == 0)
                    row.SizeChanged += (_, _) => ServersHeaderRow.Width = row.ActualWidth;
                ServersHost.Items.Add(row);
            }
            catch (Exception ex)
            {
                CrashReporter.ReportNonFatal(ex, "AccessPage.BuildServerRow");
            }
        }
    }

    private IEnumerable<VpnServerWithStatusV2Dto> ApplySort(IEnumerable<VpnServerWithStatusV2Dto> source)
    {
        static string Name(VpnServerWithStatusV2Dto s) => s.VpnServerResponses?.VpnServer?.ServerName ?? "";
        static bool Online(VpnServerWithStatusV2Dto s) => s.VpnServerResponses?.VpnServer?.IsOnline == true;
        static bool Plan(VpnServerWithStatusV2Dto s)
        {
            var v = s.VpnServerResponses?.VpnServer;
            return v is not null && v.IsAccessibleForUserQuotaPlanOrDefault();
        }

        IOrderedEnumerable<VpnServerWithStatusV2Dto> ordered = _sortKey switch
        {
            SortKey.Clients => _sortAscending ? source.OrderBy(s => s.CountConnectedClients) : source.OrderByDescending(s => s.CountConnectedClients),
            SortKey.In => _sortAscending ? source.OrderBy(s => s.TotalBytesIn) : source.OrderByDescending(s => s.TotalBytesIn),
            SortKey.Out => _sortAscending ? source.OrderBy(s => s.TotalBytesOut) : source.OrderByDescending(s => s.TotalBytesOut),
            SortKey.Online => _sortAscending ? source.OrderBy(Online) : source.OrderByDescending(Online),
            SortKey.Plan => _sortAscending ? source.OrderBy(Plan) : source.OrderByDescending(Plan),
            _ => _sortAscending ? source.OrderBy(Name, StringComparer.OrdinalIgnoreCase) : source.OrderByDescending(Name, StringComparer.OrdinalIgnoreCase),
        };
        // Stable tie-break by name so equal values do not jump around between refreshes.
        return ordered.ThenBy(Name, StringComparer.OrdinalIgnoreCase);
    }

    private void Header_OnClick(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: string tag } || !Enum.TryParse<SortKey>(tag, out var key))
            return;

        if (_sortKey == key)
            _sortAscending = !_sortAscending;
        else
        {
            _sortKey = key;
            // Text/name columns start ascending; numeric columns start with the largest first.
            _sortAscending = key is SortKey.Server;
        }

        UpdateSortIndicators();
        RebuildServerRows();
    }

    private void UpdateSortIndicators()
    {
        void Set(SortKey key, FontIcon icon)
        {
            icon.Visibility = _sortKey == key ? Visibility.Visible : Visibility.Collapsed;
            icon.RenderTransform = new RotateTransform { Angle = _sortAscending ? 0 : 180 };
        }

        Set(SortKey.Server, SortServer);
        Set(SortKey.Clients, SortClients);
        Set(SortKey.In, SortIn);
        Set(SortKey.Out, SortOut);
        Set(SortKey.Online, SortOnline);
        Set(SortKey.Plan, SortPlan);
    }

    private static Grid BuildServerRow(VpnServerWithStatusV2Dto s)
    {
        var server = s.VpnServerResponses?.VpnServer;
        var name = server?.ServerName ?? "?";
        var online = server?.IsOnline == true;
        var plan = server is not null && server.IsAccessibleForUserQuotaPlanOrDefault()
            ? Loc.T("PlanAccess_Yes")
            : Loc.T("PlanAccess_No");

        var grid = new Grid
        {
            Padding = new Thickness(8, 10, 8, 10),
            MinHeight = 60,
            BorderThickness = new Thickness(0, 0, 0, 1),
            BorderBrush = UiThemeBrushes.CardStroke(),
            ColumnSpacing = 4,
            CornerRadius = new CornerRadius(0),
            Background = new SolidColorBrush(Colors.Transparent),
        };

        foreach (var (weight, minimum) in new (double, double)[] { (3, 120), (0.7, 40), (1, 54), (1, 54), (1.1, 64), (0.9, 50) })
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(weight, GridUnitType.Star), MinWidth = minimum });

        void Add(int col, string text, bool muted = false)
        {
            var tb = new TextBlock
            {
                Text = text,
                VerticalAlignment = VerticalAlignment.Center,
                HorizontalAlignment = col is >= 1 and <= 3 ? HorizontalAlignment.Right : HorizontalAlignment.Left,
                TextTrimming = TextTrimming.CharacterEllipsis,
                Opacity = muted ? 0.75 : 1,
            };
            Grid.SetColumn(tb, col);
            ToolTipService.SetToolTip(tb, text);
            grid.Children.Add(tb);
        }

        FrameworkElement nameUi;
        try
        {
            nameUi = ServerNameUi.CreateRow(name, protocolIcon: ProtocolIconUi.Create(
                server is not null && WssServerSelector.IsXrayWindowsSupported(server),
                server is { ServerType: DataGateMonitor.SharedModels.Enums.VpnServerType.OpenVpn }));
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "AccessPage.CreateRow");
            nameUi = new TextBlock { Text = name, TextTrimming = TextTrimming.CharacterEllipsis };
        }

        ToolTipService.SetToolTip(nameUi, name);
        nameUi.VerticalAlignment = VerticalAlignment.Center;
        grid.Children.Add(nameUi);
        Add(1, s.CountConnectedClients.ToString(CultureInfo.InvariantCulture));
        Add(2, FormatBytes(s.TotalBytesIn), muted: true);
        Add(3, FormatBytes(s.TotalBytesOut), muted: true);
        var statusBrush = new SolidColorBrush(online ? Color.FromArgb(255, 0x3D, 0xC0, 0x5C) : Color.FromArgb(255, 0xE0, 0x54, 0x54));
        var statusPanel = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 6, VerticalAlignment = VerticalAlignment.Center };
        statusPanel.Children.Add(new Ellipse
        {
            Width = 8,
            Height = 8,
            VerticalAlignment = VerticalAlignment.Center,
            Fill = statusBrush,
        });
        statusPanel.Children.Add(new TextBlock
        {
            Text = online ? Loc.T("Common_Online") : Loc.T("Common_Offline"),
            TextTrimming = TextTrimming.CharacterEllipsis,
            Foreground = statusBrush,
        });
        Grid.SetColumn(statusPanel, 4);
        grid.Children.Add(statusPanel);
        var allowed = server is not null && server.IsAccessibleForUserQuotaPlanOrDefault();
        var planBadge = new Border
        {
            Padding = new Thickness(8, 4, 8, 4),
            CornerRadius = new CornerRadius(4),
            HorizontalAlignment = HorizontalAlignment.Left,
            VerticalAlignment = VerticalAlignment.Center,
            Background = allowed ? new SolidColorBrush(Color.FromArgb(24, 61, 192, 92)) : UiThemeBrushes.SecondaryFill(),
            Child = new TextBlock { Text = plan, FontSize = 12, Opacity = allowed ? 1 : 0.65 },
        };
        Grid.SetColumn(planBadge, 5);
        grid.Children.Add(planBadge);

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
