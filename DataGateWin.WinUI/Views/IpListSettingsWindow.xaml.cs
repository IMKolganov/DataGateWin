using System.Globalization;
using DataGateWin.Configuration;
using DataGateWin.Localization;
using DataGateWin.Services.IpList;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.Graphics;

namespace DataGateWin.Views;

public sealed partial class IpListSettingsWindow : Window
{
    private readonly IpListRoutesRepository _repo = new();
    private readonly TaskCompletionSource _closedTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private bool _suppressToggle;
    private bool _loaded;

    public IpListSettingsWindow()
    {
        InitializeComponent();
        AppWindow.Resize(new SizeInt32(560, 720));
        if (AppWindow.Presenter is OverlappedPresenter presenter)
        {
            presenter.IsMinimizable = false;
            presenter.IsMaximizable = false;
        }

        ApplyLocalizedChrome();
        Closed += (_, _) => _closedTcs.TrySetResult();
    }

    public Task ShowAsync()
    {
        Activate();
        return _closedTcs.Task;
    }

    private void ApplyLocalizedChrome()
    {
        Title = Loc.T("IpList_Title");
        WindowsNoticeText.Text = Loc.T("IpList_WindowsNotice");
        EnableTitleText.Text = Loc.T("IpList_EnableTitle");
        EnableSubtitleText.Text = Loc.T("IpList_EnableSubtitle");
        DisabledNotice.Text = Loc.T("IpList_DisabledNotice");
        SourceTitleText.Text = Loc.T("IpList_SourceTitle");
        SourceSubtitleText.Text = Loc.T("IpList_SourceSubtitle");
        FrequencyLabelText.Text = Loc.T("IpList_FrequencyLabel");
        CoverageLabelText.Text = Loc.T("IpList_CoverageLabel");
        CoverageWinNoteText.Text = Loc.T("IpList_CoverageWinNote");
        CoverageFastRadio.Content = Loc.T("IpList_CoverageFast");
        CoverageFullRadio.Content = Loc.T("IpList_CoverageFull");
        RouteLimitLabelText.Text = Loc.T("IpList_RouteLimitLabel");
        RouteLimitHintText.Text = Loc.T("IpList_RouteLimitHint");
        SaveButton.Content = Loc.T("IpList_Save");
        UpdateNowButton.Content = Loc.T("IpList_UpdateNow");
        StatusTitleText.Text = Loc.T("IpList_StatusTitle");
    }

    private void RootScroll_OnLoaded(object sender, RoutedEventArgs e)
    {
        if (_loaded)
            return;
        _loaded = true;

        if (FrequencyCombo.Items.Count == 0)
        {
            foreach (IpListUpdateFrequency f in Enum.GetValues<IpListUpdateFrequency>())
            {
                FrequencyCombo.Items.Add(new ComboBoxItem
                {
                    Tag = f,
                    Content = FrequencyLabel(f),
                });
            }
        }

        ReloadUiFromStore();
    }

    private static string FrequencyLabel(IpListUpdateFrequency f) =>
        f switch
        {
            IpListUpdateFrequency.SixHours => Loc.T("IpList_Freq_6h"),
            IpListUpdateFrequency.Daily => Loc.T("IpList_Freq_Daily"),
            IpListUpdateFrequency.Weekly => Loc.T("IpList_Freq_Weekly"),
            IpListUpdateFrequency.Manual => Loc.T("IpList_Freq_Manual"),
            _ => f.ToString(),
        };

    private void ReloadUiFromStore()
    {
        var s = IpListStore.LoadSettings();
        var st = IpListStore.LoadState().Status;

        _suppressToggle = true;
        CidrEnabledToggle.IsOn = s.CidrListsEnabled;
        _suppressToggle = false;

        UrlsTextBox.Text = string.Join("\n", s.SourceUrls);
        SelectFrequency(s.UpdateFrequency);
        if (s.CoverageMode == IpListCoverageMode.Fast)
            CoverageFastRadio.IsChecked = true;
        else
            CoverageFullRadio.IsChecked = true;

        RouteLimitTextBox.Text = IpListRouteConfig.SanitizeAndroid12OvpnRouteLimit(s.OvpnRouteLimit)
            .ToString(CultureInfo.InvariantCulture);

        ApplyEnabledVisual(s.CidrListsEnabled);
        RefreshStatusTexts(st);
        SaveMessageText.Visibility = Visibility.Collapsed;
    }

    private void SelectFrequency(IpListUpdateFrequency target)
    {
        foreach (ComboBoxItem item in FrequencyCombo.Items)
        {
            if (item.Tag is IpListUpdateFrequency f && f == target)
            {
                FrequencyCombo.SelectedItem = item;
                return;
            }
        }

        if (FrequencyCombo.Items.Count > 0)
            FrequencyCombo.SelectedIndex = 0;
    }

    private void ApplyEnabledVisual(bool enabled)
    {
        DisabledNotice.Visibility = enabled ? Visibility.Collapsed : Visibility.Visible;
        UrlsTextBox.IsEnabled = enabled;
        FrequencyCombo.IsEnabled = enabled;
        CoverageFastRadio.IsEnabled = enabled;
        CoverageFullRadio.IsEnabled = enabled;
        RouteLimitTextBox.IsEnabled = enabled;
        SaveButton.IsEnabled = true;
        UpdateNowButton.IsEnabled = enabled;
    }

    private void RefreshStatusTexts(IpListRuntimeStatus st)
    {
        var updated = st.LastUpdatedEpochMs is { } ms
            ? DateTimeOffset.FromUnixTimeMilliseconds(ms).ToLocalTime().ToString("g", CultureInfo.CurrentCulture)
            : Loc.T("IpList_LastUpdatedNever");

        LastUpdatedText.Text = $"{Loc.T("IpList_LastUpdated")} {updated}";
        var routesLine = Loc.T("IpList_LoadedRoutesFmt", st.LoadedRouteCount);
        if (st.ReachedRouteLimit)
            routesLine += "\n" + Loc.T("IpList_SourceListTruncated");
        LoadedRoutesText.Text = routesLine;
        LastErrorText.Text = $"{Loc.T("IpList_LastError")} {st.LastError ?? Loc.T("IpList_LastErrorNone")}";
    }

    private void CidrEnabledToggle_OnToggled(object sender, RoutedEventArgs e)
    {
        if (_suppressToggle)
            return;
        ApplyEnabledVisual(CidrEnabledToggle.IsOn);
    }

    private void SaveButton_OnClick(object sender, RoutedEventArgs e)
    {
        var limit = int.TryParse(RouteLimitTextBox.Text.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out var l)
            ? l
            : IpListRouteConfig.DefaultAndroid12OvpnRouteLimit;

        if (limit < IpListRouteConfig.MinAndroid12OvpnRouteLimit ||
            limit > IpListRouteConfig.MaxAndroid12OvpnRouteLimit)
        {
            SaveMessageText.Text = Loc.T(
                "IpList_RouteLimitErrorFmt",
                IpListRouteConfig.MinAndroid12OvpnRouteLimit,
                IpListRouteConfig.MaxAndroid12OvpnRouteLimit);
            SaveMessageText.Visibility = Visibility.Visible;
            return;
        }

        var urls = UrlsTextBox.Text
            .Split('\n')
            .Select(x => x.Trim())
            .Where(x => x.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (urls.Count == 0)
            urls = IpListDefaults.DefaultSourceUrls.ToList();

        var freq = FrequencyCombo.SelectedItem is ComboBoxItem { Tag: IpListUpdateFrequency f }
            ? f
            : IpListUpdateFrequency.Daily;

        var coverage = CoverageFastRadio.IsChecked == true
            ? IpListCoverageMode.Fast
            : IpListCoverageMode.Full;

        var settings = new IpListUserSettings
        {
            CidrListsEnabled = CidrEnabledToggle.IsOn,
            SourceUrls = urls,
            UpdateFrequency = freq,
            CoverageMode = coverage,
            OvpnRouteLimit = limit,
        };

        IpListStore.SaveSettings(settings);
        SaveMessageText.Text = Loc.T("IpList_Saved");
        SaveMessageText.Visibility = Visibility.Visible;
        RefreshStatusTexts(IpListStore.LoadState().Status);
    }

    private async void UpdateNowButton_OnClick(object sender, RoutedEventArgs e)
    {
        UpdateNowButton.IsEnabled = false;
        try
        {
            var result = await _repo.UpdateNowAsync(CancellationToken.None).ConfigureAwait(true);
            RefreshStatusTexts(IpListStore.LoadState().Status);
            if (result.Error is null)
            {
                SaveMessageText.Text = Loc.T("IpList_UpdateReadyFmt", result.RouteCount);
            }
            else
            {
                SaveMessageText.Text = result.UsedFallback
                    ? Loc.T("IpList_UpdateFailedFallbackFmt", result.Error)
                    : Loc.T("IpList_UpdateFailedFmt", result.Error);
            }

            SaveMessageText.Visibility = Visibility.Visible;
        }
        finally
        {
            UpdateNowButton.IsEnabled = CidrEnabledToggle.IsOn;
        }
    }
}
