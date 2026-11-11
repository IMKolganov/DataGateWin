using System.Net.Http;
using DataGateWin.CrashReporting;
using DataGateWin.Localization;
using DataGateWin.Services.Auth;
using DataGateWin.Services.Statistics;
using DataGateWin.Services.Ui;
using DataGateWin.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using DataGateMonitor.SharedModels.Enums;

namespace DataGateWin.Pages;

public sealed partial class StatisticsPage : Page
{
    public StatisticsViewModel Vm { get; }
    private bool _updatingChrome;

    public StatisticsPage(HttpClient authedApiHttp, AuthSession session)
    {
        Vm = new StatisticsViewModel(new StatisticsApiClient(authedApiHttp), session);
        InitializeComponent();
        UiThemeBrushes.ApplyMissingCardChrome(this);
        UiThemeBrushes.ApplyCardBackground(ChartCard);
        try { Chart.FlowDirection = FlowDirection.LeftToRight; }
        catch (Exception ex) { CrashReporter.ReportNonFatal(ex, "StatisticsPage.ChartInit"); }
        Vm.PropertyChanged += (_, _) =>
            UiDispatch.Run(DispatcherQueue, ApplyVmChrome, "StatisticsPage.ApplyVm");
        ActualThemeChanged += (_, _) =>
            Vm.SetChartTheme(ActualTheme == ElementTheme.Dark);
        ApplyLocalizedChrome();
        ApplyVmChrome();
        Vm.SetChartTheme(ActualTheme == ElementTheme.Dark);
        WinUiLanguageService.LanguageChanged += OnLang;
        Unloaded += (_, _) => WinUiLanguageService.LanguageChanged -= OnLang;
    }

    public void ApplyOnShown()
    {
        ApplyLocalizedChrome();
        ApplyVmChrome();
        WinUiLanguageService.ForceChartsLeftToRight(this);
        Vm.RefreshChart();
    }

    private void OnLang(object? sender, EventArgs e)
        => DispatcherQueue.TryEnqueue(ApplyOnShown);

    private void ApplyLocalizedChrome()
    {
        TitleText.Text = Loc.T("Stats_Title");
        CombinedLabel.Text = Loc.T("Stats_Combined");
        IncomingLabel.Text = "↓ " + Loc.T("Stats_Incoming");
        OutgoingLabel.Text = "↑ " + Loc.T("Stats_Outgoing");
        ChartTitle.Text = Loc.T("Stats_ChartTitle");
        ChartHint.Text = Vm.ChartDescription;
        FromLabel.Text = Loc.T("Stats_From");
        ToLabel.Text = Loc.T("Stats_To");
        _updatingChrome = true;
        try
        {
            FiltersTitle.Text = Loc.T("Stats_Filters");
            GroupingLabel.Text = Loc.T("Stats_Grouping");
            MetricLabel.Text = Loc.T("Stats_Metric");
            CustomPeriodExpander.Header = Loc.T("Stats_CustomPeriod");
            GroupingCombo.Items.Clear();
            foreach (var grouping in new[] { OverviewGrouping.Auto, OverviewGrouping.Hours, OverviewGrouping.Days, OverviewGrouping.Months, OverviewGrouping.Years })
                GroupingCombo.Items.Add(new ComboBoxItem { Content = Loc.T("Stats_Group_" + grouping), Tag = grouping.ToString() });
            MetricCombo.Items.Clear();
            foreach (var metric in Enum.GetValues<StatisticsMetric>())
                MetricCombo.Items.Add(new ComboBoxItem { Content = Loc.T("Stats_Metric_" + metric), Tag = metric.ToString() });
            PresetButtons.Children.Clear();
            foreach (var preset in new[] { "24h", "7d", "30d", "2m", "3m", "6m", "1y", "2y" })
            {
                var button = new ToggleButton { Content = Loc.T("Stats_Preset_" + preset), Tag = preset, CornerRadius = new CornerRadius(14) };
                button.Click += Preset_OnClick;
                PresetButtons.Children.Add(button);
            }
        }
        finally { _updatingChrome = false; }
        ApplyButtonText.Text = Loc.T("Stats_Apply");
        ResetButtonText.Text = Loc.T("Stats_Reset");
    }

    private void ApplyVmChrome()
    {
        if (_updatingChrome) return;
        _updatingChrome = true;
        try
        {
            GroupingText.Text = Vm.GroupingText;
            PeriodText.Text = Vm.PeriodText;
            TotalUploadedText.Text = Vm.TotalUploadedText;
            TotalIncomingText.Text = Vm.TotalIncomingText;
            TotalCombinedText.Text = Vm.TotalCombinedText;
            ErrorText.Text = Vm.ErrorText ?? "";
            LoadingRing.IsActive = Vm.IsLoading;
            GroupingCombo.IsEnabled = MetricCombo.IsEnabled = CustomPeriodExpander.IsEnabled = !Vm.IsLoading;
            ErrorText.Visibility = string.IsNullOrWhiteSpace(ErrorText.Text) ? Visibility.Collapsed : Visibility.Visible;
            LoadingRing.Visibility = Vm.IsLoading ? Visibility.Visible : Visibility.Collapsed;
            if (Vm.FromLocalDate is { } from) FromPicker.Date = from;
            if (Vm.ToLocalDate is { } to) ToPicker.Date = to;
            foreach (ComboBoxItem item in GroupingCombo.Items)
                if (item.Tag is string groupName && Enum.TryParse<OverviewGrouping>(groupName, out var grouping) && grouping == Vm.Grouping) GroupingCombo.SelectedItem = item;
            foreach (ComboBoxItem item in MetricCombo.Items)
                if (item.Tag is string metricName && Enum.TryParse<StatisticsMetric>(metricName, out var metric) && metric == Vm.Metric) MetricCombo.SelectedItem = item;
            foreach (ToggleButton button in PresetButtons.Children)
            {
                button.IsChecked = (string)button.Tag == Vm.SelectedPreset;
                button.IsEnabled = !Vm.IsLoading;
            }
            Bindings.Update();
        }
        catch (Exception ex) { CrashReporter.ReportNonFatal(ex, "StatisticsPage.ApplyVmChrome"); }
        finally { _updatingChrome = false; }
    }

    private async void Preset_OnClick(object sender, RoutedEventArgs e)
    {
        if (_updatingChrome || Vm.IsLoading || sender is not ToggleButton { Tag: string preset }) return;
        Vm.ApplyPreset(preset);
        ApplyVmChrome();
        await Vm.ApplyFiltersCommand.ExecuteAsync(null);
    }

    private async void GroupingCombo_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_updatingChrome || Vm.IsLoading || GroupingCombo.SelectedItem is not ComboBoxItem { Tag: string grouping }) return;
        if (!Enum.TryParse<OverviewGrouping>(grouping, out _)) return;
        Vm.SetGroupingCommand.Execute(grouping);
        await Vm.ApplyFiltersCommand.ExecuteAsync(null);
    }

    private void MetricCombo_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!_updatingChrome && MetricCombo.SelectedItem is ComboBoxItem { Tag: string name }
            && Enum.TryParse<StatisticsMetric>(name, out var metric)) Vm.Metric = metric;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        try
        {
            await Vm.LoadAsync(CancellationToken.None);
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "StatisticsPage.OnLoaded");
        }
    }

    private void FromPicker_OnDateChanged(CalendarDatePicker sender, CalendarDatePickerDateChangedEventArgs args)
    {
        if (!_updatingChrome && args.NewDate is { } d)
            Vm.FromLocalDate = d;
    }

    private void ToPicker_OnDateChanged(CalendarDatePicker sender, CalendarDatePickerDateChangedEventArgs args)
    {
        if (!_updatingChrome && args.NewDate is { } d)
            Vm.ToLocalDate = d;
    }

    private async void Apply_OnClick(object sender, RoutedEventArgs e)
        => await Vm.ApplyFiltersCommand.ExecuteAsync(null);

    private async void Reset_OnClick(object sender, RoutedEventArgs e)
    {
        Vm.ResetFiltersCommand.Execute(null);
        await Vm.ApplyFiltersCommand.ExecuteAsync(null);
    }
}
