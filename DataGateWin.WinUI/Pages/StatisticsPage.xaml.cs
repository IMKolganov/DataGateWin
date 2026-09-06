using System.Net.Http;
using DataGateWin.CrashReporting;
using DataGateWin.Localization;
using DataGateWin.Services.Auth;
using DataGateWin.Services.Statistics;
using DataGateWin.ViewModels;
using LiveChartsCore.SkiaSharpView.WinUI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace DataGateWin.Pages;

public sealed partial class StatisticsPage : Page
{
    private readonly StatisticsViewModel _vm;
    private CartesianChart? _chart;

    public StatisticsPage(HttpClient authedApiHttp, AuthSession session)
    {
        InitializeComponent();
        _vm = new StatisticsViewModel(new StatisticsApiClient(authedApiHttp), session);
        _vm.PropertyChanged += (_, args) =>
        {
            ApplyVmChrome();
            if (args.PropertyName is null
                or nameof(StatisticsViewModel.Series)
                or nameof(StatisticsViewModel.XAxes)
                or nameof(StatisticsViewModel.YAxes))
                ApplyChart();
        };
        ActualThemeChanged += (_, _) =>
            _vm.SetChartTheme(ActualTheme == ElementTheme.Dark);
        ApplyLocalizedChrome();
        ApplyVmChrome();
        EnsureChart();
        _vm.SetChartTheme(ActualTheme == ElementTheme.Dark);
        ApplyChart();
    }

    private void EnsureChart()
    {
        if (_chart is not null)
            return;

        try
        {
            _chart = new CartesianChart
            {
                Height = 260,
                TooltipPosition = LiveChartsCore.Measure.TooltipPosition.Top,
            };
            ChartHost.Children.Clear();
            ChartHost.Children.Add(_chart);
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "StatisticsPage.EnsureChart");
            ChartHost.Children.Clear();
            ChartHost.Children.Add(new TextBlock
            {
                Text = Loc.T("Stats_Series_Upload") + " — chart unavailable: " + ex.Message,
                TextWrapping = TextWrapping.Wrap,
                Opacity = 0.85,
            });
        }
    }

    private void ApplyChart()
    {
        if (_chart is null)
            return;
        _chart.Series = _vm.Series;
        _chart.XAxes = _vm.XAxes;
        _chart.YAxes = _vm.YAxes;
    }

    private void ApplyLocalizedChrome()
    {
        TitleText.Text = Loc.T("Stats_Title");
        FromLabel.Text = Loc.T("Stats_From");
        ToLabel.Text = Loc.T("Stats_To");
        Last7Button.Content = "7d";
        Last30Button.Content = "30d";
        ApplyButton.Content = Loc.T("Btn_Refresh");
        ResetButton.Content = Loc.T("Action_Ok");
    }

    private void ApplyVmChrome()
    {
        GroupingText.Text = _vm.GroupingText;
        PeriodText.Text = _vm.PeriodText;
        TotalUploadedText.Text = _vm.TotalUploadedText;
        ErrorText.Text = _vm.ErrorText ?? "";
        LoadingRing.IsActive = _vm.IsLoading;
        if (_vm.FromLocalDate is { } from)
            FromPicker.Date = from;
        if (_vm.ToLocalDate is { } to)
            ToPicker.Date = to;
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
        => await _vm.LoadAsync(CancellationToken.None);

    private void FromPicker_OnDateChanged(CalendarDatePicker sender, CalendarDatePickerDateChangedEventArgs args)
    {
        if (args.NewDate is { } d)
            _vm.FromLocalDate = d;
    }

    private void ToPicker_OnDateChanged(CalendarDatePicker sender, CalendarDatePickerDateChangedEventArgs args)
    {
        if (args.NewDate is { } d)
            _vm.ToLocalDate = d;
    }

    private void Last7_OnClick(object sender, RoutedEventArgs e)
        => _vm.SetLastDaysCommand.Execute("7");

    private void Last30_OnClick(object sender, RoutedEventArgs e)
        => _vm.SetLastDaysCommand.Execute("30");

    private async void Apply_OnClick(object sender, RoutedEventArgs e)
        => await _vm.ApplyFiltersCommand.ExecuteAsync(null);

    private void Reset_OnClick(object sender, RoutedEventArgs e)
        => _vm.ResetFiltersCommand.Execute(null);
}
