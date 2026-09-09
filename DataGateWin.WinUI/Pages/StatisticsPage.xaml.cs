using System.Net.Http;
using DataGateWin.CrashReporting;
using DataGateWin.Localization;
using DataGateWin.Services.Auth;
using DataGateWin.Services.Statistics;
using DataGateWin.Services.Ui;
using DataGateWin.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace DataGateWin.Pages;

public sealed partial class StatisticsPage : Page
{
    public StatisticsViewModel Vm { get; }

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
        FromLabel.Text = Loc.T("Stats_From");
        ToLabel.Text = Loc.T("Stats_To");
        Last7ButtonText.Text = Loc.T("Stats_Last7");
        Last30ButtonText.Text = Loc.T("Stats_Last30");
        Last90ButtonText.Text = Loc.T("Stats_Last90");
        ApplyButtonText.Text = Loc.T("Stats_Apply");
        ResetButtonText.Text = Loc.T("Stats_Reset");
    }

    private void ApplyVmChrome()
    {
        GroupingText.Text = Vm.GroupingText;
        PeriodText.Text = Vm.PeriodText;
        TotalUploadedText.Text = Vm.TotalUploadedText;
        ErrorText.Text = Vm.ErrorText ?? "";
        LoadingRing.IsActive = Vm.IsLoading;
        try
        {
            if (Vm.FromLocalDate is { } from)
                FromPicker.Date = from;
            if (Vm.ToLocalDate is { } to)
                ToPicker.Date = to;
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "StatisticsPage.ApplyVmChrome.Dates");
        }
        Bindings.Update();
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
        if (args.NewDate is { } d)
            Vm.FromLocalDate = d;
    }

    private void ToPicker_OnDateChanged(CalendarDatePicker sender, CalendarDatePickerDateChangedEventArgs args)
    {
        if (args.NewDate is { } d)
            Vm.ToLocalDate = d;
    }

    private void Last7_OnClick(object sender, RoutedEventArgs e)
        => Vm.SetLastDaysCommand.Execute("7");

    private void Last30_OnClick(object sender, RoutedEventArgs e)
        => Vm.SetLastDaysCommand.Execute("30");

    private void Last90_OnClick(object sender, RoutedEventArgs e)
        => Vm.SetLastDaysCommand.Execute("90");

    private async void Apply_OnClick(object sender, RoutedEventArgs e)
        => await Vm.ApplyFiltersCommand.ExecuteAsync(null);

    private void Reset_OnClick(object sender, RoutedEventArgs e)
        => Vm.ResetFiltersCommand.Execute(null);
}
