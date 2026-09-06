using System.Net.Http;
using DataGateWin.Localization;
using DataGateWin.Services.Auth;
using DataGateWin.Services.Statistics;
using DataGateWin.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace DataGateWin.Pages;

public sealed partial class StatisticsPage : Page
{
    private readonly StatisticsViewModel _vm;

    public StatisticsPage(HttpClient authedApiHttp, AuthSession session)
    {
        InitializeComponent();
        _vm = new StatisticsViewModel(new StatisticsApiClient(authedApiHttp), session);
        _vm.PropertyChanged += (_, _) => ApplyVm();
        ApplyLocalizedChrome();
        ApplyVm();
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

    private void ApplyVm()
    {
        GroupingText.Text = _vm.GroupingText;
        PeriodText.Text = _vm.PeriodText;
        TotalUploadedText.Text = _vm.TotalUploadedText;
        ChartStubText.Text = _vm.ChartStubText;
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
