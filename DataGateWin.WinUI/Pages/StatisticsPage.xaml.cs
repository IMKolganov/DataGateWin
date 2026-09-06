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
    public StatisticsViewModel Vm { get; }

    public StatisticsPage(HttpClient authedApiHttp, AuthSession session)
    {
        Vm = new StatisticsViewModel(new StatisticsApiClient(authedApiHttp), session);
        InitializeComponent();
        Vm.PropertyChanged += (_, _) => ApplyVmChrome();
        ActualThemeChanged += (_, _) =>
            Vm.SetChartTheme(ActualTheme == ElementTheme.Dark);
        ApplyLocalizedChrome();
        ApplyVmChrome();
        Vm.SetChartTheme(ActualTheme == ElementTheme.Dark);
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
        GroupingText.Text = Vm.GroupingText;
        PeriodText.Text = Vm.PeriodText;
        TotalUploadedText.Text = Vm.TotalUploadedText;
        ErrorText.Text = Vm.ErrorText ?? "";
        LoadingRing.IsActive = Vm.IsLoading;
        if (Vm.FromLocalDate is { } from)
            FromPicker.Date = from;
        if (Vm.ToLocalDate is { } to)
            ToPicker.Date = to;
        Bindings.Update();
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
        => await Vm.LoadAsync(CancellationToken.None);

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

    private async void Apply_OnClick(object sender, RoutedEventArgs e)
        => await Vm.ApplyFiltersCommand.ExecuteAsync(null);

    private void Reset_OnClick(object sender, RoutedEventArgs e)
        => Vm.ResetFiltersCommand.Execute(null);
}
