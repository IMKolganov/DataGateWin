using DataGateWin.Controllers;
using DataGateWin.CrashReporting;
using DataGateWin.Localization;
using DataGateWin.Services.Ui;
using DataGateWin.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.Storage.Pickers;
using WinRT.Interop;

namespace DataGateWin.Pages;

public sealed partial class ImportPage : Page
{
    private readonly ImportViewModel _vm;
    private bool _suppressProtocolChange;

    public ImportPage(HomeController homeController)
    {
        InitializeComponent();
        UiThemeBrushes.ApplyMissingCardChrome(this);
        _vm = new ImportViewModel(homeController);
        _vm.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName is nameof(ImportViewModel.StatusText) or nameof(ImportViewModel.IsBusy)
                or nameof(ImportViewModel.IsXraySelected))
                UiDispatch.Run(DispatcherQueue, ApplyVmChrome, "ImportPage.ApplyVm");
        };

        ApplyLocalizedChrome();
        FillProtocolCombo();
        RebuildProfileList();
        ApplyVmChrome();

        WinUiLanguageService.LanguageChanged += OnLang;
        Unloaded += (_, _) => WinUiLanguageService.LanguageChanged -= OnLang;
        Loaded += (_, _) => ApplyOnShown();
    }

    public void ApplyOnShown()
    {
        UiThemeBrushes.ApplyMissingCardChrome(this);
        ApplyLocalizedChrome();
        FillProtocolCombo();
        RebuildProfileList();
        ApplyVmChrome();
    }

    private void OnLang(object? sender, EventArgs e) => DispatcherQueue.TryEnqueue(() =>
    {
        ApplyLocalizedChrome();
        FillProtocolCombo();
        _vm.Reload();
        RebuildProfileList();
        ApplyVmChrome();
    });

    private void ApplyLocalizedChrome()
    {
        TitleText.Text = Loc.T("Import_Title");
        SubtitleText.Text = Loc.T("Import_Subtitle");
        ProtocolLabel.Text = Loc.T("Import_Protocol");
        XrayHintText.Text = Loc.T("Import_Hint_Xray");
        ImportSectionLabel.Text = Loc.T("Import_AddSection");
        BrowseButtonText.Text = Loc.T("Import_Browse");
        PasteButtonText.Text = Loc.T("Import_Paste");
        ImportHintText.Text = Loc.T("Import_Hint_OpenVpn");
        ProfilesLabel.Text = Loc.T("Import_SavedProfiles");
        EmptyProfilesText.Text = Loc.T("Import_Empty");
    }

    private void FillProtocolCombo()
    {
        _suppressProtocolChange = true;
        try
        {
            var selected = ProtocolCombo.SelectedIndex;
            ProtocolCombo.Items.Clear();
            ProtocolCombo.Items.Add(Loc.T("Import_Protocol_OpenVpn"));
            ProtocolCombo.Items.Add(Loc.T("Import_Protocol_Xray"));
            ProtocolCombo.SelectedIndex = selected >= 0 ? selected : 0;
            _vm.ProtocolIndex = ProtocolCombo.SelectedIndex;
        }
        finally
        {
            _suppressProtocolChange = false;
        }
    }

    private void ApplyVmChrome()
    {
        StatusText.Text = _vm.StatusText;
        XrayHintText.Visibility = Visibility.Collapsed;
        BrowseButton.IsEnabled = !_vm.IsBusy;
        PasteButton.IsEnabled = !_vm.IsBusy;
        ImportHintText.Text = _vm.IsOpenVpnSelected
            ? Loc.T("Import_Hint_OpenVpn")
            : Loc.T("Import_Hint_Xray");
    }

    private void RebuildProfileList()
    {
        ProfilesList.Items.Clear();
        foreach (var item in _vm.Profiles)
            ProfilesList.Items.Add(BuildProfileRow(item));

        EmptyProfilesText.Visibility = _vm.Profiles.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
    }

    private UIElement BuildProfileRow(ImportedProfileListItem item)
    {
        var grid = new Grid { Padding = new Thickness(8, 10, 8, 10), ColumnSpacing = 12 };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var text = new StackPanel { Spacing = 2 };
        text.Children.Add(new TextBlock { Text = item.Name, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold });
        text.Children.Add(new TextBlock { Text = item.ProtocolLabel, Opacity = 0.7 });
        text.Children.Add(new TextBlock { Text = item.Meta, FontSize = 12, Opacity = 0.55 });
        Grid.SetColumn(text, 0);
        grid.Children.Add(text);

        var connect = new Button
        {
            MinWidth = 100,
            Tag = item.Id,
            IsEnabled = item.CanConnect && !_vm.IsBusy,
        };
        IconButtonContent.Apply(connect, IconButtonContent.Connect, Loc.T("Home_Connect"));
        if (Application.Current.Resources.TryGetValue("AccentButtonStyle", out var accent) && accent is Style accentStyle)
            connect.Style = accentStyle;
        connect.Click += ConnectProfile_OnClick;
        Grid.SetColumn(connect, 1);
        grid.Children.Add(connect);

        var delete = new Button
        {
            Tag = item.Id,
            IsEnabled = !_vm.IsBusy,
        };
        IconButtonContent.Apply(delete, IconButtonContent.Delete, Loc.T("Import_Delete"));
        delete.Click += DeleteProfile_OnClick;
        Grid.SetColumn(delete, 2);
        grid.Children.Add(delete);

        return grid;
    }

    private void ProtocolCombo_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_suppressProtocolChange)
            return;
        _vm.ProtocolIndex = Math.Max(0, ProtocolCombo.SelectedIndex);
        ApplyVmChrome();
    }

    private async void BrowseButton_OnClick(object sender, RoutedEventArgs e)
    {
        try
        {
            var picker = new FileOpenPicker();
            var window = App.CurrentMainWindow ?? throw new InvalidOperationException("No main window");
            InitializeWithWindow.Initialize(picker, WindowNative.GetWindowHandle(window));
            picker.SuggestedStartLocation = PickerLocationId.DocumentsLibrary;
            if (_vm.IsXraySelected)
            {
                picker.FileTypeFilter.Add(".txt");
                picker.FileTypeFilter.Add(".json");
                picker.FileTypeFilter.Add(".conf");
            }
            else
            {
                picker.FileTypeFilter.Add(".ovpn");
                picker.FileTypeFilter.Add(".conf");
                picker.FileTypeFilter.Add(".txt");
            }

            var file = await picker.PickSingleFileAsync();
            if (file is null)
                return;

            var text = await Windows.Storage.FileIO.ReadTextAsync(file);
            _vm.ImportText(text, file.Name);
            RebuildProfileList();
            ApplyVmChrome();
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "ImportPage.Browse");
            _vm.StatusText = Loc.T("Home_Status_IdleErrorFmt", VpnUserFacingError.FromException(ex));
            ApplyVmChrome();
        }
    }

    private async void PasteButton_OnClick(object sender, RoutedEventArgs e)
    {
        var box = new TextBox
        {
            AcceptsReturn = true,
            TextWrapping = TextWrapping.NoWrap,
            FontFamily = new Microsoft.UI.Xaml.Media.FontFamily("Consolas"),
            FontSize = 12,
            MinHeight = 220,
            PlaceholderText = _vm.IsXraySelected
                ? Loc.T("Import_PastePlaceholder_Xray")
                : Loc.T("Import_PastePlaceholder"),
        };

        var dialog = new ContentDialog
        {
            Title = IconButtonContent.Heading(IconButtonContent.Paste, Loc.T("Import_PasteTitle")),
            PrimaryButtonText = Loc.T("Import_Save"),
            CloseButtonText = Loc.T("Login_Cancel"),
            DefaultButton = ContentDialogButton.Primary,
            Content = box,
            XamlRoot = XamlRoot,
        };

        var result = await dialog.ShowAsync();
        if (result != ContentDialogResult.Primary)
            return;

        _vm.ImportText(box.Text ?? "", null);
        RebuildProfileList();
        ApplyVmChrome();
    }

    private async void ConnectProfile_OnClick(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: Guid id })
            return;
        await _vm.ConnectProfileCommand.ExecuteAsync(id);
        RebuildProfileList();
        ApplyVmChrome();
    }

    private void DeleteProfile_OnClick(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: Guid id })
            return;
        _vm.DeleteProfileCommand.Execute(id);
        RebuildProfileList();
        ApplyVmChrome();
    }
}
