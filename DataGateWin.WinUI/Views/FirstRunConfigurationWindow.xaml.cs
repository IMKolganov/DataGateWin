using System.Globalization;
using DataGateWin.Configuration;
using DataGateWin.CrashReporting;
using DataGateWin.Localization;
using DataGateWin.Services.Ui;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace DataGateWin.Views;

public sealed partial class FirstRunConfigurationWindow : Window
{
    private readonly TaskCompletionSource<bool> _tcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private bool _completed;

    public FirstRunConfigurationWindow(ApiSettings? existingApi, GoogleAuthSettings? existingGoogle)
    {
        InitializeComponent();
        WindowChrome.ApplyDefault(this, width: 560, height: 480);

        Title = Loc.T("FirstRun_Title");
        TitleText.Text = Loc.T("FirstRun_Title");
        SubtitleText.Text = Loc.T("FirstRun_Subtitle");
        ApiLabel.Text = Loc.T("FirstRun_ApiBaseUrl");
        ClientIdLabel.Text = Loc.T("FirstRun_GoogleClientId");
        PortLabel.Text = Loc.T("FirstRun_RedirectPort");
        ApiBaseUrlBox.PlaceholderText = Loc.T("FirstRun_Placeholder_ApiBaseUrl");
        GoogleClientIdBox.PlaceholderText = Loc.T("FirstRun_Placeholder_GoogleClientId");
        SaveButton.Content = Loc.T("FirstRun_SaveContinue");
        CancelButton.Content = Loc.T("FirstRun_CancelExit");

        ApiBaseUrlBox.Text = string.IsNullOrWhiteSpace(existingApi?.BaseUrl)
            ? DataGatePublicDefaults.ApiBaseUrl
            : existingApi.BaseUrl.Trim();

        GoogleClientIdBox.Text = string.IsNullOrWhiteSpace(existingGoogle?.ClientId)
            ? DataGatePublicDefaults.GoogleDesktopClientId
            : existingGoogle.ClientId.Trim();

        var port = existingGoogle?.RedirectPort ?? 0;
        RedirectPortBox.Text = port > 0
            ? port.ToString(CultureInfo.InvariantCulture)
            : AppsettingsConnection.DefaultRedirectPort.ToString(CultureInfo.InvariantCulture);

        Closed += (_, _) =>
        {
            if (!_completed)
                _tcs.TrySetResult(false);
        };
    }

    public Task<bool> ShowAsync()
    {
        Activate();
        return _tcs.Task;
    }

    private void Save_OnClick(object sender, RoutedEventArgs e)
    {
        StatusText.Visibility = Visibility.Collapsed;

        var api = new ApiSettings { BaseUrl = ApiBaseUrlBox.Text.Trim() };
        var google = new GoogleAuthSettings { ClientId = GoogleClientIdBox.Text.Trim() };

        if (!int.TryParse(RedirectPortBox.Text.Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var port))
        {
            ShowError(Loc.T("FirstRun_Err_Port"));
            return;
        }

        google.RedirectPort = port;

        if (!AppsettingsConnection.IsComplete(api, google))
        {
            if (string.IsNullOrWhiteSpace(api.BaseUrl))
                ShowError(Loc.T("FirstRun_Err_BaseUrl"));
            else if (!Uri.TryCreate(api.BaseUrl, UriKind.Absolute, out var u)
                     || (u.Scheme != Uri.UriSchemeHttp && u.Scheme != Uri.UriSchemeHttps))
                ShowError(Loc.T("FirstRun_Err_BaseUrl"));
            else if (string.IsNullOrWhiteSpace(google.ClientId))
                ShowError(Loc.T("FirstRun_Err_ClientId"));
            else
                ShowError(Loc.T("FirstRun_Err_Port"));
            return;
        }

        try
        {
            AppsettingsConnection.SaveFile(AppContext.BaseDirectory, api, google);
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "FirstRunConfigurationWindow.Save");
            ShowError(Loc.T("FirstRun_Err_SaveFailedFmt", ex.Message));
            return;
        }

        _completed = true;
        _tcs.TrySetResult(true);
        Close();
    }

    private void ShowError(string message)
    {
        StatusText.Text = message;
        StatusText.Visibility = Visibility.Visible;
    }

    private void Cancel_OnClick(object sender, RoutedEventArgs e)
    {
        _completed = true;
        _tcs.TrySetResult(false);
        Close();
    }
}
