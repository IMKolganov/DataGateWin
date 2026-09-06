using System.Diagnostics;
using DataGateMonitor.SharedModels.DataGateMonitor.Auth.Responses;
using DataGateWin.CrashReporting;
using DataGateWin.Localization;
using DataGateWin.Services.Auth;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.ApplicationModel.DataTransfer;

namespace DataGateWin.Views;

public sealed class FreeTierOnboardingWindow
{
    private readonly IFreeTierAccessApiClient _api;
    private FreeTierAccessStatusResponse _status;
    private string? _linkCode;
    private DateTimeOffset _codeExpiresAtUtc;
    private bool _isBusy;
    private bool _linkCodeExpiredNotice;
    private readonly DispatcherQueueTimer _pollTimer;
    private readonly DispatcherQueueTimer _countdownTimer;
    private ContentDialog? _dialog;

    private TextBlock _bodyText = null!;
    private TextBlock _codeExpiredText = null!;
    private Border _linkCodeBorder = null!;
    private TextBlock _linkCodeText = null!;
    private TextBlock _linkCodeExpiresText = null!;
    private TextBlock _linkCodeExpiresSoonText = null!;
    private TextBlock _linkCodeStepsText = null!;
    private TextBlock _errorText = null!;
    private Button _checkAgainButton = null!;
    private Button _openChannelButton = null!;
    private Button _primaryActionButton = null!;
    private Button _copyCodeButton = null!;

    public FreeTierOnboardingWindow(IFreeTierAccessApiClient api, FreeTierAccessStatusResponse status)
    {
        _api = api ?? throw new ArgumentNullException(nameof(api));
        _status = status ?? throw new ArgumentNullException(nameof(status));

        var dq = DispatcherQueue.GetForCurrentThread();
        _pollTimer = dq.CreateTimer();
        _pollTimer.Interval = TimeSpan.FromSeconds(5);
        _pollTimer.Tick += (_, _) => _ = RefreshStatusInternalAsync();

        _countdownTimer = dq.CreateTimer();
        _countdownTimer.Interval = TimeSpan.FromSeconds(1);
        _countdownTimer.Tick += (_, _) => UpdateLinkCodeCountdown();
    }

    public async Task ShowAsync(XamlRoot xamlRoot)
    {
        var root = BuildUi();
        ApplyStatusToUi();

        _dialog = new ContentDialog
        {
            Title = Loc.T("FreeTierOnboarding_TitleSubscribe"),
            Content = root,
            XamlRoot = xamlRoot,
            CloseButtonText = Loc.T("Action_Ok"),
        };

        _pollTimer.Start();
        UpdateLinkCodeCountdown();
        try
        {
            await _dialog.ShowAsync();
        }
        finally
        {
            _pollTimer.Stop();
            _countdownTimer.Stop();
        }
    }

    private FrameworkElement BuildUi()
    {
        _bodyText = new TextBlock { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 10) };
        _codeExpiredText = new TextBlock
        {
            Foreground = new SolidColorBrush(Microsoft.UI.Colors.OrangeRed),
            TextWrapping = TextWrapping.Wrap,
            Visibility = Visibility.Collapsed,
            Text = Loc.T("FreeTierOnboarding_CodeExpired"),
            Margin = new Thickness(0, 0, 0, 10),
        };
        _linkCodeText = new TextBlock { FontSize = 22, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold, FontFamily = new FontFamily("Consolas") };
        _copyCodeButton = new Button { Content = Loc.T("FreeTierOnboarding_CopyCode"), MinWidth = 110 };
        _copyCodeButton.Click += CopyCode_OnClick;
        _linkCodeExpiresText = new TextBlock { Opacity = 0.8, Margin = new Thickness(0, 8, 0, 0) };
        _linkCodeExpiresSoonText = new TextBlock
        {
            Foreground = new SolidColorBrush(Microsoft.UI.Colors.OrangeRed),
            TextWrapping = TextWrapping.Wrap,
            Visibility = Visibility.Collapsed,
            Margin = new Thickness(0, 6, 0, 0),
        };
        _linkCodeStepsText = new TextBlock { TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 8, 0, 0) };

        var codeHeader = new Grid();
        codeHeader.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        codeHeader.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        Grid.SetColumn(_linkCodeText, 0);
        Grid.SetColumn(_copyCodeButton, 1);
        codeHeader.Children.Add(_linkCodeText);
        codeHeader.Children.Add(_copyCodeButton);

        _linkCodeBorder = new Border
        {
            Padding = new Thickness(10),
            CornerRadius = new CornerRadius(8),
            Visibility = Visibility.Collapsed,
            Background = (Brush)Application.Current.Resources["ControlFillColorSecondaryBrush"],
            Child = new StackPanel
            {
                Children =
                {
                    codeHeader,
                    _linkCodeExpiresText,
                    _linkCodeExpiresSoonText,
                    _linkCodeStepsText,
                    new TextBlock
                    {
                        Text = Loc.T("FreeTierOnboarding_OpenBotHint"),
                        Opacity = 0.85,
                        TextWrapping = TextWrapping.Wrap,
                        Margin = new Thickness(0, 8, 0, 0),
                    },
                },
            },
        };

        _errorText = new TextBlock
        {
            Foreground = new SolidColorBrush(Microsoft.UI.Colors.OrangeRed),
            TextWrapping = TextWrapping.Wrap,
            Visibility = Visibility.Collapsed,
        };

        _checkAgainButton = new Button
        {
            Content = Loc.T("FreeTierOnboarding_CheckAgain"),
            HorizontalAlignment = HorizontalAlignment.Stretch,
            Margin = new Thickness(0, 0, 0, 8),
        };
        _checkAgainButton.Click += async (_, _) => await RefreshStatusInternalAsync();

        _openChannelButton = new Button
        {
            Content = Loc.T("FreeTierOnboarding_OpenChannel"),
            HorizontalAlignment = HorizontalAlignment.Stretch,
            Margin = new Thickness(0, 0, 0, 8),
            Visibility = Visibility.Collapsed,
        };
        _openChannelButton.Click += (_, _) =>
            OpenTelegramUrl(FreeTierOnboardingPolicy.ToTelegramChannelUrl(_status.RequiredChannel));

        _primaryActionButton = new Button
        {
            Content = Loc.T("FreeTierOnboarding_OpenChannel"),
            HorizontalAlignment = HorizontalAlignment.Stretch,
            Style = (Style)Application.Current.Resources["AccentButtonStyle"],
        };
        _primaryActionButton.Click += PrimaryAction_OnClick;

        return new StackPanel
        {
            Spacing = 4,
            Children =
            {
                _bodyText,
                new TextBlock
                {
                    Text = Loc.T("FreeTierOnboarding_TelegramVpnHint"),
                    Opacity = 0.85,
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(0, 0, 0, 10),
                },
                _codeExpiredText,
                _linkCodeBorder,
                _errorText,
                _checkAgainButton,
                _openChannelButton,
                _primaryActionButton,
            },
        };
    }

    private async void PrimaryAction_OnClick(object sender, RoutedEventArgs e)
    {
        var mode = FreeTierOnboardingPolicy.GetCopyMode(_status);
        if (mode == FreeTierOnboardingCopyMode.LinkAccount && _linkCode == null)
        {
            await RequestCodeInternalAsync();
            return;
        }

        if (_linkCode != null)
        {
            OpenTelegramUrl(FreeTierOnboardingPolicy.DefaultTelegramBotUrl);
            return;
        }

        OpenTelegramUrl(FreeTierOnboardingPolicy.ToTelegramChannelUrl(_status.RequiredChannel));
    }

    private void CopyCode_OnClick(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(_linkCode))
            return;
        try
        {
            var data = new DataPackage();
            data.SetText(_linkCode);
            Clipboard.SetContent(data);
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "FreeTierOnboardingWindow.CopyCode");
        }
    }

    private async Task RefreshStatusInternalAsync()
    {
        if (_isBusy)
            return;
        SetBusy(true);
        try
        {
            var resp = await _api.GetStatusAsync(CancellationToken.None);
            var updated = resp.Data;
            if (updated == null)
            {
                ShowError(Loc.T("FreeTierOnboarding_StatusRefreshFailed"));
                return;
            }

            _status = updated;
            ApplyStatusToUi();
            if (!FreeTierOnboardingPolicy.ShouldShow(_status))
                _dialog?.Hide();
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "FreeTierOnboardingWindow.RefreshStatus");
            ShowError(Loc.T("FreeTierOnboarding_StatusRefreshFailed"));
        }
        finally
        {
            SetBusy(false);
        }
    }

    private async Task RequestCodeInternalAsync()
    {
        if (_isBusy || !_status.CanRequestAccountLinkCode)
            return;
        SetBusy(true);
        _linkCodeExpiredNotice = false;
        try
        {
            var resp = await _api.RequestAccountLinkCodeAsync(CancellationToken.None);
            if (resp.Data == null || string.IsNullOrWhiteSpace(resp.Data.Code))
            {
                ShowError(resp.Message ?? Loc.T("FreeTierOnboarding_CodeRequestFailed"));
                return;
            }

            _linkCode = resp.Data.Code.Trim();
            _codeExpiresAtUtc = DateTimeOffset.UtcNow.AddSeconds(resp.Data.ExpiresInSeconds);
            ClearError();
            ApplyStatusToUi();
            UpdateLinkCodeCountdown();
            _countdownTimer.Start();
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "FreeTierOnboardingWindow.RequestCode");
            ShowError(Loc.T("FreeTierOnboarding_CodeRequestFailed"));
        }
        finally
        {
            SetBusy(false);
        }
    }

    private void ApplyStatusToUi()
    {
        var channelLabel = FreeTierOnboardingPolicy.ResolveChannelLabel(_status);
        var copyMode = FreeTierOnboardingPolicy.GetCopyMode(_status);
        var titleKey = copyMode == FreeTierOnboardingCopyMode.LinkAccount
            ? "FreeTierOnboarding_TitleLink"
            : "FreeTierOnboarding_TitleSubscribe";
        if (_dialog is not null)
            _dialog.Title = Loc.T(titleKey);

        _bodyText.Text = copyMode switch
        {
            FreeTierOnboardingCopyMode.LinkAccount => Loc.T("FreeTierOnboarding_BodyLink", channelLabel),
            FreeTierOnboardingCopyMode.SubscribeOnly => Loc.T("FreeTierOnboarding_BodySubscribeOnly", channelLabel),
            _ => Loc.T("FreeTierOnboarding_BodyGeneric", channelLabel),
        };

        _openChannelButton.Visibility = copyMode == FreeTierOnboardingCopyMode.Generic
            ? Visibility.Collapsed
            : Visibility.Visible;

        _codeExpiredText.Visibility = _linkCodeExpiredNotice && _linkCode == null
            ? Visibility.Visible
            : Visibility.Collapsed;

        if (_linkCode != null)
        {
            _linkCodeBorder.Visibility = Visibility.Visible;
            _linkCodeText.Text = _linkCode;
            _linkCodeStepsText.Text = Loc.T("FreeTierOnboarding_CodeStepsWithVpn", _linkCode);
            _primaryActionButton.Content = Loc.T("FreeTierOnboarding_OpenBot");
        }
        else
        {
            _linkCodeBorder.Visibility = Visibility.Collapsed;
            _primaryActionButton.Content = copyMode == FreeTierOnboardingCopyMode.LinkAccount
                ? Loc.T("FreeTierOnboarding_GetCode")
                : Loc.T("FreeTierOnboarding_OpenChannel");
        }

        _primaryActionButton.IsEnabled = !_isBusy &&
            (copyMode != FreeTierOnboardingCopyMode.LinkAccount || _status.CanRequestAccountLinkCode || _linkCode != null);
    }

    private void UpdateLinkCodeCountdown()
    {
        if (_linkCode == null || _codeExpiresAtUtc == default)
        {
            _countdownTimer.Stop();
            _linkCodeExpiresText.Text = "";
            _linkCodeExpiresSoonText.Visibility = Visibility.Collapsed;
            return;
        }

        var now = DateTimeOffset.UtcNow;
        if (FreeTierOnboardingPolicy.IsLinkCodeExpired(_codeExpiresAtUtc, now))
        {
            _linkCode = null;
            _codeExpiresAtUtc = default;
            _linkCodeExpiredNotice = true;
            _countdownTimer.Stop();
            ApplyStatusToUi();
            return;
        }

        var secondsLeft = (int)Math.Ceiling((_codeExpiresAtUtc - now).TotalSeconds);
        _linkCodeExpiresText.Text = Loc.T(
            "FreeTierOnboarding_CodeExpires",
            FreeTierOnboardingPolicy.FormatCountdown(secondsLeft));

        if (FreeTierOnboardingPolicy.ShouldWarnLinkCodeExpiringSoon(secondsLeft))
        {
            _linkCodeExpiresSoonText.Text = Loc.T(
                "FreeTierOnboarding_CodeExpiresSoon",
                FreeTierOnboardingPolicy.FormatCountdown(secondsLeft));
            _linkCodeExpiresSoonText.Visibility = Visibility.Visible;
        }
        else
        {
            _linkCodeExpiresSoonText.Visibility = Visibility.Collapsed;
        }
    }

    private void ShowError(string message)
    {
        _errorText.Text = message;
        _errorText.Visibility = Visibility.Visible;
    }

    private void ClearError()
    {
        _errorText.Text = "";
        _errorText.Visibility = Visibility.Collapsed;
    }

    private void SetBusy(bool busy)
    {
        _isBusy = busy;
        _checkAgainButton.IsEnabled = !busy;
        _openChannelButton.IsEnabled = !busy;
        _copyCodeButton.IsEnabled = !busy && _linkCode != null;
        ApplyStatusToUi();
    }

    private static void OpenTelegramUrl(string url)
    {
        if (string.IsNullOrWhiteSpace(url))
            return;
        try
        {
            Process.Start(new ProcessStartInfo { FileName = url, UseShellExecute = true });
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "FreeTierOnboardingWindow.OpenTelegramUrl");
        }
    }
}
