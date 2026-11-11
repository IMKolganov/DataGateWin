using DataGateWin.Localization;
using DataGateWin.Services.Profiles;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace DataGateWin.Views;

internal static class OpenVpnAuthDialog
{
    public static async Task<(bool Proceed, OpenVpnAuthCredentials? Credentials)> TryPromptAsync(
        XamlRoot? xamlRoot,
        ImportedVpnProfile profile)
    {
        if (profile.Protocol != ImportedVpnProtocol.OpenVpn)
            return (true, null);

        var requirement = OpenVpnAuthDetector.ForConnect(profile.ConfigText, profile.LastAuthUsername);
        if (!requirement.NeedsPrompt)
            return (true, null);

        if (xamlRoot is null)
            return (false, null);

        var creds = await ShowAsync(xamlRoot, requirement);
        return (creds is not null, creds);
    }

    public static async Task<OpenVpnAuthCredentials?> ShowAsync(XamlRoot xamlRoot, OpenVpnAuthRequirement requirement)
    {
        var stack = new StackPanel { Spacing = 12, MinWidth = 320 };

        TextBox? userBox = null;
        PasswordBox? passBox = null;
        if (requirement.NeedUsernamePassword)
        {
            userBox = new TextBox
            {
                Header = Loc.T("Import_Auth_User"),
                Text = requirement.PrefillUsername ?? "",
                IsSpellCheckEnabled = false,
            };
            passBox = new PasswordBox { Header = Loc.T("Import_Auth_Password") };
            stack.Children.Add(userBox);
            stack.Children.Add(passBox);
        }

        var otpHeader = string.IsNullOrWhiteSpace(requirement.ChallengePrompt)
            ? Loc.T("Import_Auth_Otp")
            : requirement.ChallengePrompt;
        var hideOtp = requirement.NeedChallenge && !requirement.ChallengeEcho;
        TextBox? otpBox = null;
        PasswordBox? otpPassBox = null;
        if (requirement.NeedChallenge)
        {
            if (hideOtp)
            {
                otpPassBox = new PasswordBox { Header = otpHeader };
                stack.Children.Add(otpPassBox);
            }
            else
            {
                otpBox = new TextBox
                {
                    Header = otpHeader,
                    IsSpellCheckEnabled = false,
                    PlaceholderText = Loc.T("Import_Auth_OtpHint"),
                };
                stack.Children.Add(otpBox);
            }
        }

        string ReadOtp()
            => (otpPassBox?.Password ?? otpBox?.Text ?? "").Trim();

        var dialog = new ContentDialog
        {
            Title = Loc.T("Import_Auth_Title"),
            PrimaryButtonText = Loc.T("Import_Auth_Connect"),
            CloseButtonText = Loc.T("Login_Cancel"),
            DefaultButton = ContentDialogButton.Primary,
            Content = stack,
            XamlRoot = xamlRoot,
        };

        dialog.Closing += (_, e) =>
        {
            if (e.Result != ContentDialogResult.Primary)
                return;
            var user = userBox?.Text?.Trim() ?? "";
            var pass = passBox?.Password ?? "";
            var otp = ReadOtp();
            if (requirement.NeedUsernamePassword && (user.Length == 0 || pass.Length == 0))
                e.Cancel = true;
            else if (requirement.NeedChallenge && otp.Length == 0)
                e.Cancel = true;
        };

        var result = await dialog.ShowAsync();
        if (result != ContentDialogResult.Primary)
            return null;

        var user = userBox?.Text?.Trim() ?? "";
        var pass = passBox?.Password ?? "";
        var otp = ReadOtp();

        if (requirement.NeedUsernamePassword && (user.Length == 0 || pass.Length == 0))
            return null;

        if (requirement.NeedChallenge && otp.Length == 0)
            return null;

        return new OpenVpnAuthCredentials
        {
            Username = requirement.NeedUsernamePassword
                ? user
                : (requirement.PrefillUsername ?? user),
            Password = pass,
            Response = otp,
            DynamicChallengeCookie = requirement.DynamicChallengeCookie,
        };
    }
}
