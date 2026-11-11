// Substitute only language notifications; compile and exercise the production view model.
namespace DataGateWin.Localization;
internal static class WinUiLanguageService
{
    public static event EventHandler? LanguageChanged;
    public static void NotifyLanguageChanged() => LanguageChanged?.Invoke(null, EventArgs.Empty);
}
