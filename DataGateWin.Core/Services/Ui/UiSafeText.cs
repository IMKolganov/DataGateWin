namespace DataGateWin.Services.Ui;

/// <summary>
/// WinUI CoreMessaging FailFasts on enormous TextBlock payloads (engine dumps, JSON).
/// </summary>
public static class UiSafeText
{
    public const int StatusMaxChars = 2000;
    public const int ErrorMaxChars = 1500;

    public static string Truncate(string? text, int maxChars)
    {
        if (maxChars <= 0)
            return "";
        if (string.IsNullOrEmpty(text))
            return "";
        if (text.Length <= maxChars)
            return text;
        if (maxChars == 1)
            return "…";
        return string.Concat(text.AsSpan(0, maxChars - 1), "…");
    }

    public static string ForStatus(string? text) => Truncate(text, StatusMaxChars);

    public static string ForError(string? text) => Truncate(text, ErrorMaxChars);
}
