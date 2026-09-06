using System.Globalization;
using System.Text;

namespace DataGateWin.Services.VpnServers;

/// <summary>
/// Splits a leading country flag from a VPN server display name.
/// Supports API styles:
/// - emoji: "🇫🇮 Helsinki 3"
/// - ISO code: "FI Helsinki 3 tcp", "NO Norway 2 udp"
/// </summary>
public static class ServerNameFlag
{
    private const int RegionalIndicatorBase = 0x1F1E6;

    public static bool TrySplit(string? serverName, out string flagEmoji, out string remainder)
    {
        flagEmoji = "";
        remainder = serverName?.Trim() ?? "";
        if (remainder.Length == 0)
            return false;

        if (TrySplitLeadingEmoji(remainder, out flagEmoji, out remainder))
            return true;

        return TrySplitLeadingIsoCode(remainder, out flagEmoji, out remainder);
    }

    /// <summary>Flag + remainder for plain string UIs; unchanged when no flag.</summary>
    public static string WithFlagPrefix(string? serverName)
    {
        if (!TrySplit(serverName, out var flag, out var rest))
            return serverName?.Trim() ?? "";
        return string.IsNullOrEmpty(rest) ? flag : $"{flag} {rest}";
    }

    public static bool IsFlagGrapheme(string textElement)
        => IsFlagEmoji(textElement);

    private static bool TrySplitLeadingEmoji(string trimmed, out string flagEmoji, out string remainder)
    {
        flagEmoji = "";
        remainder = trimmed;

        var enumerator = StringInfo.GetTextElementEnumerator(trimmed);
        if (!enumerator.MoveNext())
            return false;

        var element = enumerator.GetTextElement();
        if (!IsFlagEmoji(element))
            return false;

        flagEmoji = element;
        remainder = trimmed[element.Length..].TrimStart();
        return true;
    }

    private static bool TrySplitLeadingIsoCode(string trimmed, out string flagEmoji, out string remainder)
    {
        flagEmoji = "";
        remainder = trimmed;

        if (trimmed.Length < 4)
            return false;

        var c0 = trimmed[0];
        var c1 = trimmed[1];
        if (!IsAsciiUpperLetter(c0) || !IsAsciiUpperLetter(c1))
            return false;
        if (!char.IsWhiteSpace(trimmed[2]))
            return false;

        flagEmoji = ToFlagEmoji(c0, c1);
        remainder = trimmed[2..].TrimStart();
        return remainder.Length > 0;
    }

    private static string ToFlagEmoji(char a, char b)
        => char.ConvertFromUtf32(RegionalIndicatorBase + (a - 'A'))
           + char.ConvertFromUtf32(RegionalIndicatorBase + (b - 'A'));

    private static bool IsAsciiUpperLetter(char c)
        => c is >= 'A' and <= 'Z';

    private static bool IsFlagEmoji(string textElement)
    {
        var runes = textElement.EnumerateRunes().ToArray();
        return runes.Length == 2
               && IsRegionalIndicator(runes[0])
               && IsRegionalIndicator(runes[1]);
    }

    private static bool IsRegionalIndicator(Rune rune)
        => rune.Value is >= RegionalIndicatorBase and <= RegionalIndicatorBase + 25;
}
