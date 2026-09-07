using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace DataGateWin.Services.VpnServers;

/// <summary>
/// Splits / synthesizes a leading country flag from a VPN server display name.
/// Supports API styles seen in production and Android fixtures:
/// - emoji: "🇫🇮 Helsinki 3"
/// - ISO prefix: "FI Helsinki 3 tcp"
/// - place/country words: "Helsinki 3", "Norway", "cyprus", "norway-xray"
/// - ISO-id: "NL-1", "de-1", "ru-1"
/// </summary>
public static class ServerNameFlag
{
    private const int RegionalIndicatorBase = 0x1F1E6;

    private static readonly Regex IsoDashId = new(
        @"^(?<iso>[A-Za-z]{2})[-_](?<rest>.+)$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    /// <summary>Longer keys first so multi-word places match before short tokens.</summary>
    private static readonly (string Key, string Iso)[] PlaceToIso =
    [
        ("united kingdom", "GB"),
        ("united states", "US"),
        ("hong kong", "HK"),
        ("netherlands", "NL"),
        ("new york", "US"),
        ("los angeles", "US"),
        ("finland", "FI"),
        ("helsinki", "FI"),
        ("norway", "NO"),
        ("bergen", "NO"),
        ("oslo", "NO"),
        ("cyprus", "CY"),
        ("nicosia", "CY"),
        ("limassol", "CY"),
        ("germany", "DE"),
        ("frankfurt", "DE"),
        ("munich", "DE"),
        ("berlin", "DE"),
        ("sweden", "SE"),
        ("stockholm", "SE"),
        ("france", "FR"),
        ("paris", "FR"),
        ("poland", "PL"),
        ("warsaw", "PL"),
        ("spain", "ES"),
        ("madrid", "ES"),
        ("barcelona", "ES"),
        ("italy", "IT"),
        ("milan", "IT"),
        ("rome", "IT"),
        ("latvia", "LV"),
        ("riga", "LV"),
        ("lithuania", "LT"),
        ("vilnius", "LT"),
        ("estonia", "EE"),
        ("tallinn", "EE"),
        ("ukraine", "UA"),
        ("kyiv", "UA"),
        ("kiev", "UA"),
        ("russia", "RU"),
        ("moscow", "RU"),
        ("romania", "RO"),
        ("bucharest", "RO"),
        ("bulgaria", "BG"),
        ("sofia", "BG"),
        ("hungary", "HU"),
        ("budapest", "HU"),
        ("austria", "AT"),
        ("vienna", "AT"),
        ("switzerland", "CH"),
        ("zurich", "CH"),
        ("geneva", "CH"),
        ("belgium", "BE"),
        ("brussels", "BE"),
        ("denmark", "DK"),
        ("copenhagen", "DK"),
        ("ireland", "IE"),
        ("dublin", "IE"),
        ("portugal", "PT"),
        ("lisbon", "PT"),
        ("greece", "GR"),
        ("athens", "GR"),
        ("czechia", "CZ"),
        ("prague", "CZ"),
        ("slovakia", "SK"),
        ("slovenia", "SI"),
        ("croatia", "HR"),
        ("serbia", "RS"),
        ("turkey", "TR"),
        ("istanbul", "TR"),
        ("israel", "IL"),
        ("japan", "JP"),
        ("tokyo", "JP"),
        ("korea", "KR"),
        ("seoul", "KR"),
        ("singapore", "SG"),
        ("taiwan", "TW"),
        ("canada", "CA"),
        ("toronto", "CA"),
        ("montreal", "CA"),
        ("australia", "AU"),
        ("sydney", "AU"),
        ("melbourne", "AU"),
        ("brazil", "BR"),
        ("mexico", "MX"),
        ("india", "IN"),
        ("amsterdam", "NL"),
        ("rotterdam", "NL"),
        ("london", "GB"),
        ("manchester", "GB"),
        ("chicago", "US"),
        ("miami", "US"),
        ("dallas", "US"),
        ("seattle", "US"),
        ("britain", "GB"),
        ("england", "GB"),
        ("hongkong", "HK"),
        ("czech", "CZ"),
        ("usa", "US"),
    ];

    public static bool TrySplit(string? serverName, out string flagEmoji, out string remainder)
    {
        flagEmoji = "";
        remainder = serverName?.Trim() ?? "";
        if (remainder.Length == 0)
            return false;

        if (TrySplitLeadingEmoji(remainder, out flagEmoji, out remainder))
            return true;

        if (TrySplitLeadingIsoCode(remainder, out flagEmoji, out remainder))
            return true;

        // Place names before ISO-dash: "norway-xray" must not become ISO "NO" + "xray" only.
        if (TrySplitByPlaceName(remainder, out flagEmoji, out remainder))
            return true;

        return TrySplitIsoDashId(remainder, out flagEmoji, out remainder);
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

    /// <summary>"NL-1", "de-1", "ru_2" → flag + id remainder.</summary>
    private static bool TrySplitIsoDashId(string trimmed, out string flagEmoji, out string remainder)
    {
        flagEmoji = "";
        remainder = trimmed;

        var m = IsoDashId.Match(trimmed);
        if (!m.Success)
            return false;

        var iso = m.Groups["iso"].Value.ToUpperInvariant();
        var rest = m.Groups["rest"].Value.Trim();
        if (rest.Length == 0)
            return false;

        // "s1-7" does not match ([A-Za-z]{2}). Reject unknown letter pairs unless rest is an id.
        if (!char.IsDigit(rest[0]) && !IsKnownIso(iso))
            return false;

        flagEmoji = ToFlagEmoji(iso[0], iso[1]);
        remainder = rest;
        return true;
    }

    private static bool TrySplitByPlaceName(string trimmed, out string flagEmoji, out string remainder)
    {
        flagEmoji = "";
        remainder = trimmed;

        var normalized = trimmed.ToLowerInvariant()
            .Replace('-', ' ')
            .Replace('_', ' ');
        while (normalized.Contains("  ", StringComparison.Ordinal))
            normalized = normalized.Replace("  ", " ", StringComparison.Ordinal);
        normalized = normalized.Trim();

        string? iso = null;
        foreach (var (key, code) in PlaceToIso)
        {
            if (ContainsPlaceToken(normalized, key))
            {
                iso = code;
                break;
            }
        }

        if (iso is null)
            return false;

        flagEmoji = ToFlagEmoji(iso[0], iso[1]);
        // Keep full original label; flag is a visual prefix only.
        remainder = trimmed;
        return true;
    }

    private static bool ContainsPlaceToken(string normalizedHaystack, string key)
    {
        if (normalizedHaystack == key)
            return true;
        if (normalizedHaystack.StartsWith(key + " ", StringComparison.Ordinal))
            return true;
        if (normalizedHaystack.EndsWith(" " + key, StringComparison.Ordinal))
            return true;
        if (normalizedHaystack.Contains(" " + key + " ", StringComparison.Ordinal))
            return true;

        // "norwayxray" after removing spaces from haystack when key is a single token.
        if (!key.Contains(' ', StringComparison.Ordinal))
        {
            var compact = normalizedHaystack.Replace(" ", "", StringComparison.Ordinal);
            if (compact == key || compact.StartsWith(key, StringComparison.Ordinal))
                return true;
        }

        return false;
    }

    private static bool IsKnownIso(string iso) =>
        iso is "US" or "GB" or "EU" or "AE" or "QA" or "KZ" or "MD" or "GE" or "AM" or "AZ"
            or "FI" or "NO" or "SE" or "DE" or "NL" or "FR" or "PL" or "CY" or "RU" or "UA"
            or "IT" or "ES" or "PT" or "IE" or "BE" or "AT" or "CH" or "DK" or "CZ" or "SK"
            or "SI" or "HR" or "RS" or "RO" or "BG" or "HU" or "LV" or "LT" or "EE" or "TR"
            or "IL" or "JP" or "KR" or "SG" or "HK" or "TW" or "CA" or "AU" or "BR" or "MX"
            or "IN" or "GR";

    private static string ToFlagEmoji(char a, char b)
        => char.ConvertFromUtf32(RegionalIndicatorBase + (char.ToUpperInvariant(a) - 'A'))
           + char.ConvertFromUtf32(RegionalIndicatorBase + (char.ToUpperInvariant(b) - 'A'));

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
