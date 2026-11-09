using System.Text.RegularExpressions;

namespace DataGateWin.Services.Profiles;

/// <summary>
/// Detects OpenVPN <c>auth-user-pass</c> and <c>static-challenge</c> from the profile text.
/// Dynamic 2FA is CRV1 / DYNAMIC_CHALLENGE at runtime, not invented in the file.
/// </summary>
public static class OpenVpnAuthDetector
{
    private static readonly Regex AuthUserPassLine = new(
        @"^\s*auth-user-pass(?:\s+.+)?\s*$",
        RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.Compiled);

    private static readonly Regex InlineAuth = new(
        @"<auth-user-pass>\s*(.*?)</auth-user-pass>",
        RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);

    private static readonly Regex StaticChallengeQuoted = new(
        @"^\s*static-challenge\s+""([^""]*)""\s+(\d+)\s*$",
        RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.Compiled);

    private static readonly Regex StaticChallengeBare = new(
        @"^\s*static-challenge\s+(\S+)\s+(\d+)\s*$",
        RegexOptions.IgnoreCase | RegexOptions.Multiline | RegexOptions.Compiled);

    public static OpenVpnAuthRequirement Analyze(string? configText)
    {
        var text = (configText ?? "").Replace("\r\n", "\n");
        TryParseInlineAuth(text, out var inlineUser, out var inlinePass);
        var hasAuthDirective = HasActiveAuthUserPass(text);
        ParseStaticChallenge(text, out var challengePrompt, out var challengeEcho);

        var needUserPass = hasAuthDirective && (string.IsNullOrEmpty(inlineUser) || string.IsNullOrEmpty(inlinePass));
        var needChallenge = challengePrompt is not null;

        return new OpenVpnAuthRequirement
        {
            NeedUsernamePassword = needUserPass,
            NeedChallenge = needChallenge,
            ChallengePrompt = challengePrompt ?? "",
            ChallengeEcho = challengeEcho,
            PrefillUsername = string.IsNullOrEmpty(inlineUser) ? null : inlineUser,
        };
    }

    /// <summary>
    /// Same as <see cref="Analyze"/>, plus last typed username when the file has no inline user.
    /// </summary>
    public static OpenVpnAuthRequirement ForConnect(string? configText, string? lastUsername)
    {
        var parsed = Analyze(configText);
        if (!parsed.NeedUsernamePassword
            || !string.IsNullOrWhiteSpace(parsed.PrefillUsername)
            || string.IsNullOrWhiteSpace(lastUsername))
        {
            return parsed;
        }

        return new OpenVpnAuthRequirement
        {
            NeedUsernamePassword = parsed.NeedUsernamePassword,
            NeedChallenge = parsed.NeedChallenge,
            ChallengePrompt = parsed.ChallengePrompt,
            ChallengeEcho = parsed.ChallengeEcho,
            PrefillUsername = lastUsername.Trim(),
        };
    }

    /// <summary>
    /// Credentials embedded in <c>&lt;auth-user-pass&gt;</c>. Used when eval_config does not set autologin.
    /// </summary>
    public static bool TryGetInlineCredentials(string? configText, out string username, out string password)
    {
        var text = (configText ?? "").Replace("\r\n", "\n");
        TryParseInlineAuth(text, out username, out password);
        return username.Length > 0 && password.Length > 0;
    }

    private static bool HasActiveAuthUserPass(string text)
    {
        foreach (Match m in AuthUserPassLine.Matches(text))
        {
            if (IsCommented(text, m.Index))
                continue;
            return true;
        }

        return false;
    }

    private static void TryParseInlineAuth(string text, out string user, out string pass)
    {
        user = "";
        pass = "";
        var m = InlineAuth.Match(text);
        if (!m.Success)
            return;

        var lines = m.Groups[1].Value
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (lines.Length >= 1)
            user = lines[0];
        if (lines.Length >= 2)
            pass = lines[1];
    }

    private static void ParseStaticChallenge(string text, out string? prompt, out bool echo)
    {
        prompt = null;
        echo = true;

        foreach (Match m in StaticChallengeQuoted.Matches(text))
        {
            if (IsCommented(text, m.Index))
                continue;
            prompt = m.Groups[1].Value;
            echo = m.Groups[2].Value != "0";
            return;
        }

        foreach (Match m in StaticChallengeBare.Matches(text))
        {
            if (IsCommented(text, m.Index))
                continue;
            prompt = m.Groups[1].Value.Replace('_', ' ');
            echo = m.Groups[2].Value != "0";
            return;
        }
    }

    private static bool IsCommented(string text, int index)
    {
        var lineStart = text.LastIndexOf('\n', Math.Max(0, index - 1)) + 1;
        for (var i = lineStart; i < index && i < text.Length; i++)
        {
            var c = text[i];
            if (c is '#' or ';')
                return true;
            if (!char.IsWhiteSpace(c))
                break;
        }

        return false;
    }
}
