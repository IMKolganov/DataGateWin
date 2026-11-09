using System.Text;

namespace DataGateWin.Services.Profiles;

/// <summary>
/// OpenVPN dynamic challenge (CRV1) from a DYNAMIC_CHALLENGE event.
/// Format: <c>CRV1:&lt;flags&gt;:&lt;state_id&gt;:&lt;username_b64&gt;:&lt;challenge_text&gt;</c>
/// </summary>
public sealed class OpenVpnDynamicChallenge
{
    public string Cookie { get; init; } = "";
    public string StateId { get; init; } = "";
    public string Username { get; init; } = "";
    public string ChallengeText { get; init; } = "";
    public bool Echo { get; init; }
    public bool ResponseRequired { get; init; } = true;

    public OpenVpnAuthRequirement ToRequirement() => new()
    {
        NeedUsernamePassword = string.IsNullOrEmpty(Username),
        NeedChallenge = true,
        ChallengePrompt = ChallengeText,
        ChallengeEcho = Echo,
        PrefillUsername = string.IsNullOrEmpty(Username) ? null : Username,
        DynamicChallengeCookie = Cookie,
    };
}

public static class OpenVpnDynamicChallengeParser
{
    public static bool TryParse(string? raw, out OpenVpnDynamicChallenge? challenge)
    {
        challenge = null;
        if (string.IsNullOrWhiteSpace(raw))
            return false;

        var s = raw.Trim();
        const string prefix = "DYNAMIC_CHALLENGE";
        if (s.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            s = s[prefix.Length..].Trim();

        var idx = s.IndexOf("CRV1:", StringComparison.OrdinalIgnoreCase);
        if (idx < 0)
            return false;

        var cookie = s[idx..].Trim();
        if (!cookie.StartsWith("CRV1:", StringComparison.OrdinalIgnoreCase))
            return false;

        var rest = cookie[5..];
        var p1 = rest.IndexOf(':');
        if (p1 < 0)
            return false;
        var p2 = rest.IndexOf(':', p1 + 1);
        if (p2 < 0)
            return false;
        var p3 = rest.IndexOf(':', p2 + 1);
        if (p3 < 0)
            return false;

        var flags = rest[..p1];
        var state = rest[(p1 + 1)..p2];
        var userB64 = rest[(p2 + 1)..p3];
        var text = rest[(p3 + 1)..];

        var echo = flags.Contains('E', StringComparison.OrdinalIgnoreCase);
        var responseRequired = flags.Length == 0 || flags.Contains('R', StringComparison.OrdinalIgnoreCase);

        var username = "";
        if (userB64.Length > 0)
        {
            try
            {
                username = Encoding.UTF8.GetString(Convert.FromBase64String(userB64));
            }
            catch (FormatException)
            {
                username = "";
            }
        }

        challenge = new OpenVpnDynamicChallenge
        {
            Cookie = cookie,
            StateId = state,
            Username = username,
            ChallengeText = text,
            Echo = echo,
            ResponseRequired = responseRequired,
        };
        return true;
    }
}
