namespace DataGateWin.Services.Profiles;

public sealed class OpenVpnAuthRequirement
{
    public bool NeedUsernamePassword { get; init; }
    public bool NeedChallenge { get; init; }
    public string ChallengePrompt { get; init; } = "";
    public bool ChallengeEcho { get; init; }
    public string? PrefillUsername { get; init; }
    public string? DynamicChallengeCookie { get; init; }

    /// <summary>Password previously saved (encrypted) for this profile, if any.</summary>
    public string? PrefillPassword { get; init; }

    /// <summary>True when a username and a saved password make the user/pass prompt unnecessary.</summary>
    public bool HasSavedPassword => !string.IsNullOrEmpty(PrefillPassword);

    public bool NeedsPrompt => (NeedUsernamePassword && !HasSavedPassword) || NeedChallenge;
}

public sealed class OpenVpnAuthCredentials
{
    public string Username { get; init; } = "";
    public string Password { get; init; } = "";
    public string Response { get; init; } = "";
    public string? DynamicChallengeCookie { get; init; }

    /// <summary>
    /// <c>true</c> = user asked to store the password (encrypted); <c>false</c> = clear any stored password;
    /// <c>null</c> = not applicable (leave the stored value alone).
    /// </summary>
    public bool? RememberPassword { get; init; }
}
