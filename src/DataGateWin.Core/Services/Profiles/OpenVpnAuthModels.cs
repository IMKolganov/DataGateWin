namespace DataGateWin.Services.Profiles;

public sealed class OpenVpnAuthRequirement
{
    public bool NeedUsernamePassword { get; init; }
    public bool NeedChallenge { get; init; }
    public string ChallengePrompt { get; init; } = "";
    public bool ChallengeEcho { get; init; }
    public string? PrefillUsername { get; init; }
    public string? DynamicChallengeCookie { get; init; }

    public bool NeedsPrompt => NeedUsernamePassword || NeedChallenge;
}

public sealed class OpenVpnAuthCredentials
{
    public string Username { get; init; } = "";
    public string Password { get; init; } = "";
    public string Response { get; init; } = "";
    public string? DynamicChallengeCookie { get; init; }
}
