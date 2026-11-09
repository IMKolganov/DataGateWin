using DataGateWin.Services.Installation;
using Newtonsoft.Json.Linq;

namespace DataGateWin.Services.Profiles;

public static class ImportedOpenVpnPayloadBuilder
{
    public static JObject Build(
        ImportedVpnProfile profile,
        InstallationIdService installationIdService,
        OpenVpnAuthCredentials? credentials = null)
    {
        ArgumentNullException.ThrowIfNull(profile);
        if (profile.Protocol != ImportedVpnProtocol.OpenVpn)
            throw new InvalidOperationException("Only OpenVPN imported profiles can start a session.");

        if (!ImportedOpenVpnValidator.TryValidate(profile.ConfigText, out var err))
            throw new InvalidOperationException("Invalid OpenVPN profile: " + err);

        var payload = new JObject
        {
            ["installationId"] = installationIdService.GetOrCreate(),
            ["cn"] = "imported-" + profile.Id.ToString("N")[..12],
            ["ovpnFileName"] = string.IsNullOrWhiteSpace(profile.SourceFileName)
                ? profile.Name + ".ovpn"
                : profile.SourceFileName,
            ["ovpnContent"] = profile.ConfigText,
            ["useWssBridge"] = false,
        };

        if (OpenVpnAuthDetector.TryGetInlineCredentials(profile.ConfigText, out var inlineUser, out var inlinePass)
            && (credentials is null
                || (string.IsNullOrEmpty(credentials.DynamicChallengeCookie)
                    && string.IsNullOrEmpty(credentials.Password)
                    && (string.IsNullOrEmpty(credentials.Username) || credentials.Username == inlineUser))))
        {
            credentials = new OpenVpnAuthCredentials
            {
                Username = inlineUser,
                Password = inlinePass,
                Response = credentials?.Response ?? "",
            };
        }

        if (credentials is not null)
        {
            payload["openVpnUsername"] = credentials.Username ?? "";
            payload["openVpnPassword"] = credentials.Password ?? "";
            payload["openVpnResponse"] = credentials.Response ?? "";
            if (!string.IsNullOrWhiteSpace(credentials.DynamicChallengeCookie))
                payload["openVpnChallengeCookie"] = credentials.DynamicChallengeCookie;
        }

        return payload;
    }
}
