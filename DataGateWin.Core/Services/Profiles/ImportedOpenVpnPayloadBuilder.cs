using DataGateWin.Services.Installation;
using Newtonsoft.Json.Linq;

namespace DataGateWin.Services.Profiles;

public static class ImportedOpenVpnPayloadBuilder
{
    public static JObject Build(ImportedVpnProfile profile, InstallationIdService installationIdService)
    {
        ArgumentNullException.ThrowIfNull(profile);
        if (profile.Protocol != ImportedVpnProtocol.OpenVpn)
            throw new InvalidOperationException("Only OpenVPN imported profiles can start a session.");

        if (!ImportedOpenVpnValidator.TryValidate(profile.ConfigText, out var err))
            throw new InvalidOperationException("Invalid OpenVPN profile: " + err);

        return new JObject
        {
            ["installationId"] = installationIdService.GetOrCreate(),
            ["cn"] = "imported-" + profile.Id.ToString("N")[..12],
            ["ovpnFileName"] = string.IsNullOrWhiteSpace(profile.SourceFileName)
                ? profile.Name + ".ovpn"
                : profile.SourceFileName,
            ["ovpnContent"] = profile.ConfigText,
            ["useWssBridge"] = false,
        };
    }
}
