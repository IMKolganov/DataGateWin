using DataGateWin.Services.Installation;
using DataGateWin.Services.Xray;
using Newtonsoft.Json.Linq;

namespace DataGateWin.Services.Profiles;

public static class ImportedXrayPayloadBuilder
{
    public static JObject Build(ImportedVpnProfile profile, InstallationIdService installationIdService)
    {
        ArgumentNullException.ThrowIfNull(profile);
        if (profile.Protocol != ImportedVpnProtocol.Xray)
            throw new InvalidOperationException("Only Xray imported profiles can use this builder.");

        if (!ImportedXrayValidator.TryValidate(profile.ConfigText, out var err))
            throw new InvalidOperationException("Invalid Xray profile: " + err);

        var shareOrOutbounds = XrayWindowsConfigBuilder.PrepareShareOrOutboundsInput(profile.ConfigText);
        var dnsServers = XrayWindowsConfigBuilder.ExtractExplicitDnsServers(profile.ConfigText);

        var payload = new JObject
        {
            ["protocol"] = "xray",
            ["installationId"] = installationIdService.GetOrCreate(),
            ["cn"] = "imported-" + profile.Id.ToString("N")[..12],
            ["xrayShareLinks"] = shareOrOutbounds,
        };

        if (dnsServers.Count > 0)
            payload["dnsServers"] = new JArray(dnsServers);

        return payload;
    }
}
