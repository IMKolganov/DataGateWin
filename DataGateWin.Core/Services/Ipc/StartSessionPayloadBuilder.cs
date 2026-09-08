using System.Text;
using DataGateMonitor.SharedModels.Enums;
using DataGateWin.Configuration;
using DataGateWin.Services.Auth;
using DataGateWin.Services.Identity;
using DataGateWin.Services.Installation;
using DataGateWin.Services.IpList;
using DataGateWin.Services.OpenVpnFiles;
using DataGateWin.Services.VpnServers;
using DataGateWin.Services.Xray;
using Newtonsoft.Json.Linq;

namespace DataGateWin.Services.Ipc;

public sealed class StartSessionPayloadBuilder(
    WssServerSelector wssServerSelector,
    InstallationIdService installationIdService,
    OpenVpnFilesApiClient filesApi,
    XrayClientLinksApiClient xrayFilesApi,
    AuthSession session,
    IpListRoutesRepository ipListRoutes)
{
    public VpnConnectionSessionInfo? LastSelection { get; private set; }

    public void ClearLastSelection() => LastSelection = null;

    public Task<JObject?> BuildAsync(CancellationToken ct) =>
        BuildAsync(autoPickServer: true, manualVpnServerId: null, ct);

    public async Task<JObject?> BuildAsync(bool autoPickServer, int? manualVpnServerId, CancellationToken ct)
    {
        var row = await wssServerSelector
            .GetServerRowAsync(autoPickServer, manualVpnServerId, ct)
            .ConfigureAwait(false);
        if (row?.VpnServerResponses?.VpnServer == null)
        {
            LastSelection = null;
            return null;
        }

        var server = row.VpnServerResponses.VpnServer;
        LastSelection = VpnConnectionSessionInfoFactory.FromStatusRow(row);

        var installationId = installationIdService.GetOrCreate();

        var token = await session.GetValidAccessTokenAsync(ct).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(token))
            throw new InvalidOperationException("Access token not available");

        var externalId =
            JwtClaimReader.GetClaimFromBearerToken(token, "externalId")
            ?? JwtClaimReader.GetClaimFromBearerToken(token, "sub")
            ?? JwtClaimReader.GetClaimFromBearerToken(token, "nameid");

        if (string.IsNullOrWhiteSpace(externalId))
            throw new InvalidOperationException("ExternalId not available");

        var cn = $"wdg-{server.Id}-{externalId}-{installationId}";
        var issuedTo = $"datagate windows user {externalId} device {installationId}";

        if (server.ServerType == VpnServerType.Xray)
            return await BuildXrayPayloadAsync(server.Id, cn, externalId, issuedTo, installationId, ct)
                .ConfigureAwait(false);

        return await BuildOpenVpnPayloadAsync(server, cn, externalId, issuedTo, installationId, ct)
            .ConfigureAwait(false);
    }

    private async Task<JObject> BuildXrayPayloadAsync(
        int vpnServerId,
        string cn,
        string externalId,
        string issuedTo,
        string installationId,
        CancellationToken ct)
    {
        var downloaded = await xrayFilesApi.EnsureAndDownloadDeviceFileAsync(
            vpnServerId: vpnServerId,
            commonName: cn,
            externalId: externalId,
            issuedTo: issuedTo,
            ct: ct).ConfigureAwait(false);

        if (downloaded.Content == null || downloaded.Content.Length == 0)
            throw new InvalidOperationException("Downloaded Xray content is empty");

        var raw = Encoding.UTF8.GetString(downloaded.Content);
        var shareOrOutbounds = XrayWindowsConfigBuilder.PrepareShareOrOutboundsInput(raw);
        if (string.IsNullOrWhiteSpace(shareOrOutbounds))
            throw new InvalidOperationException("Xray profile has no share link / outbounds");

        var dnsServers = XrayWindowsConfigBuilder.ExtractExplicitDnsServers(raw);
        if (LastSelection != null && dnsServers.Count > 0)
        {
            LastSelection = new VpnConnectionSessionInfo
            {
                ServerId = LastSelection.ServerId,
                ServerName = LastSelection.ServerName,
                ExternalIp = LastSelection.ExternalIp,
                VpnIp = LastSelection.VpnIp,
                DnsServers = dnsServers,
            };
        }

        var payload = new JObject
        {
            ["protocol"] = "xray",
            ["installationId"] = installationId,
            ["cn"] = cn,
            ["xrayShareLinks"] = shareOrOutbounds,
        };

        await AppendXrayIpListBypassAsync(payload, ct).ConfigureAwait(false);
        return payload;
    }

    /// <summary>
    /// IP-list CIDRs → Xray <c>directBypassCidrs</c> (same breadth limit as Windows OpenVPN inject).
    /// Safe for catalog + imported StartSession payloads.
    /// </summary>
    public async Task AppendXrayIpListBypassAsync(JObject payload, CancellationToken ct)
    {
        ArgumentNullException.ThrowIfNull(payload);
        var protocol = payload.Value<string>("protocol")?.Trim().ToLowerInvariant();
        if (protocol != "xray")
            return;

        var ipSettings = IpListStore.LoadSettings();
        if (!ipSettings.CidrListsEnabled)
            return;

        var routes = await ipListRoutes.GetRoutesForConnectionAsync(ct).ConfigureAwait(false);
        if (routes.Count == 0)
            return;

        var selected = IpListRouteConfig.SelectAndroid12OvpnRoutes(routes, ipSettings.OvpnRouteLimit);
        if (selected.Count == 0)
            return;

        var arr = payload["directBypassCidrs"] as JArray ?? new JArray();
        var existing = new HashSet<string>(
            arr.Select(t => t.Value<string>()?.Trim() ?? "")
                .Where(s => s.Length > 0),
            StringComparer.OrdinalIgnoreCase);

        foreach (var route in selected)
        {
            var cidr = route.ToCidrString();
            if (existing.Add(cidr))
                arr.Add(cidr);
        }

        payload["directBypassCidrs"] = arr;
    }

    private async Task<JObject> BuildOpenVpnPayloadAsync(
        DataGateMonitor.SharedModels.DataGateMonitor.VpnServers.Dto.VpnServerV2Dto server,
        string cn,
        string externalId,
        string issuedTo,
        string installationId,
        CancellationToken ct)
    {
        var downloaded = await filesApi.EnsureAndDownloadDeviceFileAsync(
            vpnServerId: server.Id,
            commonName: cn,
            externalId: externalId,
            issuedTo: issuedTo,
            ct: ct).ConfigureAwait(false);

        if (downloaded.Content == null || downloaded.Content.Length == 0)
            throw new InvalidOperationException("Downloaded OVPN content is empty");

        var ovpnContent = Encoding.UTF8.GetString(downloaded.Content);

        var ipSettings = IpListStore.LoadSettings();
        if (ipSettings.CidrListsEnabled)
        {
            var routes = await ipListRoutes.GetRoutesForConnectionAsync(ct).ConfigureAwait(false);
            var plan = IpListRouteConfig.PrepareConnectionRoutes(
                ovpnContent,
                routes,
                ipSettings.CoverageMode,
                IpListRouteConfig.SanitizeAndroid12OvpnRouteLimit(ipSettings.OvpnRouteLimit),
                supportsAndroidRouteExclusion: false);
            ovpnContent = plan.Config;
        }

        var apiUri = new Uri(server.ApiUrl);
        var host = apiUri.Host;
        var port = apiUri.IsDefaultPort ? (apiUri.Scheme == "http" ? 80 : 443) : apiUri.Port;
        var useWssBridge = server.IsEnableWss;

        return new JObject
        {
            ["installationId"] = installationId,
            ["cn"] = cn,
            ["ovpnFileName"] = downloaded.IssuedOvpn?.FileName ?? "client.ovpn",
            ["ovpnContent"] = ovpnContent,

            // Catalog OpenVPN without WSS talks to remotes in the .ovpn directly.
            ["useWssBridge"] = useWssBridge,

            ["host"] = host,
            ["port"] = port.ToString(),
            ["path"] = "/api/proxy",
            ["sni"] = host,

            ["listenIp"] = "127.0.0.1",
            ["listenPort"] = EnginePortDefaults.LocalBridgeDefaultListenPort,
            // WSS edge uses product CA; do not enable pinning without coordinated server rollout.
            ["verifyServerCert"] = false
        };
    }
}
