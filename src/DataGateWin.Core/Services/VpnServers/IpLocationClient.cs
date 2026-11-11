using System.Text.Json;

namespace DataGateWin.Services.VpnServers;

public sealed record IpLocation(double Latitude, double Longitude);

/// <summary>Optional, approximate location of the public IP; never uses the authenticated API client.</summary>
public sealed class IpLocationClient(HttpClient http)
{
    public async Task<IpLocation?> TryGetAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(4));
            using var response = await http.GetAsync(
                "https://ipwho.is/?fields=success,latitude,longitude", timeout.Token).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode) return null;
            var json = await response.Content.ReadAsStringAsync(timeout.Token).ConfigureAwait(false);
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object ||
                !root.TryGetProperty("success", out var success) || success.ValueKind != JsonValueKind.True ||
                !root.TryGetProperty("latitude", out var latitude) || latitude.ValueKind != JsonValueKind.Number ||
                !root.TryGetProperty("longitude", out var longitude) || longitude.ValueKind != JsonValueKind.Number ||
                !latitude.TryGetDouble(out var lat) || !longitude.TryGetDouble(out var lon) ||
                !double.IsFinite(lat) || !double.IsFinite(lon) || lat < -90 || lat > 90 || lon < -180 || lon > 180)
                return null;
            return new IpLocation(lat, lon);
        }
        catch (Exception)
        {
            // Geolocation must never prevent Home from opening or VPN from connecting.
            return null;
        }
    }
}
