namespace DataGateWin.Services.VpnServers;

public static class MapViewportMath
{
    public static bool HasCoordinates(double? latitude, double? longitude)
        => latitude is double lat && double.IsFinite(lat) && lat >= -90 && lat <= 90
        && longitude is double lon && double.IsFinite(lon) && lon >= -180 && lon <= 180;

    public static (double X, double Y) Project(double latitude, double longitude)
        => ((longitude + 180) * 2, (90 - latitude) * 2);

    public static double MarkerScale(double width, double zoom)
        => 1 / (width / 720 * zoom);

    public static double ZoomOffset(double offset, double anchor, double previousZoom, double nextZoom)
        => Math.Max(0, (offset + anchor) * nextZoom / previousZoom - anchor);
}
