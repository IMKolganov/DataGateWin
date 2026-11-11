using DataGateWin.Services.VpnServers;
using Xunit;
namespace DataGateWin.Tests;
public sealed class MapViewportMathTests
{
    [Theory]
    [InlineData(720, 1)] [InlineData(1040, 8)] [InlineData(400, 4)]
    public void Marker_Remains14Dip_AtEveryZoom(double width, double zoom)
        => Assert.Equal(14, 14 * MapViewportMath.MarkerScale(width, zoom) * width / 720 * zoom, 10);

    [Fact]
    public void Zoom_PreservesTheMapCoordinateUnderPointer()
    {
        var offset = MapViewportMath.ZoomOffset(120, 200, 2, 4);
        Assert.Equal((120 + 200) / 2.0, (offset + 200) / 4.0, 10);
        Assert.Equal(0, MapViewportMath.ZoomOffset(0, 200, 4, 1));
    }

    [Fact]
    public void Frankfurt_ProjectsToGermany_NotCountryFallback()
    {
        var point = MapViewportMath.Project(50.1109, 8.6821);
        Assert.Equal(377.3642, point.X, 4);
        Assert.Equal(79.7782, point.Y, 4);
    }

    [Theory]
    [InlineData(null, 30.0)] [InlineData(30.0, null)] [InlineData(91.0, 30.0)] [InlineData(30.0, -181.0)]
    [InlineData(double.NaN, 30.0)] [InlineData(30.0, double.PositiveInfinity)]
    public void InvalidCoordinates_RequireFallback(double? lat, double? lon)
        => Assert.False(MapViewportMath.HasCoordinates(lat, lon));

    [Theory]
    [InlineData(0, 0)] [InlineData(-90, -180)] [InlineData(90, 180)]
    public void ValidBoundaryCoordinates_AreNotDiscarded(double lat, double lon)
        => Assert.True(MapViewportMath.HasCoordinates(lat, lon));
}
