using DataGateWin.Services.VpnServers;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Windows.Foundation;

namespace DataGateWin.Pages.Home;

public sealed partial class HomePage
{
    private uint? _mapDragPointer;
    private Point _mapDragStart;
    private double _mapDragHorizontal;
    private double _mapDragVertical;

    private void ServerMapViewport_OnSizeChanged(object sender, SizeChangedEventArgs e)
    {
        if (ServerMapContent is null || e.NewSize.Width <= 0) return;
        // Keep the whole world visible at 1x; zoom then expands the scrollable area.
        ServerMapContent.Width = Math.Min(e.NewSize.Width, e.NewSize.Height * 720 / 330);
        ServerMapContent.Height = ServerMapContent.Width * 330 / 720;
        UpdateMapMarkerScale();
    }

    private void ServerMapViewport_OnViewChanged(object sender, Microsoft.UI.Xaml.Controls.ScrollViewerViewChangedEventArgs e)
        => UpdateMapMarkerScale();

    private void UpdateMapMarkerScale()
    {
        if (ServerMapContent is null || ServerMapMarkers is null || ServerMapViewport is null) return;
        var width = ServerMapContent.Width;
        if (!double.IsFinite(width) || width <= 0) return;
        // Cancel both Viewbox scaling and ScrollViewer zoom around each marker's centre.
        var inverse = MapViewportMath.MarkerScale(width, ServerMapViewport.ZoomFactor);
        foreach (var child in ServerMapMarkers.Children)
            if (child is FrameworkElement marker && marker.RenderTransform is ScaleTransform scale)
                scale.ScaleX = scale.ScaleY = inverse;
    }

    private void ZoomServerMap(double multiplier, Point? anchor = null)
    {
        var viewer = ServerMapViewport;
        var previous = viewer.ZoomFactor;
        var next = (float)Math.Clamp(previous * multiplier, viewer.MinZoomFactor, viewer.MaxZoomFactor);
        var point = anchor ?? new Point(viewer.ViewportWidth / 2, viewer.ViewportHeight / 2);
        viewer.ChangeView(
            MapViewportMath.ZoomOffset(viewer.HorizontalOffset, point.X, previous, next),
            MapViewportMath.ZoomOffset(viewer.VerticalOffset, point.Y, previous, next), next, true);
    }

    private void ServerMapViewport_OnPointerWheelChanged(object sender, PointerRoutedEventArgs e)
    {
        var point = e.GetCurrentPoint(ServerMapViewport);
        ZoomServerMap(Math.Pow(1.2, point.Properties.MouseWheelDelta / 120.0), point.Position);
        e.Handled = true;
    }

    private void ServerMapZoomIn_OnClick(object sender, RoutedEventArgs e) => ZoomServerMap(1.25);
    private void ServerMapZoomOut_OnClick(object sender, RoutedEventArgs e) => ZoomServerMap(1 / 1.25);
    private void ServerMapReset_OnClick(object sender, RoutedEventArgs e)
        => ServerMapViewport.ChangeView(0, 0, 1f, true);

    private void ServerMapViewport_OnPointerPressed(object sender, PointerRoutedEventArgs e)
    {
        if (e.Pointer.PointerDeviceType != Microsoft.UI.Input.PointerDeviceType.Mouse ||
            !e.GetCurrentPoint(ServerMapViewport).Properties.IsLeftButtonPressed) return;
        // Leave server markers and scrollbars to their normal click handlers.
        for (var source = e.OriginalSource as DependencyObject; source is not null && source != ServerMapViewport;
             source = VisualTreeHelper.GetParent(source))
            if (source is ButtonBase || source is ScrollBar) return;
        if (!ServerMapViewport.CapturePointer(e.Pointer)) return;
        _mapDragPointer = e.Pointer.PointerId;
        _mapDragStart = e.GetCurrentPoint(ServerMapViewport).Position;
        _mapDragHorizontal = ServerMapViewport.HorizontalOffset;
        _mapDragVertical = ServerMapViewport.VerticalOffset;
        e.Handled = true;
    }

    private void ServerMapViewport_OnPointerMoved(object sender, PointerRoutedEventArgs e)
    {
        if (_mapDragPointer != e.Pointer.PointerId) return;
        var point = e.GetCurrentPoint(ServerMapViewport).Position;
        ServerMapViewport.ChangeView(_mapDragHorizontal + _mapDragStart.X - point.X,
            _mapDragVertical + _mapDragStart.Y - point.Y, null, true);
        e.Handled = true;
    }

    private void ServerMapViewport_OnPointerReleased(object sender, PointerRoutedEventArgs e)
    {
        if (_mapDragPointer != e.Pointer.PointerId) return;
        _mapDragPointer = null;
        ServerMapViewport.ReleasePointerCapture(e.Pointer);
    }
}
