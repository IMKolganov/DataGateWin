using DataGateWin.Services.Traffic;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using Windows.Foundation;
using Windows.UI;

namespace DataGateWin.Services.Ui;

/// <summary>A small native chart: no Skia surface lifecycle or graphics-device dependency.</summary>
public sealed class LiveTrafficChart : Grid
{
    private readonly Canvas _canvas = new();
    private Microsoft.UI.Dispatching.DispatcherQueueTimer? _animation;
    private double[] _fromIn = [], _fromOut = [], _targetIn = [], _targetOut = [];
    private long _animationStarted;
    private double _axisMaximum = 1024, _targetMaximum = 1024;
    private double _scrollProgress;
    private double[] _incoming = new double[60];
    private double[] _outgoing = new double[60];
    internal static Color IncomingColor(bool dark) => dark
        ? Color.FromArgb(255, 61, 192, 92) : Color.FromArgb(255, 24, 117, 49);
    internal static Color OutgoingColor(bool dark) => dark
        ? Color.FromArgb(255, 255, 163, 54) : Color.FromArgb(255, 164, 82, 0);

    public LiveTrafficChart()
    {
        MinHeight = 120;
        Children.Add(_canvas);
        SizeChanged += (_, _) => Draw();
        Loaded += (_, _) => Draw();
        Unloaded += (_, _) => { _animation?.Stop(); CompleteAnimation(); };
        ActualThemeChanged += (_, _) => Draw();
    }

    public void Update(double[] incoming, double[] outgoing)
    {
        _animation?.Stop();
        CompleteAnimation();
        _fromIn = (double[])_incoming.Clone();
        _fromOut = (double[])_outgoing.Clone();
        _targetIn = (double[])incoming.Clone();
        _targetOut = (double[])outgoing.Clone();
        var peak = incoming.Concat(outgoing).Where(double.IsFinite).DefaultIfEmpty(0).Max();
        _targetMaximum = Math.Max(1024, Math.Pow(2, Math.Ceiling(Math.Log2(Math.Max(1, peak * 1.15)))));
        if (!IsLoaded || _fromIn.Length != incoming.Length || _fromOut.Length != outgoing.Length)
        {
            CompleteAnimation();
            Draw();
            return;
        }
        // Keep historical sample heights unchanged; reveal one new sample by scrolling horizontally.
        _incoming = _fromIn.Concat([incoming[^1]]).ToArray();
        _outgoing = _fromOut.Concat([outgoing[^1]]).ToArray();
        _axisMaximum = _targetMaximum;
        _scrollProgress = 0;
        if (_animation is null)
        {
            _animation = DispatcherQueue.CreateTimer();
            _animation.Interval = TimeSpan.FromMilliseconds(33);
            _animation.Tick += (_, _) => Animate();
        }
        _animationStarted = System.Diagnostics.Stopwatch.GetTimestamp();
        _animation.Start();
    }

    private void CompleteAnimation()
    {
        if (_targetIn.Length == 0) return;
        _incoming = (double[])_targetIn.Clone();
        _outgoing = (double[])_targetOut.Clone();
        _axisMaximum = _targetMaximum;
        _scrollProgress = 0;
    }

    private void Animate()
    {
        var t = Math.Clamp(System.Diagnostics.Stopwatch.GetElapsedTime(_animationStarted).TotalMilliseconds / 350, 0, 1);
        _scrollProgress = t * t * (3 - 2 * t);
        if (t >= 1)
        {
            _animation?.Stop();
            CompleteAnimation();
        }
        Draw();
    }

    private void Draw()
    {
        if (ActualWidth < 100 || ActualHeight < 40) return;
        _canvas.Children.Clear();
        _canvas.Clip = new RectangleGeometry { Rect = new Rect(0, 0, ActualWidth, ActualHeight) };
        var width = Math.Max(1, ActualWidth - 90);
        var height = Math.Max(1, ActualHeight - 30);
        const double left = 2, top = 10;
        var maximum = _axisMaximum;
        var dark = ActualTheme == ElementTheme.Dark;
        var grid = new SolidColorBrush(dark ? Color.FromArgb(45, 180, 190, 205) : Color.FromArgb(45, 50, 60, 75));
        var muted = new SolidColorBrush(dark ? Color.FromArgb(255, 160, 171, 185) : Color.FromArgb(255, 90, 100, 115));
        for (var i = 0; i <= 3; i++)
        {
            var y = top + height * i / 3;
            _canvas.Children.Add(new Line
            {
                X1 = left, X2 = left + width, Y1 = y, Y2 = y,
                Stroke = grid, StrokeThickness = 1,
                StrokeDashArray = i is 0 or 3 ? null : new DoubleCollection { 4, 6 },
            });
            var label = new TextBlock
            {
                Text = LiveTrafficFormatting.FormatBytesPerSec(maximum * (3 - i) / 3),
                FontSize = 11, Foreground = muted,
            };
            Canvas.SetLeft(label, left + width + 10);
            Canvas.SetTop(label, y - 8);
            _canvas.Children.Add(label);
        }
        AddSeries(_incoming, IncomingColor(dark));
        AddSeries(_outgoing, OutgoingColor(dark));

        void AddSeries(double[] values, Color color)
        {
            if (values.Length < 2) return;
            var points = new PointCollection();
            var dx = width / Math.Max(1, _targetIn.Length - 1);
            for (var i = 0; i < values.Length; i++)
            {
                var value = double.IsFinite(values[i]) ? Math.Clamp(values[i], 0, maximum) : 0;
                points.Add(new Point(left + dx * (i - _scrollProgress), top + height * (1 - value / maximum)));
            }
            // Monotone cubic interpolation passes through the samples without artificial peaks.
            var slopes = new double[points.Count];
            for (var i = 0; i < points.Count; i++)
            {
                var before = i == 0 ? 0 : (points[i].Y - points[i - 1].Y) / dx;
                var after = i == points.Count - 1 ? 0 : (points[i + 1].Y - points[i].Y) / dx;
                slopes[i] = before * after > 0 ? 2 * before * after / (before + after) : 0;
            }
            PathGeometry Curve(bool filled)
            {
                var figure = new PathFigure { StartPoint = points[0], IsClosed = filled, IsFilled = filled };
                for (var i = 0; i < points.Count - 1; i++)
                {
                    var low = Math.Min(points[i].Y, points[i + 1].Y);
                    var high = Math.Max(points[i].Y, points[i + 1].Y);
                    figure.Segments.Add(new BezierSegment
                    {
                        Point1 = new Point(points[i].X + dx / 3, Math.Clamp(points[i].Y + slopes[i] * dx / 3, low, high)),
                        Point2 = new Point(points[i + 1].X - dx / 3, Math.Clamp(points[i + 1].Y - slopes[i + 1] * dx / 3, low, high)),
                        Point3 = points[i + 1],
                    });
                }
                if (filled)
                {
                    figure.Segments.Add(new LineSegment { Point = new Point(left + width, top + height) });
                    figure.Segments.Add(new LineSegment { Point = new Point(left, top + height) });
                }
                var geometry = new PathGeometry();
                geometry.Figures.Add(figure);
                return geometry;
            }
            var fill = new LinearGradientBrush { StartPoint = new Point(0, 0), EndPoint = new Point(0, 1) };
            fill.GradientStops.Add(new GradientStop { Offset = 0, Color = Color.FromArgb(65, color.R, color.G, color.B) });
            fill.GradientStops.Add(new GradientStop { Offset = 1, Color = Color.FromArgb(0, color.R, color.G, color.B) });
            _canvas.Children.Add(new Microsoft.UI.Xaml.Shapes.Path { Data = Curve(true), Fill = fill, Clip = new RectangleGeometry { Rect = new Rect(left, top, width, height + 2) } });
            _canvas.Children.Add(new Microsoft.UI.Xaml.Shapes.Path
            {
                Data = Curve(false), Clip = new RectangleGeometry { Rect = new Rect(left, top, width, height + 2) }, Stroke = new SolidColorBrush(color), StrokeThickness = 2,
                StrokeLineJoin = PenLineJoin.Round, StrokeStartLineCap = PenLineCap.Round, StrokeEndLineCap = PenLineCap.Round,
            });
        }
    }
}
