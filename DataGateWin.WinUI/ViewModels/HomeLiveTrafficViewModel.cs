using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.CompilerServices;
using DataGateWin.Localization;
using DataGateWin.Services.Traffic;
using LiveChartsCore;
using LiveChartsCore.Defaults;
using LiveChartsCore.Kernel.Sketches;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Painting;
using SkiaSharp;

namespace DataGateWin.ViewModels;

public sealed class HomeLiveTrafficViewModel : INotifyPropertyChanged
{
    public const int WindowSize = 60;

    private static readonly SKColor InColor = new(0x3D, 0xC0, 0x5C);
    private static readonly SKColor OutColor = new(0xE0, 0x54, 0x54);

    public event PropertyChangedEventHandler? PropertyChanged;

    private readonly ObservableCollection<ObservableValue> _inValues = new();
    private readonly ObservableCollection<ObservableValue> _outValues = new();
    private readonly LineSeries<ObservableValue> _inSeries;
    private readonly LineSeries<ObservableValue> _outSeries;

    private bool _darkTheme = true;
    private string _inRateText = "";
    private string _outRateText = "";
    private string _errorText = "";
    private string? _errorLocKey;

    public HomeLiveTrafficViewModel()
    {
        for (var i = 0; i < WindowSize; i++)
        {
            _inValues.Add(new ObservableValue(0));
            _outValues.Add(new ObservableValue(0));
        }

        _inSeries = new LineSeries<ObservableValue>
        {
            Values = _inValues,
            GeometrySize = 0,
            LineSmoothness = 0,
            Fill = new SolidColorPaint(InColor.WithAlpha(70)),
            Stroke = new SolidColorPaint(InColor) { StrokeThickness = 2 },
            YToolTipLabelFormatter = p =>
            {
                try { return LiveTrafficFormatting.FormatBytesPerSec(p.Coordinate.PrimaryValue); }
                catch { return ""; }
            },
        };
        _outSeries = new LineSeries<ObservableValue>
        {
            Values = _outValues,
            GeometrySize = 0,
            LineSmoothness = 0,
            Fill = new SolidColorPaint(OutColor.WithAlpha(50)),
            Stroke = new SolidColorPaint(OutColor) { StrokeThickness = 2 },
            YToolTipLabelFormatter = p =>
            {
                try { return LiveTrafficFormatting.FormatBytesPerSec(p.Coordinate.PrimaryValue); }
                catch { return ""; }
            },
        };

        Series = [_inSeries, _outSeries];
        ApplyChrome();
    }

    public ISeries[] Series { get; }

    public ICartesianAxis[] XAxes { get; private set; } = [];

    public ICartesianAxis[] YAxes { get; private set; } = [];

    public string InRateText
    {
        get => _inRateText;
        private set
        {
            if (_inRateText == value)
                return;
            _inRateText = value;
            OnPropertyChanged();
        }
    }

    public string OutRateText
    {
        get => _outRateText;
        private set
        {
            if (_outRateText == value)
                return;
            _outRateText = value;
            OnPropertyChanged();
        }
    }

    public string ErrorText
    {
        get => _errorText;
        private set
        {
            if (_errorText == value)
                return;
            _errorText = value;
            OnPropertyChanged();
        }
    }

    public void SetChartTheme(bool dark)
    {
        _darkTheme = dark;
        ApplyAxes();
    }

    public void ApplyChrome()
    {
        try
        {
            _inSeries.Name = Loc.T("Home_Traffic_In");
            _outSeries.Name = Loc.T("Home_Traffic_Out");
            if (_errorLocKey is null)
                ApplyRateLabels(0, 0);
            else
                ErrorText = Loc.T(_errorLocKey);
            ApplyAxes();
        }
        catch
        {
            SetErrorFromKey(LiveTrafficError.KeyGeneric);
        }
    }

    public void SetErrorFromKey(string locKey)
    {
        _errorLocKey = string.IsNullOrWhiteSpace(locKey) ? LiveTrafficError.KeyGeneric : locKey;
        ErrorText = Loc.T(_errorLocKey);
        InRateText = "";
        OutRateText = "";
    }

    public void ClearError()
    {
        _errorLocKey = null;
        if (ErrorText.Length == 0)
            return;
        ErrorText = "";
    }

    /// <summary>Zero the series and rate labels (call when hiding the chart on disconnect).</summary>
    public void ResetSeries()
    {
        try
        {
            ClearError();
            for (var i = 0; i < _inValues.Count; i++)
                _inValues[i].Value = 0;
            for (var i = 0; i < _outValues.Count; i++)
                _outValues[i].Value = 0;
            ApplyRateLabels(0, 0);
        }
        catch
        {
            SetErrorFromKey(LiveTrafficError.KeyGeneric);
        }
    }

    public void Push(LiveTrafficTick tick)
    {
        try
        {
            ClearError();
            Shift(_inValues, tick.InBytesPerSec);
            Shift(_outValues, tick.OutBytesPerSec);
            ApplyRateLabels(tick.InBytesPerSec, tick.OutBytesPerSec);
        }
        catch
        {
            SetErrorFromKey(LiveTrafficError.KeyGeneric);
        }
    }

    private void ApplyRateLabels(double inBps, double outBps)
    {
        try
        {
            var culture = CultureInfo.CurrentCulture;
            InRateText = Loc.T("Home_Traffic_InFmt", LiveTrafficFormatting.FormatBytesPerSec(inBps, culture));
            OutRateText = Loc.T("Home_Traffic_OutFmt", LiveTrafficFormatting.FormatBytesPerSec(outBps, culture));
        }
        catch
        {
            InRateText = Loc.T("Home_Traffic_In");
            OutRateText = Loc.T("Home_Traffic_Out");
        }
    }

    private void ApplyAxes()
    {
        try
        {
            var fg = _darkTheme ? new SKColor(0xE0, 0xE0, 0xE0) : new SKColor(0x20, 0x20, 0x20);
            var grid = _darkTheme
                ? new SKColor(0xE0, 0xE0, 0xE0, 40)
                : new SKColor(0x20, 0x20, 0x20, 40);

            XAxes =
            [
                new Axis
                {
                    MinLimit = 0,
                    MaxLimit = WindowSize - 1,
                    LabelsPaint = null,
                    SeparatorsPaint = null,
                    ShowSeparatorLines = false,
                }
            ];

            YAxes =
            [
                new Axis
                {
                    MinLimit = 0,
                    LabelsPaint = new SolidColorPaint(fg),
                    SeparatorsPaint = new SolidColorPaint(grid) { StrokeThickness = 1 },
                    Labeler = value =>
                    {
                        try
                        {
                            return LiveTrafficFormatting.FormatBytesPerSec(Math.Max(0, value), CultureInfo.CurrentCulture);
                        }
                        catch
                        {
                            return "";
                        }
                    },
                }
            ];

            OnPropertyChanged(nameof(XAxes));
            OnPropertyChanged(nameof(YAxes));
        }
        catch
        {
            SetErrorFromKey(LiveTrafficError.KeyGeneric);
        }
    }

    private static void Shift(ObservableCollection<ObservableValue> values, double next)
    {
        if (values.Count > 0)
            values.RemoveAt(0);
        values.Add(new ObservableValue(next));
    }

    private void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
