using System.ComponentModel;
using System.Globalization;
using System.Runtime.CompilerServices;
using CommunityToolkit.Mvvm.Input;
using DataGateWin.CrashReporting;
using DataGateWin.Localization;
using DataGateWin.Services.Auth;
using DataGateWin.Services.Identity;
using DataGateWin.Services.Statistics;
using DataGateWin.Services.Ui;
using DataGateMonitor.SharedModels.DataGateMonitor.VpnServerClients.Requests;
using DataGateMonitor.SharedModels.DataGateMonitor.VpnServerClients.Responses;
using DataGateMonitor.SharedModels.Enums;
using LiveChartsCore;
using LiveChartsCore.Defaults;
using LiveChartsCore.Kernel.Sketches;
using LiveChartsCore.SkiaSharpView;
using LiveChartsCore.SkiaSharpView.Painting;
using SkiaSharp;

namespace DataGateWin.ViewModels;

public enum StatisticsMetric { Both, Incoming, Outgoing, Total }

public sealed class StatisticsViewModel : INotifyPropertyChanged
{
    private readonly StatisticsApiClient _api;
    private readonly AuthSession _session;

    public event PropertyChangedEventHandler? PropertyChanged;

    private bool _isLoading;
    public bool IsLoading
    {
        get => _isLoading;
        private set { _isLoading = value; OnPropertyChanged(); }
    }

    private string? _errorText;
    public string? ErrorText
    {
        get => _errorText;
        private set { _errorText = value; OnPropertyChanged(); }
    }

    private string _totalUploadedText = "—";
    public string TotalUploadedText
    {
        get => _totalUploadedText;
        private set { _totalUploadedText = value; OnPropertyChanged(); }
    }

    public string TotalIncomingText => _lastData is null ? "—" : FormatBytes(_lastData.Summary.TotalTrafficInBytes);
    public string TotalCombinedText => _lastData is null ? "—" : FormatBytes(
        (double)_lastData.Summary.TotalTrafficInBytes + _lastData.Summary.TotalTrafficOutBytes);
    public string ChartDescription => Loc.T("Stats_VolumeHint");

    private string _periodText = "—";
    public string PeriodText
    {
        get => _periodText;
        private set { _periodText = value; OnPropertyChanged(); }
    }

    private ISeries[] _series = Array.Empty<ISeries>();
    public ISeries[] Series
    {
        get => _series;
        private set { _series = value; OnPropertyChanged(); }
    }

    private ICartesianAxis[] _xAxes = Array.Empty<ICartesianAxis>();
    public ICartesianAxis[] XAxes
    {
        get => _xAxes;
        private set { _xAxes = value; OnPropertyChanged(); }
    }

    private ICartesianAxis[] _yAxes = Array.Empty<ICartesianAxis>();
    public ICartesianAxis[] YAxes
    {
        get => _yAxes;
        private set { _yAxes = value; OnPropertyChanged(); }
    }

    private DateTimeOffset? _fromLocalDate;
    public DateTimeOffset? FromLocalDate
    {
        get => _fromLocalDate;
        set
        {
            _selectedPreset = null;
            _fromLocalDate = value;
            OnPropertyChanged();
            _loadedFromUtc = null;
            _loadedToUtc = null;
            UpdatePeriodTextPreview();
        }
    }

    private DateTimeOffset? _toLocalDate;
    public DateTimeOffset? ToLocalDate
    {
        get => _toLocalDate;
        set
        {
            _selectedPreset = null;
            _toLocalDate = value;
            OnPropertyChanged();
            _loadedFromUtc = null;
            _loadedToUtc = null;
            UpdatePeriodTextPreview();
        }
    }

    private OverviewGrouping _grouping = OverviewGrouping.Auto;
    public OverviewGrouping Grouping
    {
        get => _grouping;
        private set
        {
            _grouping = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(GroupingText));
        }
    }

    public string GroupingText => Grouping switch
    {
        OverviewGrouping.Auto => Loc.T("Stats_Group_Auto"),
        OverviewGrouping.Hours => Loc.T("Stats_Group_Hours"),
        OverviewGrouping.Days => Loc.T("Stats_Group_Days"),
        OverviewGrouping.Months => Loc.T("Stats_Group_Months"),
        OverviewGrouping.Years => Loc.T("Stats_Group_Years"),
        _ => Grouping.ToString()
    };

    public IAsyncRelayCommand ApplyFiltersCommand { get; }
    public IRelayCommand ResetFiltersCommand { get; }
    public IRelayCommand<string> SetGroupingCommand { get; }
    public IRelayCommand<string> SetLastDaysCommand { get; }

    private string? _selectedPreset;
    public string? SelectedPreset => _selectedPreset;
    private OverviewGrouping _loadedGrouping = OverviewGrouping.Auto;
    private StatisticsMetric _metric;
    public StatisticsMetric Metric
    {
        get => _metric;
        set { if (_metric == value) return; _metric = value; OnPropertyChanged(); RefreshChart(); }
    }

    public void ApplyPreset(string preset)
    {
        var (from, to) = StatisticsRangePolicy.Resolve(preset, DateTimeOffset.Now);
        _selectedPreset = preset;
        _fromLocalDate = from.ToLocalTime();
        _toLocalDate = to.ToLocalTime();
        _loadedFromUtc = _loadedToUtc = null;
        OnPropertyChanged(nameof(SelectedPreset));
        OnPropertyChanged(nameof(FromLocalDate));
        OnPropertyChanged(nameof(ToLocalDate));
        UpdatePeriodTextPreview();
    }

    private OverviewSeriesResponse? _lastData;
    private DateTimeOffset? _loadedFromUtc;
    private DateTimeOffset? _loadedToUtc;
    private bool _darkTheme = true;
    private Exception? _lastError;

    public StatisticsViewModel(StatisticsApiClient api, AuthSession session)
    {
        _api = api ?? throw new ArgumentNullException(nameof(api));
        _session = session ?? throw new ArgumentNullException(nameof(session));

        SetGroupingCommand = new RelayCommand<string>(SetGrouping);
        ApplyFiltersCommand = new AsyncRelayCommand(ct => ApplyAsync(ct));
        ResetFiltersCommand = new RelayCommand(ResetFilters);
        SetLastDaysCommand = new RelayCommand<string>(SetLastDays);

        WinUiLanguageService.LanguageChanged += OnUiLanguageChanged;
        ResetFilters();
        ApplyEmptyChart();
    }

    public void SetChartTheme(bool dark)
    {
        _darkTheme = dark;
        RefreshChart();
    }

    private void OnUiLanguageChanged(object? sender, EventArgs e)
    {
        OnPropertyChanged(nameof(GroupingText));
        if (_lastError is not null)
            ErrorText = VpnUserFacingError.FromException(_lastError);
        if (_loadedFromUtc is not null && _loadedToUtc is not null)
            ApplyLoadedPeriodText();
        else
            UpdatePeriodTextPreview();
        RefreshChart();
    }

    public Task LoadAsync(CancellationToken ct) => ApplyAsync(ct);

    private void SetGrouping(string? grouping)
    {
        if (Enum.TryParse<OverviewGrouping>(grouping, ignoreCase: true, out var parsed))
            Grouping = parsed;
    }

    private async Task ApplyAsync(CancellationToken ct)
    {
        ErrorText = null;
        _lastError = null;
        var (from, to) = _selectedPreset is { } preset
            ? StatisticsRangePolicy.Resolve(preset, DateTimeOffset.Now)
            : (GetFromDateUtc(), GetToDateUtc());
        if (to <= from)
        {
            ErrorText = Loc.T("Stats_InvalidPeriod");
            return;
        }

        IsLoading = true;
        try
        {
            var token = await _session.GetValidAccessTokenAsync(ct).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(token))
            {
                ErrorText = Loc.T("Stats_Err_NoToken");
                return;
            }

            var externalId =
                JwtClaimReader.GetClaimFromBearerToken(token, "externalId")
                ?? JwtClaimReader.GetClaimFromBearerToken(token, "sub")
                ?? JwtClaimReader.GetClaimFromBearerToken(token, "nameid");

            if (string.IsNullOrWhiteSpace(externalId))
            {
                ErrorText = Loc.T("Stats_Err_NoExternalId");
                return;
            }

            var effectiveGrouping = ResolveGrouping(Grouping, from, to);
            var req = new GetOverviewSeriesRequest
            {
                From = from,
                To = to,
                ExternalId = externalId,
                Grouping = effectiveGrouping
            };

            var data = await _api.GetOverviewSeriesAsync(req, ct);
            _lastData = data;
            _loadedGrouping = effectiveGrouping;
            TotalUploadedText = FormatBytes(data.Summary.TotalTrafficOutBytes);
            OnPropertyChanged(nameof(TotalIncomingText));
            OnPropertyChanged(nameof(TotalCombinedText));
            _loadedFromUtc = from;
            _loadedToUtc = to;
            ApplyLoadedPeriodText();
            RefreshChart();
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            return;
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "StatisticsViewModel.Apply");
            _lastError = ex;
            ErrorText = VpnUserFacingError.FromException(ex);
        }
        finally
        {
            IsLoading = false;
        }
    }

    public void RefreshChart()
    {
        if (_lastData is null)
            ApplyEmptyChart();
        else
            ApplySeriesChart(_lastData);
    }

    private void ApplyEmptyChart()
    {
        Series = Array.Empty<ISeries>();
        ApplyAxes();
    }

    private void ApplySeriesChart(OverviewSeriesResponse data)
    {
        var rows = data.OverviewSeriesRows.OrderBy(row => row.Ts).ToArray();
        var incoming = new SKColor(0x42, 0xB8, 0xF5);
        var outgoing = new SKColor(0xF4, 0xAB, 0x4A);
        Series =
        [
            new LineSeries<ObservableValue>
            {
                Name = Loc.T("Stats_Incoming"),
                Values = rows.Select(row => new ObservableValue(row.TrafficInBytes)).ToArray(),
                Fill = new SolidColorPaint(incoming.WithAlpha(22)),
                Stroke = new SolidColorPaint(incoming) { StrokeThickness = 2.5f },
                GeometrySize = 5,
                GeometryFill = new SolidColorPaint(incoming),
                GeometryStroke = null,
                LineSmoothness = 0,
                YToolTipLabelFormatter = point => FormatBytes(point.Coordinate.PrimaryValue),
            },
            new LineSeries<ObservableValue>
            {
                Name = Loc.T("Stats_Outgoing"),
                Values = rows.Select(row => new ObservableValue(row.TrafficOutBytes)).ToArray(),
                Fill = new SolidColorPaint(outgoing.WithAlpha(16)),
                Stroke = new SolidColorPaint(outgoing) { StrokeThickness = 2.5f },
                GeometrySize = 5,
                GeometryFill = new SolidColorPaint(outgoing),
                GeometryStroke = null,
                LineSmoothness = 0,
                YToolTipLabelFormatter = point => FormatBytes(point.Coordinate.PrimaryValue),
            }
        ];
        Series = Metric switch
        {
            StatisticsMetric.Incoming => [Series[0]],
            StatisticsMetric.Outgoing => [Series[1]],
            StatisticsMetric.Total =>
            [
                new LineSeries<ObservableValue>
                {
                    Name = Loc.T("Stats_Combined"),
                    Values = rows.Select(row => new ObservableValue((double)row.TrafficInBytes + row.TrafficOutBytes)).ToArray(),
                    Fill = new SolidColorPaint(incoming.WithAlpha(22)),
                    Stroke = new SolidColorPaint(incoming) { StrokeThickness = 2.5f },
                    GeometrySize = 5,
                    GeometryFill = new SolidColorPaint(incoming),
                    GeometryStroke = null,
                    LineSmoothness = 0,
                    YToolTipLabelFormatter = point => FormatBytes(point.Coordinate.PrimaryValue),
                }
            ],
            _ => Series,
        };
        var grouping = _loadedGrouping;
        var format = grouping switch
        {
            OverviewGrouping.Hours => "dd MMM HH:mm",
            OverviewGrouping.Months => "MMM yyyy",
            OverviewGrouping.Years => "yyyy",
            _ => "dd MMM",
        };
        ApplyAxes(rows.Select(row => row.Ts.UtcDateTime.ToString(format, Loc.FormatCulture)).ToArray());
    }

    private void ApplyAxes(string[]? labels = null)
    {
        var fg = _darkTheme ? new SKColor(0xC8, 0xCD, 0xD5) : new SKColor(0x40, 0x48, 0x52);
        var grid = _darkTheme
            ? new SKColor(0xFF, 0xFF, 0xFF, 24)
            : new SKColor(0x20, 0x20, 0x20, 24);
        XAxes =
        [
            new Axis
            {
                Labels = labels ?? Array.Empty<string>(),
                LabelsPaint = new SolidColorPaint(fg),
                TextSize = 12,
                SeparatorsPaint = null,
                UnitWidth = 1,
                MinStep = 1,
                ForceStepToMin = false,
                MinLimit = -0.5,
                MaxLimit = labels is { Length: > 0 } ? labels.Length - 0.5 : 0.5,
            }
        ];
        YAxes =
        [
            new Axis
            {
                MinLimit = 0,
                TextSize = 12,
                LabelsPaint = new SolidColorPaint(fg),
                SeparatorsPaint = new SolidColorPaint(grid) { StrokeThickness = 1 },
                Labeler = value => FormatBytes(Math.Max(0, value)),
            }
        ];
    }

    private void ApplyLoadedPeriodText()
    {
        if (_loadedFromUtc is null || _loadedToUtc is null)
            return;

        PeriodText = Loc.T(
            "Stats_PeriodDataFmt",
            _loadedFromUtc.Value.ToLocalTime().ToString("g", Loc.FormatCulture),
            _loadedToUtc.Value.ToLocalTime().ToString("g", Loc.FormatCulture));
    }

    private static OverviewGrouping ResolveGrouping(OverviewGrouping requested, DateTimeOffset from, DateTimeOffset to)
    {
        if (requested != OverviewGrouping.Auto)
            return requested;
        var days = (to - from).TotalDays;
        if (days <= 2) return OverviewGrouping.Hours;
        if (days <= 90) return OverviewGrouping.Days;
        if (days <= 800) return OverviewGrouping.Months;
        return OverviewGrouping.Years;
    }

    private void ResetFilters()
    {
        Grouping = OverviewGrouping.Auto;
        ApplyPreset("7d");
    }

    private void SetLastDays(string? daysText)
    {
        if (daysText is "7" or "30" or "90") ApplyPreset(daysText + "d");
    }

    private DateTimeOffset GetFromDateUtc()
    {
        var local = (FromLocalDate?.DateTime ?? DateTime.Now.Date).Date;
        var localStart = new DateTime(local.Year, local.Month, local.Day, 0, 0, 0, DateTimeKind.Local);
        return new DateTimeOffset(localStart).ToUniversalTime();
    }

    private DateTimeOffset GetToDateUtc()
    {
        var local = (ToLocalDate?.DateTime ?? DateTime.Now.Date).Date;
        var localEnd = new DateTime(local.Year, local.Month, local.Day, 23, 59, 59, 999, DateTimeKind.Local);
        return new DateTimeOffset(localEnd).ToUniversalTime();
    }

    private void UpdatePeriodTextPreview()
    {
        if (_selectedPreset is { } preset)
        {
            var range = StatisticsRangePolicy.Resolve(preset, DateTimeOffset.Now);
            PeriodText = Loc.T("Stats_PeriodDataFmt", range.From.ToLocalTime().ToString("g", Loc.FormatCulture),
                range.To.ToLocalTime().ToString("g", Loc.FormatCulture));
            return;
        }
        var from = FromLocalDate?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) ?? "—";
        var to = ToLocalDate?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) ?? "—";
        PeriodText = Loc.T("Stats_PeriodDataFmt", from, to);
    }

    private static string FormatBytes(double bytes)
    {
        const double k = 1024.0;
        if (bytes < k) return $"{bytes.ToString("F0", Loc.FormatCulture)} B";
        var kb = bytes / k;
        if (kb < k) return $"{kb:F1} KB";
        var mb = kb / k;
        if (mb < k) return $"{mb:F1} MB";
        var gb = mb / k;
        return $"{gb:F2} GB";
    }

    private void OnPropertyChanged([CallerMemberName] string? name = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
