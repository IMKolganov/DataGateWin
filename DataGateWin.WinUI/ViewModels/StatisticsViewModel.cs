using System.ComponentModel;
using System.Globalization;
using System.Runtime.CompilerServices;
using CommunityToolkit.Mvvm.Input;
using DataGateWin.CrashReporting;
using DataGateWin.Localization;
using DataGateWin.Services.Auth;
using DataGateWin.Services.Identity;
using DataGateWin.Services.Statistics;
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

    private OverviewSeriesResponse? _lastData;
    private DateTimeOffset? _loadedFromUtc;
    private DateTimeOffset? _loadedToUtc;
    private bool _darkTheme = true;

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
        var from = GetFromDateUtc();
        var to = GetToDateUtc();
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
            TotalUploadedText = FormatBytes(data.Summary.TotalTrafficOutBytes);
            _loadedFromUtc = from;
            _loadedToUtc = to;
            ApplyLoadedPeriodText();
            RefreshChart();
        }
        catch (Exception ex)
        {
            CrashReporter.ReportNonFatal(ex, "StatisticsViewModel.Apply");
            ErrorText = ex.Message;
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
        var accent = new SKColor(0x4C, 0x9A, 0xFF);
        var points = new List<DateTimePoint>();
        foreach (var row in data.OverviewSeriesRows)
            points.Add(new DateTimePoint(row.Ts.UtcDateTime, row.TrafficOutBytes));

        Series =
        [
            new LineSeries<DateTimePoint>
            {
                Name = Loc.T("Stats_Series_Upload"),
                Values = points,
                GeometrySize = 0,
                Fill = new SolidColorPaint(accent.WithAlpha(80)),
                Stroke = new SolidColorPaint(accent) { StrokeThickness = 2 },
                LineSmoothness = 0
            }
        ];
        ApplyAxes();
    }

    private void ApplyAxes()
    {
        var fg = _darkTheme ? new SKColor(0xE0, 0xE0, 0xE0) : new SKColor(0x20, 0x20, 0x20);
        var grid = _darkTheme
            ? new SKColor(0xE0, 0xE0, 0xE0, 60)
            : new SKColor(0x20, 0x20, 0x20, 60);

        XAxes =
        [
            new Axis
            {
                Labeler = value =>
                {
                    try { return new DateTime((long)value).ToString("dd MMM", CultureInfo.CurrentCulture); }
                    catch { return ""; }
                },
                LabelsPaint = new SolidColorPaint(fg),
                SeparatorsPaint = new SolidColorPaint(grid) { StrokeThickness = 1 },
                UnitWidth = TimeSpan.FromDays(1).Ticks,
                MinStep = TimeSpan.FromHours(1).Ticks
            }
        ];

        YAxes =
        [
            new Axis
            {
                Name = Loc.T("Stats_Axis_Traffic"),
                NamePaint = new SolidColorPaint(fg),
                LabelsPaint = new SolidColorPaint(fg),
                SeparatorsPaint = new SolidColorPaint(grid) { StrokeThickness = 1 },
                Labeler = value => FormatBytes((long)Math.Max(0, value))
            }
        ];
    }

    private void ApplyLoadedPeriodText()
    {
        if (_loadedFromUtc is null || _loadedToUtc is null)
            return;

        PeriodText = Loc.T(
            "Stats_PeriodDataFmt",
            _loadedFromUtc.Value.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
            _loadedToUtc.Value.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture));
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
        var nowLocal = DateTime.Now.Date;
        FromLocalDate = new DateTimeOffset(nowLocal.AddDays(-7));
        ToLocalDate = new DateTimeOffset(nowLocal);
        _loadedFromUtc = null;
        _loadedToUtc = null;
        UpdatePeriodTextPreview();
    }

    private void SetLastDays(string? daysText)
    {
        if (!int.TryParse(daysText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var days) || days <= 0)
            return;
        var nowLocal = DateTime.Now.Date;
        FromLocalDate = new DateTimeOffset(nowLocal.AddDays(-days));
        ToLocalDate = new DateTimeOffset(nowLocal);
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
        var from = FromLocalDate?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) ?? "—";
        var to = ToLocalDate?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) ?? "—";
        PeriodText = Loc.T("Stats_PeriodDataFmt", from, to);
    }

    private static string FormatBytes(long bytes)
    {
        const double k = 1024.0;
        if (bytes < k) return $"{bytes.ToString(CultureInfo.InvariantCulture)} B";
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
