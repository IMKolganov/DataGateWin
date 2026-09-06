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

namespace DataGateWin.ViewModels;

/// <summary>Statistics VM without OxyPlot — summary + series text stub for WinUI.</summary>
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

    private string _chartStubText = "";
    public string ChartStubText
    {
        get => _chartStubText;
        private set { _chartStubText = value; OnPropertyChanged(); }
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
        ChartStubText = Loc.T("Stats_Series_Upload") + " — chart pending (OxyPlot not ported)";
        // TODO(parity): replace ChartStubText with a WinUI chart control when available
    }

    private void OnUiLanguageChanged(object? sender, EventArgs e)
    {
        OnPropertyChanged(nameof(GroupingText));
        if (_loadedFromUtc is not null && _loadedToUtc is not null)
            ApplyLoadedPeriodText();
        else
            UpdatePeriodTextPreview();
        RefreshSummaryStub();
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
            RefreshSummaryStub();
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

    private void RefreshSummaryStub()
    {
        if (_lastData is null)
        {
            ChartStubText = Loc.T("Stats_Series_Upload") + " — no data";
            return;
        }

        var rows = _lastData.OverviewSeriesRows?.Count ?? 0;
        ChartStubText = Loc.T("Stats_Series_Upload")
            + Environment.NewLine
            + $"{rows} points · {Loc.T("Stats_Axis_Traffic")}: {TotalUploadedText}"
            + Environment.NewLine
            + "(chart stub — OxyPlot not available on WinUI)";
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
