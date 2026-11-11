using System.Net;
using System.Text;
using System.Web;
using DataGateMonitor.SharedModels.DataGateMonitor.Auth.Responses;
using DataGateMonitor.SharedModels.Enums;
using DataGateWin.Services.Auth;
using DataGateWin.Services.Auth.Interfaces;
using DataGateWin.Services.Statistics;
using DataGateWin.ViewModels;
using LiveChartsCore.Defaults;
using LiveChartsCore.SkiaSharpView;
using Newtonsoft.Json;
using Xunit;

namespace DataGateWin.Tests;

public sealed class StatisticsViewModelTests
{
    [Theory]
    [InlineData("24h", OverviewGrouping.Hours)]
    [InlineData("7d", OverviewGrouping.Days)]
    [InlineData("30d", OverviewGrouping.Days)]
    [InlineData("1y", OverviewGrouping.Months)]
    public async Task Preset_SendsExpectedRangeAndAutomaticGrouping(string preset, OverviewGrouping expected)
    {
        using var fixture = new Fixture();
        var vm = fixture.Vm;
        vm.ApplyPreset(preset);
        await vm.LoadAsync(default);
        Assert.Null(vm.ErrorText);
        var query = HttpUtility.ParseQueryString(fixture.LastUri!.Query);
        Assert.Equal(((int)expected).ToString(), query["Grouping"]);
        Assert.Equal("test-user", query["ExternalId"]);
        var from = DateTimeOffset.Parse(query["From"]!);
        var to = DateTimeOffset.Parse(query["To"]!);
        if (preset == "24h") Assert.Equal(TimeSpan.FromHours(24), to - from);
        Assert.Equal(preset, vm.SelectedPreset);
    }

    [Theory]
    [InlineData(OverviewGrouping.Hours)]
    [InlineData(OverviewGrouping.Days)]
    [InlineData(OverviewGrouping.Months)]
    [InlineData(OverviewGrouping.Years)]
    public async Task ExplicitGrouping_ReachesApi_WithoutResettingPreset(OverviewGrouping grouping)
    {
        using var fixture = new Fixture();
        fixture.Vm.ApplyPreset("24h");
        fixture.Vm.SetGroupingCommand.Execute(grouping.ToString());
        await fixture.Vm.LoadAsync(default);
        Assert.Equal(((int)grouping).ToString(), HttpUtility.ParseQueryString(fixture.LastUri!.Query)["Grouping"]);
        Assert.Equal("24h", fixture.Vm.SelectedPreset);
    }

    [Fact]
    public async Task MetricSwitch_KeepsDirectionsSeparate_AndAddsThemWithoutAnotherRequest()
    {
        using var fixture = new Fixture();
        await fixture.Vm.LoadAsync(default);
        Assert.Equal(2, fixture.Vm.Series.Length);
        Assert.Equal(new double?[] { 10, 30 }, Values(fixture.Vm.Series[0]));
        Assert.Equal(new double?[] { 20, 40 }, Values(fixture.Vm.Series[1]));
        fixture.Vm.Metric = StatisticsMetric.Total;
        Assert.Equal(new double?[] { 30, 70 }, Values(Assert.Single(fixture.Vm.Series)));
        fixture.Vm.Metric = StatisticsMetric.Incoming;
        Assert.Equal(new double?[] { 10, 30 }, Values(Assert.Single(fixture.Vm.Series)));
        fixture.Vm.Metric = StatisticsMetric.Outgoing;
        Assert.Equal(new double?[] { 20, 40 }, Values(Assert.Single(fixture.Vm.Series)));
        fixture.Vm.Metric = StatisticsMetric.Both;
        Assert.Equal(2, fixture.Vm.Series.Length);
        Assert.Equal(1, fixture.Calls);
    }

    [Fact]
    public async Task Series_AreChronological_WithDistinctDayLabelsAndZeroBaseline()
    {
        using var fixture = new Fixture();
        await fixture.Vm.LoadAsync(default);
        Assert.Equal(new double?[] { 10, 30 }, Values(fixture.Vm.Series[0]));
        var axis = Assert.IsType<Axis>(Assert.Single(fixture.Vm.XAxes));
        Assert.Equal(2, axis.Labels!.Count);
        Assert.Equal(2, axis.Labels.Distinct().Count());
        Assert.Equal(1, axis.MinStep);
        Assert.Equal(0, Assert.Single(fixture.Vm.YAxes).MinLimit);
    }

    [Fact]
    public async Task CustomDates_ClearPreset_AndInvalidRangeDoesNotHitNetwork()
    {
        using var fixture = new Fixture();
        fixture.Vm.ApplyPreset("24h");
        fixture.Vm.FromLocalDate = new DateTimeOffset(2026, 11, 12, 0, 0, 0, TimeSpan.Zero);
        fixture.Vm.ToLocalDate = new DateTimeOffset(2026, 11, 11, 0, 0, 0, TimeSpan.Zero);
        Assert.Null(fixture.Vm.SelectedPreset);
        await fixture.Vm.LoadAsync(default);
        Assert.NotNull(fixture.Vm.ErrorText);
        Assert.Equal(0, fixture.Calls);
        Assert.False(fixture.Vm.IsLoading);
    }

    [Fact]
    public async Task ApiTimeout_ShowsError_StopsLoading_AndPreservesLastGoodChart()
    {
        using var fixture = new Fixture();
        await fixture.Vm.LoadAsync(default);
        var previous = fixture.Vm.Series;
        fixture.Fail = true;
        await fixture.Vm.LoadAsync(default);
        Assert.False(fixture.Vm.IsLoading);
        Assert.False(string.IsNullOrWhiteSpace(fixture.Vm.ErrorText));
        Assert.Same(previous, fixture.Vm.Series);
    }

    private static double?[] Values(LiveChartsCore.ISeries series)
        => Assert.IsType<LineSeries<ObservableValue>>(series).Values!.Select(v => v.Value).ToArray();

    private sealed class Fixture : HttpMessageHandler
    {
        private readonly HttpClient _http;
        public Uri? LastUri;
        public int Calls;
        public bool Fail;
        public StatisticsViewModel Vm { get; }

        public Fixture()
        {
            _http = new HttpClient(this, false) { BaseAddress = new Uri("https://stats.test/") };
            var session = new AuthSession(new AuthApiClient(_http), new MemoryTokens(), "test-device", "test");
            session.InitializeAsync(default).GetAwaiter().GetResult();
            Vm = new StatisticsViewModel(new StatisticsApiClient(_http), session);
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Calls++; LastUri = request.RequestUri;
            if (Fail) throw new TimeoutException("Statistics timed out");
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonConvert.SerializeObject(new
                {
                    success = true,
                    data = new
                    {
                        summary = new { totalTrafficInBytes = 40, totalTrafficOutBytes = 60 },
                        overviewSeriesRows = new[]
                        {
                            new { ts = "2026-11-11T00:00:00Z", trafficInBytes = 30, trafficOutBytes = 40 },
                            new { ts = "2026-11-10T00:00:00Z", trafficInBytes = 10, trafficOutBytes = 20 },
                        },
                    },
                }), Encoding.UTF8, "application/json"),
            });
        }

        protected override void Dispose(bool disposing) { if (disposing) _http.Dispose(); base.Dispose(disposing); }
    }

    private sealed class MemoryTokens : ITokenStore
    {
        public Task<AuthTokensResponse?> LoadAsync(CancellationToken ct) => Task.FromResult<AuthTokensResponse?>(new()
        {
            // Synthetic, unsigned token for claim parsing only. Never sent outside the fake HTTP handler.
            Token = "e30." + Convert.ToBase64String(Encoding.UTF8.GetBytes("{\"externalId\":\"test-user\"}")).TrimEnd('=') + ".test",
            Expiration = DateTimeOffset.UtcNow.AddHours(1),
        });
        public Task SaveAsync(AuthTokensResponse tokens, CancellationToken ct) => Task.CompletedTask;
        public Task ClearAsync(CancellationToken ct) => Task.CompletedTask;
    }
}
