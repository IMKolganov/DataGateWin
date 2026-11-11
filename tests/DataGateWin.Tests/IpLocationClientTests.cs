using System.Net;
using DataGateWin.Services.VpnServers;
using Xunit;

namespace DataGateWin.Tests;

public sealed class IpLocationClientTests
{
    [Theory]
    [InlineData("{}")]
    [InlineData("null")]
    [InlineData("not json")]
    [InlineData("[]")]
    [InlineData("{\"success\":\"true\",\"latitude\":35,\"longitude\":33}")]
    [InlineData("{\"success\":true,\"latitude\":-91,\"longitude\":33}")]
    [InlineData("{\"success\":true,\"latitude\":35,\"longitude\":-181}")]
    [InlineData("{\"success\":true,\"latitude\":1e999,\"longitude\":33}")]
    [InlineData("{\"success\":true,\"latitude\":35,\"longitude\":1e999}")]
    [InlineData("{\"success\":true,\"latitude\":null,\"longitude\":33}")]
    [InlineData("{\"success\":false,\"latitude\":35,\"longitude\":33}")]
    [InlineData("{\"success\":true,\"latitude\":35}")]
    [InlineData("{\"success\":true,\"latitude\":91,\"longitude\":33}")]
    [InlineData("{\"success\":true,\"latitude\":35,\"longitude\":181}")]
    [InlineData("{\"success\":true,\"latitude\":\"35\",\"longitude\":33}")]
    public async Task InvalidResponses_OmitLocation(string json)
    {
        using var http = new HttpClient(new Handler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
        { Content = new StringContent(json) })));
        Assert.Null(await new IpLocationClient(http).TryGetAsync());
    }

    [Fact]
    public async Task ValidCoordinates_AreReturned()
    {
        using var http = new HttpClient(new Handler((request, _) =>
        {
            Assert.Equal("https", request.RequestUri!.Scheme);
            Assert.Null(request.Headers.Authorization);
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            { Content = new StringContent("{\"success\":true,\"latitude\":35,\"longitude\":33}") });
        }));
        Assert.Equal(new IpLocation(35, 33), await new IpLocationClient(http).TryGetAsync());
    }

    [Fact]
    public async Task NetworkFailure_OmitsLocation()
    {
        using var http = new HttpClient(new Handler((_, _) => throw new HttpRequestException("offline")));
        Assert.Null(await new IpLocationClient(http).TryGetAsync());
    }

    [Fact]
    public async Task Cancellation_StopsPendingRequest()
    {
        using var cancellation = new CancellationTokenSource();
        using var http = new HttpClient(new Handler(async (_, token) =>
        {
            cancellation.Cancel();
            await Task.Delay(Timeout.Infinite, token);
            return new HttpResponseMessage(HttpStatusCode.OK);
        }));
        Assert.Null(await new IpLocationClient(http).TryGetAsync(cancellation.Token));
    }

    [Fact]
    public async Task UnresponsiveServer_TimesOut()
    {
        using var http = new HttpClient(new Handler(async (_, token) =>
        {
            await Task.Delay(Timeout.Infinite, token);
            return new HttpResponseMessage(HttpStatusCode.OK);
        }));
        Assert.Null(await new IpLocationClient(http).TryGetAsync().WaitAsync(TimeSpan.FromSeconds(8)));
    }

    [Fact]
    public async Task RateLimit_OmitsLocation()
    {
        using var http = new HttpClient(new Handler((_, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.TooManyRequests))));
        Assert.Null(await new IpLocationClient(http).TryGetAsync());
    }

    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            => send(request, cancellationToken);
    }
}
