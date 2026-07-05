using System.Net;
using System.Text;
using DataGateMonitor.SharedModels.DataGateMonitor.Auth.Requests;
using DataGateMonitor.SharedModels.DataGateMonitor.Auth.Responses;
using DataGateWin.Services.Auth;
using Newtonsoft.Json;
using DataGateMonitor.SharedModels.Responses;
using Xunit;

namespace DataGateWin.Tests;

public sealed class FreeTierAccessApiClientTests
{
    [Fact]
    public async Task GetStatusAsync_CallsExpectedEndpointAndParsesPayload()
    {
        var expected = new FreeTierAccessStatusResponse
        {
            IsApplicable = true,
            IsCompliant = false,
            RequiredChannel = "@DataGateVPNBot"
        };

        var envelope = new ApiResponse<FreeTierAccessStatusResponse>
        {
            Success = true,
            Data = expected
        };

        using var handler = new RecordingHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonConvert.SerializeObject(envelope), Encoding.UTF8, "application/json")
            });
        using var http = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://api.example.com/")
        };

        var sut = new FreeTierAccessApiClient(http);
        var result = await sut.GetStatusAsync(CancellationToken.None);

        Assert.Equal(HttpMethod.Get, handler.LastRequest!.Method);
        Assert.Equal("https://api.example.com/api/auth/free-tier-access/status", handler.LastRequest.RequestUri!.ToString());
        Assert.NotNull(result.Data);
        Assert.True(result.Data!.IsApplicable);
        Assert.False(result.Data.IsCompliant);
        Assert.Equal("@DataGateVPNBot", result.Data.RequiredChannel);
    }

    [Fact]
    public async Task RequestAccountLinkCodeAsync_PostsTelegramIdAndParsesCode()
    {
        var response = new ApiResponse<RequestTelegramAccountLinkCodeResponse>
        {
            Success = true,
            Data = new RequestTelegramAccountLinkCodeResponse
            {
                Code = "ABCD2345",
                ExpiresInSeconds = 900
            }
        };

        using var handler = new RecordingHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(JsonConvert.SerializeObject(response), Encoding.UTF8, "application/json")
            });
        using var http = new HttpClient(handler)
        {
            BaseAddress = new Uri("https://api.example.com/")
        };

        var sut = new FreeTierAccessApiClient(http);
        var request = new RequestTelegramAccountLinkCodeRequest
        {
            TelegramId = 123456789
        };

        var result = await sut.RequestAccountLinkCodeAsync(request, CancellationToken.None);
        var body = await handler.LastRequest!.Content!.ReadAsStringAsync();

        Assert.Equal(HttpMethod.Post, handler.LastRequest!.Method);
        Assert.Equal("https://api.example.com/api/auth/telegram/request-account-link-code", handler.LastRequest.RequestUri!.ToString());
        Assert.Contains("\"TelegramId\":123456789", body, StringComparison.Ordinal);
        Assert.Equal("ABCD2345", result.Data!.Code);
        Assert.Equal(900, result.Data.ExpiresInSeconds);
    }

    private sealed class RecordingHandler(Func<HttpRequestMessage, HttpResponseMessage> responder) : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _responder = responder;
        public HttpRequestMessage? LastRequest { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastRequest = request;
            return Task.FromResult(_responder(request));
        }
    }
}
