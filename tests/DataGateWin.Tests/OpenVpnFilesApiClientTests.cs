using System.Net;
using System.Text;
using DataGateWin.Services.OpenVpnFiles;
using Newtonsoft.Json;
using Xunit;

namespace DataGateWin.Tests;

public sealed class OpenVpnFilesApiClientTests
{
    [Fact]
    public async Task CreationResponseBody_IsNotBufferedBeforeDownloadingProfile()
    {
        const string profile = "client\nremote vpn.example.com 1194\n";
        var messages = new List<string>();
        using var handler = new ProfileHandler(profile);
        using var http = new HttpClient(handler) { BaseAddress = new Uri("https://api.example.com/") };
        var client = new OpenVpnFilesApiClient(http, messages.Add);

        var result = await client.EnsureAndDownloadDeviceFileAsync(1, "cn", "external", "device", CancellationToken.None);

        Assert.Equal(profile, Encoding.UTF8.GetString(result.Content!));
        Assert.Equal(3, handler.Calls);
        Assert.Contains(messages, line => line.Contains("Profile decoded bytes="));
        Assert.DoesNotContain(messages, line => line.Contains("external") || line.Contains("remote vpn.example.com"));
    }

    [Fact]
    public async Task BackendGenerationTimeout_DoesNotAttemptToIssueAnotherProfile()
    {
        using var handler = new GenerationTimeoutHandler();
        using var http = new HttpClient(handler) { BaseAddress = new Uri("https://api.example.com/") };
        var messages = new List<string>();
        var client = new OpenVpnFilesApiClient(http, messages.Add);
        await Assert.ThrowsAsync<TimeoutException>(() => client.EnsureAndDownloadDeviceFileAsync(
            1, "private-device-cn", "external", "device", CancellationToken.None));
        Assert.Equal(1, handler.Calls);
        Assert.Contains(messages, line => line.Contains("waiting for the generated OVPN"));
        Assert.DoesNotContain(messages, line => line.Contains("private-device-cn"));
    }

    private sealed class GenerationTimeoutHandler : HttpMessageHandler
    {
        public int Calls { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            BackendEndpointIdentityTests.AssertIdentity(request);
            Calls++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.BadRequest)
            {
                Content = new StringContent(JsonConvert.SerializeObject(new
                {
                    success = false,
                    message = "Failed to download OVPN file. Details: Timed out after 10s waiting for OVPN 'private-device-cn'",
                })),
            });
        }
    }

    private sealed class ProfileHandler(string profile) : HttpMessageHandler
    {
        public int Calls { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            BackendEndpointIdentityTests.AssertIdentity(request);
            Calls++;
            var response = Calls switch
            {
                1 => new HttpResponseMessage(HttpStatusCode.NotFound),
                2 => new HttpResponseMessage(HttpStatusCode.OK) { Content = new UnreadableBody() },
                _ => new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(JsonConvert.SerializeObject(new
                    {
                        success = true,
                        data = new { content = Convert.ToBase64String(Encoding.UTF8.GetBytes(profile)) },
                    })),
                },
            };
            return Task.FromResult(response);
        }
    }

    private sealed class UnreadableBody : HttpContent
    {
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context)
            => throw new InvalidOperationException("Creation response body must not be buffered.");
        protected override bool TryComputeLength(out long length) { length = 0; return false; }
    }
}
