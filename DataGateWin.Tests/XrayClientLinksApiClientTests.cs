using System.Net;
using System.Text;
using DataGateWin.Services.Xray;
using Newtonsoft.Json.Linq;
using Xunit;

namespace DataGateWin.Tests;

public sealed class XrayClientLinksApiClientTests
{
    [Fact]
    public async Task EnsureAndDownload_ParsesShareLinkContent_AndHitsXrayPath()
    {
        const string payload = "vless://uuid@host:443?encryption=none#n";
        using var handler = new QueueHandler(OkDownload("link.txt", payload));
        using var http = new HttpClient(handler) { BaseAddress = new Uri("https://api.example.com/") };

        var sut = new XrayClientLinksApiClient(http);
        var result = await sut.EnsureAndDownloadDeviceFileAsync(1, "cn", "ext", "me", CancellationToken.None);

        Assert.Equal("link.txt", result.IssuedOvpn!.FileName);
        Assert.Equal(payload, Encoding.UTF8.GetString(result.Content!));
        Assert.Equal(HttpMethod.Post, handler.Requests[0].Method);
        Assert.Equal(
            "https://api.example.com/api/xray-client-links/download-file-by-cn",
            handler.Requests[0].RequestUri!.ToString());

        var body = JObject.Parse(await handler.Requests[0].Content!.ReadAsStringAsync());
        Assert.Equal(1, body.Value<int?>("vpnServerId") ?? body.Value<int>("VpnServerId"));
        Assert.Equal("cn", body.Value<string>("commonName") ?? body.Value<string>("CommonName"));
    }

    [Fact]
    public async Task EnsureAndDownload_ParsesIssuedMonitorJsonProfileBytes()
    {
        var payload =
            """{"vless":"vless://uuid@host:443?encryption=none#n","dnsServers":["172.20.0.1"],"dnsIdentityEnabled":true,"friendlyName":"Node"}""";
        using var handler = new QueueHandler(OkDownload("client.json", payload));
        using var http = new HttpClient(handler) { BaseAddress = new Uri("https://api.example.com/") };

        var sut = new XrayClientLinksApiClient(http);
        var result = await sut.EnsureAndDownloadDeviceFileAsync(9, "cn", "ext", "me", CancellationToken.None);
        var text = Encoding.UTF8.GetString(result.Content!);

        Assert.Equal("client.json", result.IssuedOvpn!.FileName);
        Assert.Equal(payload, text);
        Assert.Equal(
            ["172.20.0.1"],
            XrayWindowsConfigBuilder.ExtractExplicitDnsServers(text));
        Assert.Equal(
            "vless://uuid@host:443?encryption=none#n",
            XrayWindowsConfigBuilder.ExtractShareLink(text));
    }

    [Fact]
    public async Task EnsureAndDownload_CreatesWhenMissing_Via400NotFoundMessage()
    {
        const string payload = "vless://a@b:1";
        using var handler = new QueueHandler(
            Json(HttpStatusCode.BadRequest, """{"success":false,"message":"Issued OVPN file not found"}"""),
            Json(HttpStatusCode.OK, """{"success":true}"""),
            OkDownload("c.txt", payload));
        using var http = new HttpClient(handler) { BaseAddress = new Uri("https://api.example.com/") };

        var sut = new XrayClientLinksApiClient(http);
        var result = await sut.EnsureAndDownloadDeviceFileAsync(2, "cn-2", "ext-2", "me-2", CancellationToken.None);

        Assert.Equal(payload, Encoding.UTF8.GetString(result.Content!));
        Assert.Equal(3, handler.Requests.Count);
        Assert.EndsWith(
            "/api/xray-client-links/add-with-token",
            handler.Requests[1].RequestUri!.AbsolutePath,
            StringComparison.Ordinal);

        var addBody = JObject.Parse(await handler.Requests[1].Content!.ReadAsStringAsync());
        Assert.Equal(2, addBody.Value<int?>("vpnServerId") ?? addBody.Value<int>("VpnServerId"));
        Assert.Equal("cn-2", addBody.Value<string>("commonName") ?? addBody.Value<string>("CommonName"));
        Assert.Equal("ext-2", addBody.Value<string>("externalId") ?? addBody.Value<string>("ExternalId"));
        Assert.Equal("me-2", addBody.Value<string>("issuedTo") ?? addBody.Value<string>("IssuedTo"));
    }

    [Fact]
    public async Task EnsureAndDownload_CreatesWhenMissing_Via404()
    {
        const string payload = "vmess://x";
        using var handler = new QueueHandler(
            new HttpResponseMessage(HttpStatusCode.NotFound),
            Json(HttpStatusCode.OK, """{"success":true}"""),
            OkDownload("x.txt", payload));
        using var http = new HttpClient(handler) { BaseAddress = new Uri("https://api.example.com/") };

        var sut = new XrayClientLinksApiClient(http);
        var result = await sut.EnsureAndDownloadDeviceFileAsync(3, "cn", "ext", "me", CancellationToken.None);
        Assert.Equal(payload, Encoding.UTF8.GetString(result.Content!));
        Assert.Equal(3, handler.Requests.Count);
    }

    [Fact]
    public async Task EnsureAndDownload_ThrowsWhenCreateFails()
    {
        using var handler = new QueueHandler(
            new HttpResponseMessage(HttpStatusCode.NotFound),
            Json(HttpStatusCode.InternalServerError, "boom"));
        using var http = new HttpClient(handler) { BaseAddress = new Uri("https://api.example.com/") };

        var sut = new XrayClientLinksApiClient(http);
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            sut.EnsureAndDownloadDeviceFileAsync(1, "cn", "ext", "me", CancellationToken.None));
        Assert.Contains("profile_download_failed", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task EnsureAndDownload_ThrowsWhenStillMissingAfterCreate()
    {
        using var handler = new QueueHandler(
            new HttpResponseMessage(HttpStatusCode.NotFound),
            Json(HttpStatusCode.OK, """{"success":true}"""),
            new HttpResponseMessage(HttpStatusCode.NotFound));
        using var http = new HttpClient(handler) { BaseAddress = new Uri("https://api.example.com/") };

        var sut = new XrayClientLinksApiClient(http);
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            sut.EnsureAndDownloadDeviceFileAsync(7, "cn", "ext", "me", CancellationToken.None));
        Assert.Contains("profile_download_failed", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task EnsureAndDownload_ThrowsOnNonNotFoundDownloadError()
    {
        using var handler = new QueueHandler(
            Json(HttpStatusCode.BadRequest, """{"success":false,"message":"quota exceeded"}"""));
        using var http = new HttpClient(handler) { BaseAddress = new Uri("https://api.example.com/") };

        var sut = new XrayClientLinksApiClient(http);
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            sut.EnsureAndDownloadDeviceFileAsync(1, "cn", "ext", "me", CancellationToken.None));
        Assert.Contains("profile_download_failed", ex.Message, StringComparison.Ordinal);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task EnsureAndDownload_TreatsSuccessFalseWithoutDataAsMissing_ThenCreates()
    {
        const string payload = "ss://x";
        using var handler = new QueueHandler(
            Json(HttpStatusCode.OK, """{"success":false,"message":"nope"}"""),
            Json(HttpStatusCode.OK, """{"success":true}"""),
            OkDownload("s.txt", payload));
        using var http = new HttpClient(handler) { BaseAddress = new Uri("https://api.example.com/") };

        var sut = new XrayClientLinksApiClient(http);
        var result = await sut.EnsureAndDownloadDeviceFileAsync(1, "cn", "ext", "me", CancellationToken.None);
        Assert.Equal(payload, Encoding.UTF8.GetString(result.Content!));
        Assert.Equal(3, handler.Requests.Count);
    }

    [Fact]
    public void Ctor_RejectsNullHttpClient()
    {
        Assert.Throws<ArgumentNullException>(() => new XrayClientLinksApiClient(null!));
    }

    private static HttpResponseMessage OkDownload(string fileName, string payloadUtf8)
    {
        var body = new JObject
        {
            ["success"] = true,
            ["data"] = new JObject
            {
                ["issuedOvpn"] = new JObject { ["fileName"] = fileName },
                ["content"] = Convert.ToBase64String(Encoding.UTF8.GetBytes(payloadUtf8))
            }
        }.ToString();
        return Json(HttpStatusCode.OK, body);
    }

    private static HttpResponseMessage Json(HttpStatusCode code, string body) =>
        new(code) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    private sealed class QueueHandler : HttpMessageHandler
    {
        private readonly Queue<HttpResponseMessage> _responses;

        public QueueHandler(params HttpResponseMessage[] responses)
        {
            _responses = new Queue<HttpResponseMessage>(responses);
        }

        public List<HttpRequestMessage> Requests { get; } = new();

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Requests.Add(request);
            if (_responses.Count == 0)
                throw new InvalidOperationException("No queued HTTP response");
            return Task.FromResult(_responses.Dequeue());
        }
    }
}
