using System.Net;
using System.Text;
using System.Text.Json;
using DataGateWin.Installer;
using Xunit;

namespace DataGateWin.Tests;

public sealed class InstallerInfrastructureTests
{
    [Theory]
    [InlineData("update")]
    [InlineData("--update")]
    [InlineData("/update")]
    [InlineData("UPDATE")]
    public void CommandLine_Parse_DetectsUpdateMode(string arg)
    {
        var options = InstallerCommandLine.Parse(["installer.exe", arg]);

        Assert.True(options.IsUpdateMode);
        Assert.False(options.IsUninstall);
        Assert.False(options.Quiet);
    }

    [Fact]
    public void CommandLine_Parse_DetectsUninstallAndQuiet()
    {
        var options = InstallerCommandLine.Parse(["--quiet", "--uninstall"]);

        Assert.False(options.IsUpdateMode);
        Assert.True(options.IsUninstall);
        Assert.True(options.Quiet);
    }

    [Fact]
    public void WizardRules_GetInitialStep_UsesUpdateMode()
    {
        Assert.Equal(InstallerWizardStep.Policy, InstallerWizardRules.GetInitialStep(isUpdateMode: false));
        Assert.Equal(InstallerWizardStep.Install, InstallerWizardRules.GetInitialStep(isUpdateMode: true));
    }

    [Fact]
    public void WizardRules_IsNextEnabled_MatchesStepRequirements()
    {
        Assert.False(InstallerWizardRules.IsNextEnabled(InstallerWizardStep.Policy, false, "C:\\App", false));
        Assert.True(InstallerWizardRules.IsNextEnabled(InstallerWizardStep.Policy, true, "C:\\App", false));
        Assert.False(InstallerWizardRules.IsNextEnabled(InstallerWizardStep.Path, true, "", false));
        Assert.False(InstallerWizardRules.IsNextEnabled(InstallerWizardStep.Path, true, "   ", false));
        Assert.True(InstallerWizardRules.IsNextEnabled(InstallerWizardStep.Path, true, "C:\\App", false));
        Assert.False(InstallerWizardRules.IsNextEnabled(InstallerWizardStep.Install, true, "C:\\App", false));
        Assert.True(InstallerWizardRules.IsNextEnabled(InstallerWizardStep.Install, true, "C:\\App", true));
        Assert.True(InstallerWizardRules.IsNextEnabled(InstallerWizardStep.Finish, false, "", false));
    }

    [Fact]
    public void CrashReporting_CreateConfiguration_UsesInstallerIdentity()
    {
        var cfg = InstallerCrashReporting.CreateConfiguration();

        Assert.True(cfg.Enabled);
        Assert.Equal("https://api.datagateapp.com/", cfg.BaseUrl);
        Assert.Equal("com.imkolganov.datagate.win.installer", cfg.ProcessName);
        Assert.Equal("", cfg.CrashToken);
    }

    [Fact]
    public void Product_shortcut_name_matches_branded_product_name()
    {
        Assert.Equal("DataGate", InstallerConstants.ProductName);
        Assert.Equal("DataGate.lnk", $"{InstallerConstants.ProductName}.lnk");
    }

    [Fact]
    public void Downloader_CreateGitHubHttpClient_AddsUserAgent()
    {
        using var http = InstallerDownloader.CreateGitHubHttpClient();

        Assert.Contains(
            http.DefaultRequestHeaders.UserAgent,
            value => string.Equals(value.Product?.Name, "DataGateWin.Installer", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Downloader_DownloadFileAsync_WritesBodyAndReportsContentLengthProgress()
    {
        var destination = Path.Combine(Path.GetTempPath(), "datagate_download_" + Guid.NewGuid().ToString("N"));
        try
        {
            using var http = new HttpClient(new RecordingHandler(_ =>
            {
                var content = new ByteArrayContent(Encoding.UTF8.GetBytes("hello"));
                content.Headers.ContentLength = 5;
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = content
                };
            }));
            var progress = new RecordingProgress();

            await InstallerDownloader.DownloadFileAsync(
                http,
                "https://example.invalid/file.zip",
                destination,
                progress,
                CancellationToken.None);

            Assert.Equal("hello", File.ReadAllText(destination));
            Assert.NotEmpty(progress.Values);
            Assert.Equal(100, progress.Values[^1]);
        }
        finally
        {
            DeleteFileBestEffort(destination);
        }
    }

    [Fact]
    public async Task Downloader_DownloadFileAsync_Reports100WhenContentLengthIsUnknown()
    {
        var destination = Path.Combine(Path.GetTempPath(), "datagate_download_" + Guid.NewGuid().ToString("N"));
        try
        {
            using var http = new HttpClient(new RecordingHandler(_ =>
            {
                var content = new StreamContent(new MemoryStream(Encoding.UTF8.GetBytes("unknown")));
                content.Headers.ContentLength = null;
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = content
                };
            }));
            var progress = new RecordingProgress();

            await InstallerDownloader.DownloadFileAsync(
                http,
                "https://example.invalid/file.zip",
                destination,
                progress,
                CancellationToken.None);

            Assert.Equal("unknown", File.ReadAllText(destination));
            Assert.Single(progress.Values);
            Assert.Equal(100, progress.Values[0]);
        }
        finally
        {
            DeleteFileBestEffort(destination);
        }
    }

    [Fact]
    public async Task Downloader_DownloadFileAsync_ThrowsOnHttpErrorWithoutCreatingFile()
    {
        var destination = Path.Combine(Path.GetTempPath(), "datagate_download_" + Guid.NewGuid().ToString("N"));
        using var http = new HttpClient(new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.InternalServerError)));

        await Assert.ThrowsAsync<HttpRequestException>(() =>
            InstallerDownloader.DownloadFileAsync(
                http,
                "https://example.invalid/file.zip",
                destination,
                new RecordingProgress(),
                CancellationToken.None));

        Assert.False(File.Exists(destination));
    }

    [Fact]
    public async Task Downloader_DownloadFileAsync_HonorsPreCanceledToken()
    {
        var destination = Path.Combine(Path.GetTempPath(), "datagate_download_" + Guid.NewGuid().ToString("N"));
        using var http = new HttpClient(new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.OK)));
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            InstallerDownloader.DownloadFileAsync(
                http,
                "https://example.invalid/file.zip",
                destination,
                new RecordingProgress(),
                cts.Token));

        Assert.False(File.Exists(destination));
    }

    [Fact]
    public async Task Downloader_ResolveLatestReleaseZipUrlAsync_ReturnsSelectedAsset()
    {
        using var http = new HttpClient(new RecordingHandler(request =>
        {
            Assert.Equal("https://example.invalid/releases/latest", request.RequestUri!.ToString());
            return JsonResponse(
                """
                {
                  "assets": [
                    { "name": "DataGateWin.v1.0.9.zip", "browser_download_url": "https://example.invalid/DataGateWin.v1.0.9.zip" }
                  ]
                }
                """);
        }));

        var url = await InstallerDownloader.ResolveLatestReleaseZipUrlAsync(
            http,
            "https://example.invalid/releases/latest",
            "DataGateWin.v",
            ".zip",
            CancellationToken.None);

        Assert.Equal("https://example.invalid/DataGateWin.v1.0.9.zip", url);
    }

    [Fact]
    public async Task Downloader_ResolveLatestReleaseZipUrlAsync_ThrowsOnInvalidJson()
    {
        using var http = new HttpClient(new RecordingHandler(_ => JsonResponse("{")));

        await Assert.ThrowsAnyAsync<JsonException>(() =>
            InstallerDownloader.ResolveLatestReleaseZipUrlAsync(
                http,
                "https://example.invalid/releases/latest",
                "DataGateWin.v",
                ".zip",
                CancellationToken.None));
    }

    [Fact]
    public async Task Downloader_ResolveLatestReleaseZipUrlAsync_ThrowsOnHttpError()
    {
        using var http = new HttpClient(new RecordingHandler(_ => new HttpResponseMessage(HttpStatusCode.NotFound)));

        await Assert.ThrowsAsync<HttpRequestException>(() =>
            InstallerDownloader.ResolveLatestReleaseZipUrlAsync(
                http,
                "https://example.invalid/releases/latest",
                "DataGateWin.v",
                ".zip",
                CancellationToken.None));
    }

    static HttpResponseMessage JsonResponse(string json) =>
        new(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };

    static void DeleteFileBestEffort(string path)
    {
        try
        {
            if (File.Exists(path))
                File.Delete(path);
        }
        catch
        {
        }
    }

    sealed class RecordingProgress : IProgress<double>
    {
        public List<double> Values { get; } = new();

        public void Report(double value)
            => Values.Add(value);
    }

    sealed class RecordingHandler(Func<HttpRequestMessage, HttpResponseMessage> handle) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(handle(request));
        }
    }
}
