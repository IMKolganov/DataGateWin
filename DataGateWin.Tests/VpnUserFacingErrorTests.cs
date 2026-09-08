using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using DataGateWin.Services.Ui;
using Xunit;

namespace DataGateWin.Tests;

public sealed class VpnUserFacingErrorTests
{
    [Fact]
    public void TunBusy_FromWin32AlreadyExists()
    {
        Assert.Equal("Home_Error_TunBusy", VpnUserFacingError.FromMessage(
            "Cannot create a file when that file already exists"));
    }

    [Fact]
    public void HttpTimeout_IsTimeout_NotCanceled()
    {
        Exception ex = new TaskCanceledException("The request was canceled due to the configured HttpClient.Timeout.");
        Assert.Equal("Home_Error_Timeout", VpnUserFacingError.FromException(ex));
    }

    [Fact]
    public void OperationCanceled_IsCanceled()
    {
        Assert.Equal("Home_Error_Canceled", VpnUserFacingError.FromException(new OperationCanceledException()));
    }

    [Fact]
    public void UnauthorizedHttp_IsAuth()
    {
        var ex = new HttpRequestException("401", null, HttpStatusCode.Unauthorized);
        Assert.Equal("Home_Error_Auth", VpnUserFacingError.FromException(ex));
    }

    [Fact]
    public void Socket_IsNetwork()
    {
        Assert.Equal("Home_Error_Network", VpnUserFacingError.FromException(
            new SocketException(10061)));
    }

    [Fact]
    public void AccessDenied_IsPermission()
    {
        Assert.Equal("Home_Error_Permission", VpnUserFacingError.FromException(
            new UnauthorizedAccessException("Access to the path is denied.")));
    }

    [Fact]
    public void HresultDump_IsGeneric()
    {
        Assert.Equal("Home_Error_Generic", VpnUserFacingError.FromException(
            new InvalidOperationException("HRESULT 0x80070005 at Foo.Bar()")));
    }

    [Fact]
    public void TotpJsonBody_InvalidCode()
    {
        var ex = new HttpRequestException(
            "TOTP verify failed: 400 Bad Request. Body: {\"success\":false,\"message\":\"Invalid code\"}",
            null,
            HttpStatusCode.BadRequest);
        Assert.Equal("Login_Totp_Error_Invalid", VpnUserFacingError.FromException(ex));
    }

    [Fact]
    public void TotpExpired_FromApiPhrase()
    {
        Assert.Equal("Login_Totp_ChallengeExpired", VpnUserFacingError.FromMessage(
            "Login challenge expired. Please sign in again."));
    }

    [Fact]
    public void EngineExit_FromEventText()
    {
        Assert.Equal("Home_Error_EngineExit", VpnUserFacingError.FromMessage("engine exit code=3221225781"));
    }

    [Fact]
    public void EngineMissing_FromFileNotFound()
    {
        Assert.Equal("Home_Status_EngineMissing", VpnUserFacingError.FromException(
            new FileNotFoundException("Engine executable not found: C:\\app\\engine.exe", @"C:\app\engine.exe")));
    }

    [Fact]
    public void ServerJsonDump_IsServerRequest()
    {
        Assert.Equal("Home_Error_ServerRequest", VpnUserFacingError.FromMessage(
            "{\"success\":false,\"error\":{\"code\":500}}"));
    }
}
