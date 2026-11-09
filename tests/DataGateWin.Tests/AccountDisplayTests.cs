using Xunit;
using System.Text;
using DataGateWin.Services.Identity;
using Newtonsoft.Json.Linq;

namespace DataGateWin.Tests;

public class AccountDisplayTests
{
    [Fact]
    public void AspNetProfileClaimsTakePriorityOverLogin()
    {
        var token = Token(new JObject
        {
            ["unique_name"] = "imkolgasnovtest",
            ["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"] = " Имя ",
            ["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname"] = "Фамилия",
            ["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"] = " user@example.com "
        });

        Assert.Equal("Имя Фамилия", AccountDisplay.TryResolveDisplayName(token));
        Assert.Equal("user@example.com", JwtClaimReader.GetEmailFromBearerToken(token));
    }

    [Fact]
    public void GoogleProfileClaimsTakePriorityOverLogin()
    {
        var token = Token(new JObject
        {
            ["given_name"] = "Имя",
            ["family_name"] = "Фамилия",
            ["unique_name"] = "imkolgasnovtest",
            ["email"] = "user@example.com"
        });

        Assert.Equal("Имя Фамилия", AccountDisplay.TryResolveDisplayName(token));
        Assert.Equal("user@example.com", JwtClaimReader.GetEmailFromBearerToken(token));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("invalid")]
    [InlineData("header.!!!.signature")]
    public void MissingOrMalformedTokenHasNoProfile(string? token)
    {
        Assert.Null(AccountDisplay.TryResolveDisplayName(token));
        Assert.Null(JwtClaimReader.GetEmailFromBearerToken(token));
    }

    private static string Token(JObject payload) =>
        "header." + Convert.ToBase64String(Encoding.UTF8.GetBytes(payload.ToString()))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_') + ".signature";
}


