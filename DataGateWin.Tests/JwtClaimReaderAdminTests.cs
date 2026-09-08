using System.Text;
using DataGateWin.Services.Identity;
using Xunit;

namespace DataGateWin.Tests;

public sealed class JwtClaimReaderAdminTests
{
    [Fact]
    public void IsAdmin_True_WhenRoleStringAdmin()
    {
        var token = MakeToken(new { role = "Admin" });
        Assert.True(JwtClaimReader.IsAdmin(token));
    }

    [Fact]
    public void IsAdmin_True_WhenRoleArrayContainsAdmin()
    {
        var token = MakeToken(new { role = new[] { "User", "Admin" } });
        Assert.True(JwtClaimReader.IsAdmin(token));
    }

    [Fact]
    public void IsAdmin_False_WhenRoleUser()
    {
        var token = MakeToken(new { role = "User" });
        Assert.False(JwtClaimReader.IsAdmin(token));
    }

    [Fact]
    public void IsAdmin_False_WhenMissingRole()
    {
        var token = MakeToken(new { name = "x" });
        Assert.False(JwtClaimReader.IsAdmin(token));
        Assert.False(JwtClaimReader.IsAdmin(null));
    }

    private static string MakeToken(object payload)
    {
        var json = Newtonsoft.Json.JsonConvert.SerializeObject(payload);
        var b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(json))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
        return $"hdr.{b64}.sig";
    }
}
