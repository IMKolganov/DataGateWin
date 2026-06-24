using Xunit;

namespace DataGateWin.Tests;

/// <summary>
/// Mirrors engine <c>ArgParser::HasFlag</c> contract used by <c>--recover-dns</c>.
/// </summary>
public sealed class EngineArgParserContractTests
{
    static bool HasFlag(string[] argv, string flag)
    {
        for (var i = 1; i < argv.Length; i++)
        {
            if (string.Equals(argv[i], flag, StringComparison.Ordinal))
                return true;
        }

        return false;
    }

    [Fact]
    public void HasFlag_DetectsRecoverDnsSwitch()
    {
        Assert.True(HasFlag(["engine.exe", "--recover-dns"], "--recover-dns"));
        Assert.False(HasFlag(["engine.exe", "--session-id", "dev"], "--recover-dns"));
    }
}
