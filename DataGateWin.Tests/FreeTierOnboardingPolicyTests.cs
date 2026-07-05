using DataGateMonitor.SharedModels.DataGateMonitor.Auth.Responses;
using DataGateWin.Services.Auth;
using Xunit;

namespace DataGateWin.Tests;

public sealed class FreeTierOnboardingPolicyTests
{
    [Fact]
    public void ShouldShow_ReturnsFalse_WhenStatusMissing()
    {
        Assert.False(FreeTierOnboardingPolicy.ShouldShow(null));
    }

    [Fact]
    public void ShouldShow_ReturnsFalse_WhenPlanNotApplicable()
    {
        var status = new FreeTierAccessStatusResponse
        {
            IsApplicable = false,
            IsCompliant = false
        };

        Assert.False(FreeTierOnboardingPolicy.ShouldShow(status));
    }

    [Fact]
    public void ShouldShow_ReturnsFalse_WhenAlreadyCompliant()
    {
        var status = new FreeTierAccessStatusResponse
        {
            IsApplicable = true,
            IsCompliant = true
        };

        Assert.False(FreeTierOnboardingPolicy.ShouldShow(status));
    }

    [Fact]
    public void ShouldShow_ReturnsTrue_WhenApplicableAndNotCompliant()
    {
        var status = new FreeTierAccessStatusResponse
        {
            IsApplicable = true,
            IsCompliant = false
        };

        Assert.True(FreeTierOnboardingPolicy.ShouldShow(status));
    }
}
