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

    [Fact]
    public void GetCopyMode_ReturnsLinkAccount_WhenCanRequestCode()
    {
        var status = new FreeTierAccessStatusResponse
        {
            CanRequestAccountLinkCode = true,
            IsLinkedToTelegram = true
        };

        Assert.Equal(FreeTierOnboardingCopyMode.LinkAccount, FreeTierOnboardingPolicy.GetCopyMode(status));
    }

    [Fact]
    public void GetCopyMode_ReturnsSubscribeOnly_WhenLinkedWithoutLinkCode()
    {
        var status = new FreeTierAccessStatusResponse
        {
            CanRequestAccountLinkCode = false,
            IsLinkedToTelegram = true
        };

        Assert.Equal(FreeTierOnboardingCopyMode.SubscribeOnly, FreeTierOnboardingPolicy.GetCopyMode(status));
    }

    [Fact]
    public void GetCopyMode_ReturnsGeneric_WhenNotLinkedAndCannotRequestCode()
    {
        var status = new FreeTierAccessStatusResponse
        {
            CanRequestAccountLinkCode = false,
            IsLinkedToTelegram = false
        };

        Assert.Equal(FreeTierOnboardingCopyMode.Generic, FreeTierOnboardingPolicy.GetCopyMode(status));
    }

    [Fact]
    public void FormatCountdown_FormatsMinutesAndSeconds()
    {
        Assert.Equal("5:09", FreeTierOnboardingPolicy.FormatCountdown(309));
        Assert.Equal("0:45", FreeTierOnboardingPolicy.FormatCountdown(45));
    }

    [Fact]
    public void ShouldWarnLinkCodeExpiringSoon_WithinThreshold()
    {
        Assert.True(FreeTierOnboardingPolicy.ShouldWarnLinkCodeExpiringSoon(300));
        Assert.True(FreeTierOnboardingPolicy.ShouldWarnLinkCodeExpiringSoon(1));
        Assert.False(FreeTierOnboardingPolicy.ShouldWarnLinkCodeExpiringSoon(301));
        Assert.False(FreeTierOnboardingPolicy.ShouldWarnLinkCodeExpiringSoon(0));
    }
}
