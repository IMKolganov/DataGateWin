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
    public void ShouldSkipClientChecks_AdminOrPaidPlan()
    {
        Assert.True(FreeTierOnboardingPolicy.ShouldSkipClientChecks(isAdmin: true, knownPlanName: null));
        Assert.True(FreeTierOnboardingPolicy.ShouldSkipClientChecks(isAdmin: true, knownPlanName: "Free"));
        Assert.True(FreeTierOnboardingPolicy.ShouldSkipClientChecks(isAdmin: false, knownPlanName: "Pro"));
        Assert.True(FreeTierOnboardingPolicy.ShouldSkipClientChecks(isAdmin: false, knownPlanName: "Unlimited"));
        Assert.False(FreeTierOnboardingPolicy.ShouldSkipClientChecks(isAdmin: false, knownPlanName: null));
        Assert.False(FreeTierOnboardingPolicy.ShouldSkipClientChecks(isAdmin: false, knownPlanName: "Free"));
        Assert.False(FreeTierOnboardingPolicy.ShouldSkipClientChecks(isAdmin: false, knownPlanName: "Default"));
    }

    [Fact]
    public void IsFreeOrDefaultPlan_Cases()
    {
        Assert.True(FreeTierOnboardingPolicy.IsFreeOrDefaultPlan("Free"));
        Assert.True(FreeTierOnboardingPolicy.IsFreeOrDefaultPlan("default"));
        Assert.False(FreeTierOnboardingPolicy.IsFreeOrDefaultPlan("Pro"));
        Assert.False(FreeTierOnboardingPolicy.IsFreeOrDefaultPlan(null));
        Assert.False(FreeTierOnboardingPolicy.IsFreeOrDefaultPlan(""));
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
