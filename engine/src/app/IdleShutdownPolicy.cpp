#include "IdleShutdownPolicy.h"

#include <ostream>

IdleShutdownPolicy::IdleShutdownPolicy(uint64_t idleExitAfterMs)
    : idleExitAfterMs_(idleExitAfterMs)
{
}

void IdleShutdownPolicy::ResetPrintTimer()
{
    lastPrintedSec_ = 0;
}

bool IdleShutdownPolicy::ShouldExit(uint64_t nowMs, uint64_t lastSeenMs, uint64_t startMs) const
{
    const uint64_t lastSeenOrStart = GetLastSeenOrStart(lastSeenMs, startMs);
    const uint64_t idleForMs = GetIdleForMs(nowMs, lastSeenOrStart);
    return idleForMs >= idleExitAfterMs_;
}

void IdleShutdownPolicy::MaybePrintCountdown(std::ostream& out, uint64_t nowMs, uint64_t lastSeenMs, uint64_t startMs)
{
    const uint64_t lastSeenOrStart = GetLastSeenOrStart(lastSeenMs, startMs);
    const uint64_t idleForMs = GetIdleForMs(nowMs, lastSeenOrStart);

    if (idleForMs >= idleExitAfterMs_)
        return;

    const uint64_t sec = GetRemainingSeconds(idleForMs);
    if (sec != lastPrintedSec_)
    {
        lastPrintedSec_ = sec;
        out << "[engine] idle shutdown in " << sec << "s" << std::endl;
    }
}

uint64_t IdleShutdownPolicy::GetLastSeenOrStart(uint64_t lastSeenMs, uint64_t startMs) const
{
    return lastSeenMs ? lastSeenMs : startMs;
}

uint64_t IdleShutdownPolicy::GetIdleForMs(uint64_t nowMs, uint64_t lastSeenOrStartMs) const
{
    return nowMs - lastSeenOrStartMs;
}

uint64_t IdleShutdownPolicy::GetRemainingSeconds(uint64_t idleForMs) const
{
    return (idleExitAfterMs_ - idleForMs + 999) / 1000;
}
