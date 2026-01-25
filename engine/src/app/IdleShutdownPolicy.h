#pragma once

#include <cstdint>
#include <iosfwd>

class IdleShutdownPolicy
{
public:
    explicit IdleShutdownPolicy(uint64_t idleExitAfterMs);

    void ResetPrintTimer();

    bool ShouldExit(uint64_t nowMs, uint64_t lastSeenMs, uint64_t startMs) const;

    void MaybePrintCountdown(std::ostream& out, uint64_t nowMs, uint64_t lastSeenMs, uint64_t startMs);

private:
    uint64_t GetLastSeenOrStart(uint64_t lastSeenMs, uint64_t startMs) const;
    uint64_t GetIdleForMs(uint64_t nowMs, uint64_t lastSeenOrStartMs) const;
    uint64_t GetRemainingSeconds(uint64_t idleForMs) const;

private:
    uint64_t idleExitAfterMs_;
    uint64_t lastPrintedSec_ = 0;
};
