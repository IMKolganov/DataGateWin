#pragma once

#include <cstddef>

namespace datagate
{
    // Safety ceiling for IPC control / crash-queue style buffers (bytes).
    // UI journals use a line ring (1000) on the managed side instead.
    inline constexpr std::size_t kInMemoryLogBudgetBytes = 8ull * 1024ull * 1024ull;
}
