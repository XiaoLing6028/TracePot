#pragma once

#include <atomic>

namespace tracepot {

// Thread-safe cancellation flag. cancel() is async-signal-safe (lock-free atomic store), so the
// CLI can call it from a SIGINT handler.
class CancellationToken {
public:
    void cancel() noexcept { cancelled_.store(true, std::memory_order_relaxed); }
    [[nodiscard]] bool cancelled() const noexcept { return cancelled_.load(std::memory_order_relaxed); }

private:
    std::atomic<bool> cancelled_{false};
    static_assert(std::atomic<bool>::is_always_lock_free);
};

}  // namespace tracepot
