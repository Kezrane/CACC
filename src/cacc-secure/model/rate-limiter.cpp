// rate-limiter.cpp
//
// Implementation of Algorithm 3 (Rate Limiting for PH Inflation).

#include "rate-limiter.hpp"

#include <ns3/log.h>
#include <ns3/simulator.h>

#include <chrono>

namespace ns3 {
namespace ndn {

NS_LOG_COMPONENT_DEFINE("CaccSecureRateLimiter");

// ===========================================================================
// Construction
// ===========================================================================
RateLimiter::RateLimiter(uint32_t maxIncrPerWindow, uint32_t windowSeconds)
    : m_maxIncrPerWindow(maxIncrPerWindow),
      m_windowMs(static_cast<uint64_t>(windowSeconds) * 1000ULL)
{
    NS_LOG_FUNCTION(this << maxIncrPerWindow << windowSeconds);
}

// ===========================================================================
// nowMs(): wall-clock time in milliseconds
// ===========================================================================
uint64_t
RateLimiter::nowMs() const
{
    // Prefer NS-3 simulated time when available, for reproducibility
    const auto simTime = Simulator::Now();
    if (simTime.GetNanoSeconds() > 0) {
        return static_cast<uint64_t>(simTime.GetMilliSeconds());
    }
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

// ===========================================================================
// Algorithm 3: check and update
// ===========================================================================
// Require: PH from packet, Rate Limiter state
// Ensure: Valid PH or clamped value
// 1: window_count <- rate_counter[ContentName].count_in_last_60s
// 2: if window_count >= MAX_INCR_PER_WINDOW (10) then
// 3:    PH <- previous_PH (clamp to prevent inflation)
// 4: else
// 5:    rate_counter[ContentName] <- rate_counter[ContentName] + 1
// 6: end if
// 7: Pass to reputation weighting
// ===========================================================================
bool
RateLimiter::checkAndUpdate(const ::ndn::Name& contentName, uint8_t& ph)
{
    const uint64_t now = nowMs();
    Window& w = m_windows[contentName];

    // 1. Purge timestamps older than the window
    while (!w.timestamps.empty() &&
           (now - w.timestamps.front()) > m_windowMs) {
        w.timestamps.pop_front();
    }

    // 2. Count increments in the current window
    const uint32_t windowCount = static_cast<uint32_t>(w.timestamps.size());

    // 3-4. Clamp if threshold exceeded
    if (windowCount >= m_maxIncrPerWindow) {
        ph = w.lastPh;   // clamp to previous value
        NS_LOG_DEBUG("Rate limiter CLAMP for " << contentName.toUri()
                     << " (windowCount=" << windowCount
                     << ", PH kept at " << static_cast<int>(ph) << ")");
        return true;
    }

    // 5. Otherwise, record the increment
    w.timestamps.push_back(now);
    w.lastPh = ph;

    NS_LOG_DEBUG("Rate limiter ACCEPT for " << contentName.toUri()
                 << " (windowCount=" << windowCount + 1
                 << ", PH=" << static_cast<int>(ph) << ")");
    return false;
}

void
RateLimiter::clear()
{
    m_windows.clear();
}

} // namespace ndn
} // namespace ns3