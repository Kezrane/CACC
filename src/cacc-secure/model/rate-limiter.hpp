// rate-limiter.hpp
//
// Algorithm 3: Rate Limiting for PH Inflation Prevention.
//
// Maintains a sliding-window counter per content name. If the number
// of PH increments observed in the last 60 seconds exceeds the
// threshold (10), the PH is clamped to its previous value.

#ifndef CACC_SECURE_RATE_LIMITER_HPP
#define CACC_SECURE_RATE_LIMITER_HPP

#include <ndn-cxx/name.hpp>
#include <cstdint>
#include <deque>
#include <map>
#include <utility>

namespace ns3 {
namespace ndn {

class RateLimiter {
public:
    /**
     * @param maxIncrPerWindow  Threshold (default 10 increments).
     * @param windowSeconds     Sliding window duration (default 60 s).
     */
    explicit RateLimiter(uint32_t maxIncrPerWindow = 10,
                         uint32_t windowSeconds    = 60);

    /**
     * @brief Algorithm 3: check and update the sliding-window counter.
     *
     * @param contentName  Content name.
     * @param ph           In/out: if the threshold is exceeded, PH is
     *                     reset to its previous value (clamped).
     * @return             true if the PH was clamped (threshold exceeded).
     */
    bool checkAndUpdate(const ::ndn::Name& contentName, uint8_t& ph);

    void   clear();
    size_t size() const { return m_windows.size(); }

private:
    struct Window {
        std::deque<uint64_t> timestamps;  // ms since epoch
        uint8_t lastPh = 0;
    };

    uint64_t nowMs() const;

private:
    uint32_t m_maxIncrPerWindow;
    uint64_t m_windowMs;   // window in milliseconds
    std::map<::ndn::Name, Window> m_windows;
};

} // namespace ndn
} // namespace ns3

#endif // CACC_SECURE_RATE_LIMITER_HPP