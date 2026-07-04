#ifndef NDN_SIM_RATE_LIMITER_HPP
#define NDN_SIM_RATE_LIMITER_HPP

#include <ns3/core-module.h>
#include <ndn-cxx/name.hpp>
#include <map>
#include <queue>

namespace ns3 {
namespace ndn {

/**
 * @brief Sliding-window frequency tracking system to clamp malicious PH inflation.
 */
class RateLimiter {
public:
    /**
     * @param windowSize The history timeframe to evaluate arrival velocity (e.g., 1.0 second).
     * @param maxRequests Allowed threshold bounds before triggering mitigation logic.
     */
    RateLimiter(Time windowSize = Seconds(1.0), uint32_t maxRequests = 50);

    /**
     * @brief Evaluates arriving instances of a specific data prefix.
     * @param interestName The structural NDN name of the incoming content request.
     * @return true if frequency thresholds are respected, false if an inflation spike is caught.
     */
    bool validateFrequency(const ::ndn::Name& interestName);

    // Dynamic configuration adjustments
    void setWindowSize(Time windowSize) { m_windowSize = windowSize; }
    void setMaxRequests(uint32_t maxRequests) { m_maxRequests = maxRequests; }

    /**
     * @brief Purges expired history records to prevent state-table leakage.
     */
    void purgeExpiredRecords();

private:
    Time m_windowSize;
    uint32_t m_maxRequests;

    // Track timestamps for arrivals mapped per data prefix
    std::map<::ndn::Name, std::queue<Time>> m_prefixHistoryTable;
};

} // namespace ndn
} // namespace ns3

#endif // NDN_SIM_RATE_LIMITER_HPP