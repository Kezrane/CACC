#include "rate-limiter.hpp"

namespace ns3 {
namespace ndn {

RateLimiter::RateLimiter(Time windowSize, uint32_t maxRequests)
    : m_windowSize(windowSize), m_maxRequests(maxRequests) {}

bool RateLimiter::validateFrequency(const ::ndn::Name& interestName) {
    Time currentTime = Simulator::Now();
    Time boundaryLimit = currentTime - m_windowSize;

    // Fetch or instantiate history log queue for current prefix path
    auto& historyQueue = m_prefixHistoryTable[interestName];

    // Evict all entry milestones falling completely outside our tracking window
    while (!historyQueue.empty() && historyQueue.front() < boundaryLimit) {
        historyQueue.pop();
    }

    // Evaluate window density bounds against configuration ceilings
    if (historyQueue.size() >= m_maxRequests) {
        // Threshold breached: suppress update to protect the core cache metrics
        return false; 
    }

    // Everything is stable; commit current packet timestamp to history queue
    historyQueue.push(currentTime);
    return true;
}

void RateLimiter::purgeExpiredRecords() {
    Time boundaryLimit = Simulator::Now() - m_windowSize;
    auto it = m_prefixHistoryTable.begin();

    while (it != m_prefixHistoryTable.end()) {
        auto& historyQueue = it->second;
        
        while (!historyQueue.empty() && historyQueue.front() < boundaryLimit) {
            historyQueue.pop();
        }

        if (historyQueue.empty()) {
            it = m_prefixHistoryTable.erase(it);
        } else {
            ++it;
        }
    }
}

} // namespace ndn
} // namespace ns3