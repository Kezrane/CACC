#include "seq-cache.hpp"

namespace ns3 {
namespace ndn {

SeqCache::SeqCache(size_t maxTrackedEntries)
    : m_maxTrackedEntries(maxTrackedEntries) {}

bool SeqCache::validateSequence(const ::ndn::Name& contentName, uint8_t incomingSeq) {
    auto it = m_seqTable.find(contentName);

    if (it != m_seqTable.end()) {
        // Entry is present: check for strict monotonic progression
        uint8_t lastKnownSeq = it->second;

        // Account for standard 8-bit unsigned integer wrap-around bounds
        if (incomingSeq <= lastKnownSeq && !(lastKnownSeq > 240 && incomingSeq < 15)) {
            // Replay state caught: incoming index is stale or cloned
            return false;
        }

        // Fresh index confirmed: update state tracking
        m_seqTable[contentName] = incomingSeq;

        // Move entry to the top of the LRU tracking queue
        m_lruTracker.erase(m_lruMap[contentName]);
        m_lruTracker.push_front(contentName);
        m_lruMap[contentName] = m_lruTracker.begin();
        
        return true;
    }

    // New prefix entry initialization
    if (m_seqTable.size() >= m_maxTrackedEntries) {
        evictOldest();
    }

    m_seqTable[contentName] = incomingSeq;
    m_lruTracker.push_front(contentName);
    m_lruMap[contentName] = m_lruTracker.begin();

    return true;
}

void SeqCache::evictOldest() {
    if (m_lruTracker.empty()) return;

    // Identify and remove least recently used key
    ::ndn::Name oldestKey = m_lruTracker.back();
    
    m_seqTable.erase(oldestKey);
    m_lruMap.erase(oldestKey);
    m_lruTracker.pop_back();
}

void SeqCache::clear() {
    m_seqTable.clear();
    m_lruTracker.clear();
    m_lruMap.clear();
}

} // namespace ndn
} // namespace ns3