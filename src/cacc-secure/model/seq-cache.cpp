#include "seq-cache.hpp"

namespace ns3 {
namespace ndn {

SeqCache::SeqCache(size_t maxTrackedEntries)
    : m_maxTrackedEntries(maxTrackedEntries) {}

// ---------------------------------------------------------------------------
// Algorithm 2: Anti-Replay Verification (with circular SEQN handling)
//
// Require: SEQN from packet, SEQN Cache
// Ensure:  Valid or DROP
//
// 1: last_SEQN <- seqn_cache[ContentName]
// 2: if last_SEQN exists then
// 3:    diff <- (SEQN - last_SEQN + 256) mod 256
// 4:    if diff == 0 then
// 5:       DROP packet (duplicate)
// 6:    else if diff > 128 then
// 7:       DROP packet (suspicious backward jump)
// 8:    else
// 9:       seqn_cache[ContentName] <- SEQN
//10:       Pass to rate limiting check
//11:    end if
//12: else
//13:    seqn_cache[ContentName] <- SEQN
//14:    Pass to rate limiting check
//15: end if
// ---------------------------------------------------------------------------
bool SeqCache::validateSequence(const ::ndn::Name& contentName, uint8_t incomingSeq) {
    auto it = m_seqTable.find(contentName);

    if (it != m_seqTable.end()) {
        // --- Line 3: circular distance on 8-bit space ---
        const uint8_t  lastSeq = it->second;
        const uint16_t diff    = static_cast<uint16_t>(
                                     (static_cast<uint16_t>(incomingSeq)
                                    + SEQN_MODULUS
                                    - static_cast<uint16_t>(lastSeq))
                                    % SEQN_MODULUS);

        // --- Line 4-5: duplicate ---
        if (diff == 0) {
            return false;   // DROP: duplicate / replay
        }

        // --- Line 6-7: suspicious backward jump ---
        if (diff > SEQN_HALF_WIN) {
            return false;   // DROP: stale or maliciously rewound SEQN
        }

        // --- Line 8-10: fresh SEQN accepted (1 <= diff <= 128) ---
        m_seqTable[contentName] = incomingSeq;

        // Touch LRU: move to front (O(1))
        m_lruTracker.erase(m_lruMap[contentName]);
        m_lruTracker.push_front(contentName);
        m_lruMap[contentName] = m_lruTracker.begin();

        return true;
    }

    // --- Line 12-14: first time we see this content name ---
    if (m_seqTable.size() >= m_maxTrackedEntries) {
        evictOldest();
    }

    m_seqTable[contentName] = incomingSeq;
    m_lruTracker.push_front(contentName);
    m_lruMap[contentName] = m_lruTracker.begin();

    return true;
}

// ---------------------------------------------------------------------------
// LRU eviction (paper §3.5.2 mentions "aggressive key rotation (24 h) and
// appropriate cache sizing" to mitigate eviction-induced replay windows).
// ---------------------------------------------------------------------------
void SeqCache::evictOldest() {
    if (m_lruTracker.empty()) return;

    const ::ndn::Name oldestKey = m_lruTracker.back();

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