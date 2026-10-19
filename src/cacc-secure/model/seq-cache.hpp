#ifndef NDN_SIM_SEQ_CACHE_HPP
#define NDN_SIM_SEQ_CACHE_HPP

#include <ndn-cxx/name.hpp>
#include <map>
#include <list>
#include <cstdint>

namespace ns3 {
namespace ndn {

/**
 * @brief Anti-Replay Verification (SEQN Cache) as specified in
 *        Algorithm 2 of the CACC-Secure paper.
 *
 * Handles 8-bit circular sequence numbers (0..255) with a midpoint at 128:
 *   diff = (incomingSEQN - lastSEQN + 256) mod 256
 *   - diff == 0        -> duplicate, DROP
 *   - diff >  128      -> suspicious backward jump, DROP
 *   - 1 <= diff <= 128 -> fresh, ACCEPT and update
 *
 * A size-bounded LRU structure limits memory usage (default 1000 entries,
 * matching the paper's implementation section 4.2.2).
 */
class SeqCache {
public:
    /**
     * @param maxTrackedEntries Maximum number of unique content names kept.
     */
    explicit SeqCache(size_t maxTrackedEntries = 1000);

    /**
     * @brief Algorithm 2: Anti-Replay Verification with circular SEQN handling.
     * @param contentName The structural name identifier of the data chunk.
     * @param incomingSeq The 1-byte sequence number extracted from the header.
     * @return true if the SEQN is fresh (accepted), false if it must be dropped.
     */
    bool validateSequence(const ::ndn::Name& contentName, uint8_t incomingSeq);

    /**
     * @brief Clears out internal tracking tables completely.
     */
    void clear();

    /**
     * @brief Returns the currently tracked number of entries (for debugging).
     */
    size_t size() const { return m_seqTable.size(); }

private:
    /**
     * @brief Evicts the oldest element using an LRU policy.
     */
    void evictOldest();

private:
    static constexpr uint16_t SEQN_MODULUS   = 256;  // 2^8
    static constexpr uint16_t SEQN_HALF_WIN  = 128;  // midpoint

    size_t m_maxTrackedEntries;

    // last observed SEQN per content name
    std::map<::ndn::Name, uint8_t> m_seqTable;

    // LRU tracking list
    std::list<::ndn::Name> m_lruTracker;

    // O(1) handle into the LRU list for each name
    std::map<::ndn::Name, std::list<::ndn::Name>::iterator> m_lruMap;
};

} // namespace ndn
} // namespace ns3

#endif // NDN_SIM_SEQ_CACHE_HPP