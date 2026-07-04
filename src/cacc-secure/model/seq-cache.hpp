#ifndef NDN_SIM_SEQ_CACHE_HPP
#define NDN_SIM_SEQ_CACHE_HPP

#include <ndn-cxx/name.hpp>
#include <map>
#include <list>
#include <cstdint>

namespace ns3 {
namespace ndn {

/**
 * @brief State tracking container to defend against metadata replay attacks.
 * Uses a size-bounded structure to manage active sequence tracks.
 */
class SeqCache {
public:
    /**
     * @param maxTrackedEntries Maximum number of unique names to retain in memory.
     */
    SeqCache(size_t maxTrackedEntries = 5000);

    /**
     * @brief Validates incoming sequence sequence freshness.
     * @param contentName The structural name identifier of the data chunk.
     * @param incomingSeq The sequence number extracted from the 6-byte header.
     * @return true if sequence is strictly monotonically increasing (fresh), false if replayed.
     */
    bool validateSequence(const ::ndn::Name& contentName, uint8_t incomingSeq);

    /**
     * @brief Clears out internal tracking tables completely.
     */
    void clear();

private:
    /**
     * @brief Evicts the oldest element using an LRU policy to stay within limits.
     */
    void evictOldest();

private:
    size_t m_maxTrackedEntries;

    // Fast loop lookup structure for tracking current sequences
    std::map<::ndn::Name, uint8_t> m_seqTable;

    // Tracking list for managing cache eviction
    std::list<::ndn::Name> m_lruTracker;
    
    // Cross-referencing pointers to maintain O(1) removals during cache hits
    std::map<::ndn::Name, std::list<::ndn::Name>::iterator> m_lruMap;
};

} // namespace ndn
} // namespace ns3

#endif // NDN_SIM_SEQ_CACHE_HPP