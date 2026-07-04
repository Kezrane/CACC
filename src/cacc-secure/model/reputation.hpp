#ifndef NDN_SIM_REPUTATION_HPP
#define NDN_SIM_REPUTATION_HPP

#include <ndn-cxx/face.hpp>
#include <map>
#include <cstdint>

namespace ns3 {
namespace ndn {

/**
 * @brief Dynamic reputation trust tracking system to isolate compromised neighborhood nodes.
 */
class Reputation {
public:
    /**
     * @param defaultTrust Baseline trust assigned to newly seen network interfaces.
     * @param penaltyStep Point deduction value applied when an anomaly is triggered.
     */
    Reputation(double defaultTrust = 1.0, double penaltyStep = 0.15);

    /**
     * @brief Fetches current normalized reputation score for a targeted node link.
     * @param faceId Unique systemic ID of the incoming router interface.
     * @return Trust score mapped within standard bounds [0.0, 1.0].
     */
    double getTrustScore(uint64_t faceId);

    /**
     * @brief Applies an explicit penalty deduction upon security breach detection.
     * @param faceId Unique systemic ID of the offending interface.
     */
    void registerAnomaly(uint64_t faceId);

    /**
     * @brief Gradually restores reputation scores over time to prevent permanent lockouts.
     */
    void applyTimeDecayRecovery();

    /**
     * @brief Completely resets the reputation state tables.
     */
    void reset();

private:
    double m_defaultTrust;
    double m_penaltyStep;

    // Table mapping Interface/Face IDs to absolute floating point trust values
    std::map<uint64_t, double> m_reputationTable;
};

} // namespace ndn
} // namespace ns3

#endif // NDN_SIM_REPUTATION_HPP