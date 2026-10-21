// reputation.hpp
//
// Algorithm 4: Reputation-Based Trust Weighting.
//
// Maintains a local trust score per neighbor. PH and RHC are weighted
// by the reputation of the previous hop before the caching decision.

#ifndef CACC_SECURE_REPUTATION_HPP
#define CACC_SECURE_REPUTATION_HPP

#include <cstdint>
#include <map>

namespace ns3 {
namespace ndn {

class ReputationTable {
public:
    explicit ReputationTable(double initialTrust = 0.5,
                             double decayFactor  = 0.9);

    /**
     * @brief Get the trust score of a neighbor (defaults to initialTrust).
     */
    double getTrustScore(uint32_t neighborId) const;

    /**
     * @brief Update the trust score of a neighbor.
     * @param neighborId  Neighbor identifier.
     * @param consistent  true if the neighbor behaved consistently,
     *                    false if it was flagged (HMAC failure, replay, ...).
     */
    void update(uint32_t neighborId, bool consistent);

    double initialTrust() const { return m_initialTrust; }

private:
    double m_initialTrust;
    double m_decayFactor;
    std::map<uint32_t, double> m_scores;
};

} // namespace ndn
} // namespace ns3

#endif // CACC_SECURE_REPUTATION_HPP