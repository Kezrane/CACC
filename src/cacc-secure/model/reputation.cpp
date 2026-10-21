// reputation.cpp
//
// Implementation of Algorithm 4 (Reputation-Based Trust Weighting).

#include "reputation.hpp"

#include <ns3/log.h>

#include <algorithm>

namespace ns3 {
namespace ndn {

NS_LOG_COMPONENT_DEFINE("CaccSecureReputation");

// ===========================================================================
// Construction
// ===========================================================================
ReputationTable::ReputationTable(double initialTrust, double decayFactor)
    : m_initialTrust(initialTrust),
      m_decayFactor(decayFactor)
{
    NS_LOG_FUNCTION(this << initialTrust << decayFactor);
}

// ===========================================================================
// Algorithm 4, line 1: trust <- reputation_table[previous_hop]
// ===========================================================================
double
ReputationTable::getTrustScore(uint32_t neighborId) const
{
    auto it = m_scores.find(neighborId);
    if (it == m_scores.end()) {
        // Cold start: neutral trust
        return m_initialTrust;
    }
    return it->second;
}

// ===========================================================================
// Algorithm 4, lines 2-3 (implicit): update the trust score
// ===========================================================================
// Consistent behaviour  : score <- score * decay + (1 - decay) * 1
// Inconsistent behaviour: score <- score * decay
// The score is clamped to [0, 1].
// ===========================================================================
void
ReputationTable::update(uint32_t neighborId, bool consistent)
{
    double& score = m_scores[neighborId];
    if (score == 0.0 && m_scores.find(neighborId) == m_scores.end()) {
        score = m_initialTrust;
    }

    if (consistent) {
        score = score * m_decayFactor + (1.0 - m_decayFactor) * 1.0;
    } else {
        score = score * m_decayFactor;
    }

    score = std::max(0.0, std::min(1.0, score));

    NS_LOG_DEBUG("Reputation update: neighbor=" << neighborId
                 << " consistent=" << consistent
                 << " -> score=" << score);
}

} // namespace ndn
} // namespace ns3