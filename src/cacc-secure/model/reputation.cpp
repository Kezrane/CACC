#include "reputation.hpp"
#include <algorithm>

namespace ns3 {
namespace ndn {

Reputation::Reputation(double defaultTrust, double penaltyStep)
    : m_defaultTrust(defaultTrust), m_penaltyStep(penaltyStep) {}

double Reputation::getTrustScore(uint64_t faceId) {
    auto it = m_reputationTable.find(faceId);
    if (it == m_reputationTable.end()) {
        // First occurrence: initialize interface with baseline parameters
        m_reputationTable[faceId] = m_defaultTrust;
        return m_defaultTrust;
    }
    return it->second;
}

void Reputation::registerAnomaly(uint64_t faceId) {
    double currentScore = getTrustScore(faceId);
    
    // Deduct trust score while maintaining absolute floor boundary bounds
    m_reputationTable[faceId] = std::max(0.0, currentScore - m_penaltyStep);
}

void Reputation::applyTimeDecayRecovery() {
    // Standard gradual step-up recovery constant per evaluation era
    const double recoveryFactor = 0.02;

    for (auto& pair : m_reputationTable) {
        if (pair.second < m_defaultTrust) {
            pair.second = std::min(m_defaultTrust, pair.second + recoveryFactor);
        }
    }
}

void Reputation::reset() {
    m_reputationTable.clear();
}

} // namespace ndn
} // namespace ns3