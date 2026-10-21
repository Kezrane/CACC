// cacc-core.hpp
//
// Equation (1) and Algorithm 5: CACC Core Caching Decision.
//
// P = alpha * (1 - 1/(PH_eff + 2)) + (1 - alpha) * (RHC_eff / (H_max + 1))
//
// The engine increments RHC_eff for the current hop, computes P, samples
// a uniform random variable r, and caches if r <= P.

#ifndef CACC_SECURE_CACC_CORE_HPP
#define CACC_SECURE_CACC_CORE_HPP

#include <cstdint>

namespace ns3 {
namespace ndn {

class CaccCore {
public:
    explicit CaccCore(double alpha = 0.6, uint8_t maxHops = 20);

    /**
     * @brief Algorithm 5: increment RHC, compute P, sample r, decide.
     * @param phEff   Effective PH (weighted by reputation).
     * @param rhcEff  Effective RHC (weighted by reputation).
     * @return        true if the packet should be cached.
     */
    bool decide(double phEff, double rhcEff);

    /**
     * @brief Pure probability function (no random sampling).
     *        Exposed for tests and for the ablation study.
     */
    double probability(double phEff, double rhcEff) const;

    double  alpha()          const { return m_alpha; }
    uint8_t maxHops()        const { return m_maxHops; }
    double  lastProbability() const { return m_lastP; }
    double  lastRandom()     const { return m_lastR; }

private:
    double  m_alpha;
    uint8_t m_maxHops;
    double  m_lastP = 0.0;
    double  m_lastR = 0.0;
};

} // namespace ndn
} // namespace ns3

#endif // CACC_SECURE_CACC_CORE_HPP