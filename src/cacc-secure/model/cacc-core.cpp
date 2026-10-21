// cacc-core.cpp
//
// Implementation of Equation (1) and Algorithm 5 (CACC Core Caching).

#include "cacc-core.hpp"

#include <ns3/log.h>

#include <random>

namespace ns3 {
namespace ndn {

NS_LOG_COMPONENT_DEFINE("CaccSecureCaccCore");

// ===========================================================================
// Construction
// ===========================================================================
CaccCore::CaccCore(double alpha, uint8_t maxHops)
    : m_alpha(alpha),
      m_maxHops(maxHops)
{
    NS_LOG_FUNCTION(this << alpha << static_cast<int>(maxHops));
    if (alpha < 0.0 || alpha > 1.0) {
        NS_LOG_WARN("CaccCore: alpha outside [0,1], clamping");
        m_alpha = std::max(0.0, std::min(1.0, alpha));
    }
}

// ===========================================================================
// Equation (1): P(PH, RHC)
// ===========================================================================
double
CaccCore::probability(double phEff, double rhcEff) const
{
    // 1. Popularity term: 1 - 1/(PH_eff + 2)
    const double popularityComponent = 1.0 - (1.0 / (phEff + 2.0));

    // 2. Locality term: RHC_eff / (H_max + 1)
    const double localityComponent =
        rhcEff / (static_cast<double>(m_maxHops) + 1.0);

    // 3. Weighted sum
    const double p = m_alpha * popularityComponent
                   + (1.0 - m_alpha) * localityComponent;

    // Clamp to [0, 1] for numerical safety
    return std::max(0.0, std::min(1.0, p));
}

// ===========================================================================
// Algorithm 5: CACC Core Caching Decision
// ===========================================================================
// Require: Effective PH, Effective RHC
// Ensure: Cache or Forward decision
// 1: RHC_effective <- RHC_effective + 1 (increment for this hop)
// 2: P <- alpha * (1 - 1/(PH_effective + 2))
//           + (1 - alpha) * (RHC_effective / (H_max + 1))
// 3: r <- random(0, 1)
// 4: if r <= P then
// 5:    cache(DataPacket)
// 6: end if
// 7: forward(DataPacket)
// ===========================================================================
bool
CaccCore::decide(double phEff, double rhcEff)
{
    // 1. Increment RHC for the current hop
    const double rhcIncremented = rhcEff + 1.0;

    // 2. Compute P
    m_lastP = probability(phEff, rhcIncremented);

    // 3. Sample r ~ U(0, 1)
    static thread_local std::mt19937_64 rng(std::random_device{}());
    static thread_local std::uniform_real_distribution<double> dist(0.0, 1.0);
    m_lastR = dist(rng);

    // 4-6. Cache if r <= P
    const bool shouldCache = (m_lastR <= m_lastP);

    NS_LOG_DEBUG("CaccCore::decide: PH_eff=" << phEff
                 << " RHC_eff=" << rhcEff
                 << " RHC_inc=" << rhcIncremented
                 << " P=" << m_lastP
                 << " r=" << m_lastR
                 << " -> " << (shouldCache ? "CACHE" : "FORWARD"));

    return shouldCache;
}

} // namespace ndn
} // namespace ns3