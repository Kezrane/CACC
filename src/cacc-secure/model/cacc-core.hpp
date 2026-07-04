#ifndef NDN_SIM_CACC_CORE_HPP
#define NDN_SIM_CACC_CORE_HPP

#include "cacc-header.hpp"
#include "rate-limiter.hpp"
#include "seq-cache.hpp"
#include "reputation.hpp"

#include <ndn-cxx/data.hpp>
#include <ns3/core-module.h>
#include <string>

namespace ns3 {
namespace ndn {

/**
 * @brief Main engine coordinating security validations and probabilistic caching calculations.
 */
class CaccCore {
public:
    /**
     * @param alpha Weighted probability bias balancing Popularity Hint vs. Locality [0.0, 1.0].
     * @param maxHops Expected operational network diameter bound.
     * @param secretKey Cryptographic key sequence utilized for local HMAC verification.
     */
    CaccCore(double alpha = 0.5, uint8_t maxHops = 16, const std::string& secretKey = "CACC_SECRET");

    /**
     * @brief Processes an incoming Data packet, applying the 4 security layers.
     * @param data The incoming NDN Data packet containing the CaccHeader.
     * @param faceId The incoming face interface ID from which the packet was received.
     * @return true if the packet successfully passes all security checks.
     */
    bool verifyAndProcessIncomingData(const ::ndn::Data& data, uint64_t faceId);

    /**
     * @brief Computes the CACC core probabilistic caching decision.
     * @param ph Extracted Popularity Hint value.
     * @param ohc Extracted Origin Hop-Count value.
     * @param faceId The interface ID used to apply reputation discounting.
     * @return true if the calculated random boundary triggers a cache decision.
     */
    bool shouldCache(uint8_t ph, uint8_t ohc, uint64_t faceId);

    // Maintenance handles for the security subsystems
    RateLimiter& getRateLimiter() { return m_rateLimiter; }
    SeqCache& getSeqCache() { return m_seqCache; }
    Reputation& getReputation() { return m_reputation; }

private:
    /**
     * @brief Computes a local truncated HMAC signature for validation.
     */
    uint32_t calculateHmac(const ::ndn::Name& name, uint8_t ph, uint8_t ohc, uint8_t seq);

private:
    double m_alpha;
    uint8_t m_maxHops;
    std::string m_secretKey;

    // Security subsystems integration
    RateLimiter m_rateLimiter;
    SeqCache m_seqCache;
    Reputation m_reputation;
};

} // namespace ndn
} // namespace ns3

#endif // NDN_SIM_CACC_CORE_HPP