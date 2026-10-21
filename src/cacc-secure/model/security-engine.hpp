// security-engine.hpp
//
// Algorithm 1: HMAC Integrity Verification.
//
// Computes Truncate(HMAC-SHA256(K, PH || RHC || SEQN || ContentName), 4)
// and compares it with the received HMAC.

#ifndef CACC_SECURE_SECURITY_ENGINE_HPP
#define CACC_SECURE_SECURITY_ENGINE_HPP

#include <ndn-cxx/name.hpp>
#include <cstdint>
#include <string>

namespace ns3 {
namespace ndn {

class SecurityEngine {
public:
    explicit SecurityEngine(const std::string& key);

    /**
     * @brief Algorithm 1: compute the truncated HMAC.
     * @param contentName  NDN name of the content object.
     * @param ph           Popularity Hint.
     * @param rhc          Retrieval Hop Count.
     * @param seqn         Sequence Number.
     * @return             First 4 bytes of HMAC-SHA256 as uint32_t (big-endian).
     */
    uint32_t computeHmac(const ::ndn::Name& contentName,
                         uint8_t ph, uint8_t rhc, uint8_t seqn) const;

    /**
     * @brief Algorithm 1: full verification (compute + compare).
     * @return true if the received HMAC matches.
     */
    bool verify(const ::ndn::Name& contentName,
                uint8_t ph, uint8_t rhc, uint8_t seqn,
                uint32_t receivedHmac) const;

private:
    std::string m_key;
};

} // namespace ndn
} // namespace ns3

#endif // CACC_SECURE_SECURITY_ENGINE_HPP