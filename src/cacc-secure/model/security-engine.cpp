// security-engine.cpp
//
// Implementation of Algorithm 1 (HMAC Integrity Verification).
// Uses OpenSSL's HMAC-SHA256 as the underlying primitive.

#include "security-engine.hpp"

#include <ns3/log.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#include <vector>
#include <sstream>
#include <cstring>

namespace ns3 {
namespace ndn {

NS_LOG_COMPONENT_DEFINE("CaccSecureSecurityEngine");

// ===========================================================================
// Construction
// ===========================================================================
SecurityEngine::SecurityEngine(const std::string& key)
    : m_key(key)
{
    NS_LOG_FUNCTION(this << "key length=" << key.size());
    if (key.empty()) {
        NS_LOG_WARN("SecurityEngine: empty HMAC key, all verifications will fail");
    }
}

// ===========================================================================
// Algorithm 1: compute the truncated HMAC
// ===========================================================================
// Require: PH, RHC, SEQN, ContentName, Secret key K
// 1: computed_hmac <- Truncate(HMAC-SHA256(K, PH || RHC || SEQN || ContentName), 4)
// 2: return computed_hmac
// ===========================================================================
uint32_t
SecurityEngine::computeHmac(const ::ndn::Name& contentName,
                            uint8_t ph, uint8_t rhc, uint8_t seqn) const
{
    // 1. Build the input buffer: PH || RHC || SEQN || ContentName
    std::vector<uint8_t> buffer;
    buffer.reserve(3 + contentName.size() + 8);
    buffer.push_back(ph);
    buffer.push_back(rhc);
    buffer.push_back(seqn);

    // Append ContentName as a URI string (deterministic, matches ndn-cxx)
    const std::string nameStr = contentName.toUri();
    buffer.insert(buffer.end(), nameStr.begin(), nameStr.end());

    // 2. Compute HMAC-SHA256 over the buffer using the pre-shared key
    unsigned int hmacLen = 0;
    unsigned char hmacOut[EVP_MAX_MD_SIZE];

    const unsigned char* result = HMAC(
        EVP_sha256(),
        m_key.data(), static_cast<int>(m_key.size()),
        buffer.data(), buffer.size(),
        hmacOut, &hmacLen);

    if (result == nullptr) {
        NS_LOG_ERROR("HMAC computation failed");
        return 0;
    }

    // 3. Truncate to the first 4 bytes, interpreted as big-endian uint32_t
    if (hmacLen < 4) {
        NS_LOG_ERROR("HMAC output shorter than 4 bytes");
        return 0;
    }

    const uint32_t truncated =
        (static_cast<uint32_t>(hmacOut[0]) << 24) |
        (static_cast<uint32_t>(hmacOut[1]) << 16) |
        (static_cast<uint32_t>(hmacOut[2]) <<  8) |
        (static_cast<uint32_t>(hmacOut[3]));

    NS_LOG_DEBUG("computeHmac: name=" << contentName.toUri()
                 << " PH=" << static_cast<int>(ph)
                 << " RHC=" << static_cast<int>(rhc)
                 << " SEQN=" << static_cast<int>(seqn)
                 << " -> 0x" << std::hex << truncated << std::dec);

    return truncated;
}

// ===========================================================================
// Algorithm 1: full verification
// ===========================================================================
// Require: Data packet with metadata (PH, RHC, SEQN, HMAC_received), key K
// Ensure: Valid or DROP
// 1: computed_hmac <- Truncate(HMAC-SHA256(K, PH || RHC || SEQN || ContentName), 4)
// 2: if computed_hmac != HMAC_received then
// 3:    DROP packet (tampering detected)
// 4: end if
// 5: Pass to anti-replay check
// ===========================================================================
bool
SecurityEngine::verify(const ::ndn::Name& contentName,
                       uint8_t ph, uint8_t rhc, uint8_t seqn,
                       uint32_t receivedHmac) const
{
    const uint32_t computed = computeHmac(contentName, ph, rhc, seqn);
    if (computed != receivedHmac) {
        NS_LOG_DEBUG("verify: HMAC mismatch for " << contentName.toUri()
                     << " (computed=0x" << std::hex << computed
                     << ", received=0x" << receivedHmac << std::dec << ")");
        return false;
    }
    return true;
}

} // namespace ndn
} // namespace ns3