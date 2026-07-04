#include "cacc-core.cpp"
#include <ns3/log.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <cstdlib>
#include <cmath>

NS_LOG_COMPONENT_DEFINE("ndn.CaccCore");

namespace ns3 {
namespace ndn {

CaccCore::CaccCore(double alpha, uint8_t maxHops, const std::string& secretKey)
    : m_alpha(alpha), m_maxHops(maxHops), m_secretKey(secretKey),
      m_rateLimiter(Seconds(1.0), 50), m_seqCache(5000), m_reputation(1.0, 0.15) {}

uint32_t CaccCore::calculateHmac(const ::ndn::Name& name, uint8_t ph, uint8_t ohc, uint8_t seq) {
    std::string nameStr = name.toUri();
    
    // Assemble the contiguous byte stream for validation
    std::vector<uint8_t> buffer(nameStr.begin(), nameStr.end());
    buffer.push_back(ph);
    buffer.push_back(ohc);
    buffer.push_back(seq);

    unsigned int mdLen = 0;
    uint8_t md[EVP_MAX_MD_SIZE];

    // Compute HMAC-SHA256 signature using OpenSSL functions
    HMAC(EVP_sha256(), 
         m_secretKey.c_str(), m_secretKey.length(), 
         buffer.data(), buffer.size(), 
         md, &mdLen);

    if (mdLen < 4) return 0;

    // Truncate signature to a 4-byte big-endian unsigned integer boundary
    uint32_t truncatedHmac = (static_cast<uint32_t>(md[0]) << 24) |
                             (static_cast<uint32_t>(md[1]) << 16) |
                             (static_cast<uint32_t>(md[2]) << 8)  |
                             (static_cast<uint32_t>(md[3]));

    return truncatedHmac;
}

bool CaccCore::verifyAndProcessIncomingData(const ::ndn::Data& data, uint64_t faceId) {
    try {
        // Find and extract the embedded CaccHeader block within the Data packet
        auto caccBlock = data.getContext<CaccHeader>();
        if (!caccBlock) {
            NS_LOG_WARN("Packet missing necessary CaccHeader structural block. Rejecting.");
            return false;
        }

        const ::ndn::Name& contentName = data.getName();

        // Layer 1: HMAC-Based Metadata Integrity Validation
        uint32_t calculatedSign = calculateHmac(contentName, caccBlock->getPh(), caccBlock->getOhc(), caccBlock->getSeq());
        if ((calculatedSign & 0xFFFFFF) != caccBlock->getHmac()) {
            NS_LOG_WARN("HMAC validation integrity fault discovered from Face ID: " << faceId);
            m_reputation.registerAnomaly(faceId);
            return false;
        }

        // Layer 2: Sequence Number Anti-Replay Validation
        if (!m_seqCache.validateSequence(contentName, caccBlock->getSeq())) {
            NS_LOG_WARN("Sequence anti-replay mechanism caught stale tracking update from Face ID: " << faceId);
            m_reputation.registerAnomaly(faceId);
            return false;
        }

        // Layer 3: Sliding-Window Counter Rate Limiting
        if (!m_rateLimiter.validateFrequency(contentName)) {
            NS_LOG_WARN("Rate limiting capacity ceiling triggered for prefix pattern from Face ID: " << faceId);
            // Rate limiters handle load; do not apply hard trust penalties immediately
            return false;
        }

        return true;
    } 
    catch (const std::exception& e) {
        NS_LOG_ERROR("Exception occurred during CaccCore metadata parsing logic: " << e.what());
        return false;
    }
}

bool CaccCore::shouldCache(uint8_t ph, uint8_t ohc, uint64_t faceId) {
    // Layer 4: Extract current reputation weight modifier
    double trustScale = m_reputation.getTrustScore(faceId);

    // Apply trust adjustment to the raw Popularity Hint metric
    double adjustedPh = static_cast<double>(ph) * trustScale;

    // Mathematical formulation mapping:
    // P = alpha * (1 - 1/(PH + 2)) + (1 - alpha) * (1 - OHC/(H_max + 1))
    double popularityComponent = 1.0 - (1.0 / (adjustedPh + 2.0));
    double localityComponent = 1.0 - (static_cast<double>(ohc) / (static_cast<double>(m_maxHops) + 1.0));

    double cachingProbability = (m_alpha * popularityComponent) + ((1.0 - m_alpha) * localityComponent);

    // Generate a uniform random evaluation boundary between [0.0, 1.0]
    double randomSample = static_cast<double>(std::rand()) / static_cast<double>(RAND_MAX);

    return randomSample <= cachingProbability;
}

} // namespace ndn
} // namespace ns3