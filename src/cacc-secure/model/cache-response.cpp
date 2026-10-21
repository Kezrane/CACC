// cache-response.cpp
//
// Implementation of Algorithm 7 (Cache Response Processing).

#include "cache-response.hpp"

#include <ns3/log.h>

namespace ns3 {
namespace ndn {

NS_LOG_COMPONENT_DEFINE("CaccSecureCacheResponse");

CacheResponse::CacheResponse(const std::string& hmacKey)
    : m_security(hmacKey)
{
    NS_LOG_FUNCTION(this);
}

// ===========================================================================
// Algorithm 7: Cache Response Processing
// ===========================================================================
// Require: Data Packet (from cache), Secret Key K
// Ensure: Updated Data Packet
// 1: PH <- DataPacket.PH + 1
// 2: RHC <- 0
// 3: SEQN <- DataPacket.SEQN + 1
// 4: HMAC <- Truncate(HMAC-SHA256(K, PH || RHC || SEQN || ContentName), 4)
// 5: DataPacket <- (PH, RHC, SEQN, HMAC)
// 6: return DataPacket
// ===========================================================================
CaccHeader
CacheResponse::updateHeader(const ::ndn::Name& contentName,
                            const CaccHeader& cached)
{
    CaccHeader hdr;

    // 1. PH <- cached.PH + 1 (8-bit wraparound is intentional)
    hdr.ph = static_cast<uint8_t>((cached.ph + 1) & 0xFF);

    // 2. RHC <- 0 (reset when served from cache)
    hdr.rhc = 0;

    // 3. SEQN <- cached.SEQN + 1 (8-bit wraparound is intentional)
    hdr.seqn = static_cast<uint8_t>((cached.seqn + 1) & 0xFF);

    // 4. Recompute HMAC over the new metadata
    hdr.hmac = m_security.computeHmac(contentName, hdr.ph, hdr.rhc, hdr.seqn);

    NS_LOG_DEBUG("CacheResponse::updateHeader: " << contentName.toUri()
                 << " PH " << static_cast<int>(cached.ph)
                 << " -> " << static_cast<int>(hdr.ph)
                 << " | RHC " << static_cast<int>(cached.rhc)
                 << " -> " << static_cast<int>(hdr.rhc)
                 << " | SEQN " << static_cast<int>(cached.seqn)
                 << " -> " << static_cast<int>(hdr.seqn));

    return hdr;
}

} // namespace ndn
} // namespace ns3