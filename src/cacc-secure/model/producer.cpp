// producer.cpp
//
// Implementation of Algorithm 6 (Producer-Side Processing).

#include "producer.hpp"

#include <ns3/log.h>

namespace ns3 {
namespace ndn {

NS_LOG_COMPONENT_DEFINE("CaccSecureProducer");

Producer::Producer(const std::string& hmacKey)
    : m_security(hmacKey)
{
    NS_LOG_FUNCTION(this);
}

// ===========================================================================
// Algorithm 6: Producer-Side Processing
// ===========================================================================
// Require: ContentName, Secret Key K
// Ensure: Data packet with CACC-Secure header
// 1: PH <- 0
// 2: RHC <- 0
// 3: SEQN <- global_seq_counter[ContentName] + 1
// 4: global_seq_counter[ContentName] <- SEQN
// 5: HMAC <- Truncate(HMAC-SHA256(K, PH || RHC || SEQN || ContentName), 4)
// 6: return DataPacket(PH, RHC, SEQN, HMAC, Content)
// ===========================================================================
CaccHeader
Producer::createHeader(const ::ndn::Name& contentName)
{
    CaccHeader hdr;

    // 1-2. PH = 0, RHC = 0
    hdr.ph  = 0;
    hdr.rhc = 0;

    // 3-4. Monotonic SEQN per content
    hdr.seqn = nextSeqn(contentName);

    // 5. Compute HMAC
    hdr.hmac = m_security.computeHmac(contentName, hdr.ph, hdr.rhc, hdr.seqn);

    NS_LOG_DEBUG("Producer::createHeader: " << contentName.toUri()
                 << " PH=" << static_cast<int>(hdr.ph)
                 << " RHC=" << static_cast<int>(hdr.rhc)
                 << " SEQN=" << static_cast<int>(hdr.seqn)
                 << " HMAC=0x" << std::hex << hdr.hmac << std::dec);

    return hdr;
}

uint8_t
Producer::nextSeqn(const ::ndn::Name& contentName)
{
    // 8-bit wraparound is intentional (circular SEQN space)
    uint8_t& seqn = m_globalSeqn[contentName];
    seqn = static_cast<uint8_t>((seqn + 1) & 0xFF);
    return seqn;
}

uint8_t
Producer::currentSeqn(const ::ndn::Name& contentName) const
{
    auto it = m_globalSeqn.find(contentName);
    return (it == m_globalSeqn.end()) ? 0 : it->second;
}

} // namespace ndn
} // namespace ns3