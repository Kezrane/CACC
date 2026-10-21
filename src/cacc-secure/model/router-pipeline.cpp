// router-pipeline.cpp
//
// Implementation of Algorithm 8 (Router-Side Processing) of the
// CACC-Secure protocol. See router-pipeline.hpp for the full pipeline
// description.

#include "router-pipeline.hpp"

#include <ns3/log.h>
#include <ns3/simulator.h>

#include <cstring>

namespace ns3 {
namespace ndn {

NS_LOG_COMPONENT_DEFINE("CaccSecureRouterPipeline");

// ===========================================================================
// Construction
// ===========================================================================
RouterPipeline::RouterPipeline(uint32_t nodeId,
                               const std::string& hmacKey,
                               size_t   maxTrackedEntries,
                               uint32_t maxRatePerWindow,
                               double   alpha,
                               uint8_t  maxHops)
    : m_nodeId(nodeId),
      m_security(hmacKey),                          // Alg. 1
      m_seqCache(maxTrackedEntries),                // Alg. 2
      m_rateLimiter(maxRatePerWindow, /*windowSec=*/60),  // Alg. 3
      m_reputation(),                               // Alg. 4
      m_caccCore(alpha, maxHops)                    // Eq. (1), Alg. 5
{
    NS_LOG_FUNCTION(this << nodeId);
    NS_LOG_INFO("RouterPipeline initialised on node " << nodeId
                << " (alpha=" << alpha
                << ", H_max=" << static_cast<int>(maxHops)
                << ", SEQN cache=" << maxTrackedEntries
                << ", rate threshold=" << maxRatePerWindow << "/60s)");
}

// ===========================================================================
// MODULE A: Header Parsing
// ===========================================================================
CaccHeader
RouterPipeline::parse(const uint8_t* rawHeader) const
{
    NS_LOG_FUNCTION(this << static_cast<const void*>(rawHeader));

    CaccHeader hdr;
    if (rawHeader == nullptr) {
        NS_LOG_WARN("parse(): null header, returning zeroed CaccHeader");
        return hdr;
    }

    // Layout: PH (1) | RHC (1) | SEQN (1) | HMAC (4, big-endian)
    hdr.ph   = rawHeader[0];
    hdr.rhc  = rawHeader[1];
    hdr.seqn = rawHeader[2];
    hdr.hmac = (static_cast<uint32_t>(rawHeader[3]) << 24) |
               (static_cast<uint32_t>(rawHeader[4]) << 16) |
               (static_cast<uint32_t>(rawHeader[5]) <<  8) |
               (static_cast<uint32_t>(rawHeader[6]));

    NS_LOG_DEBUG("parse(): PH=" << static_cast<int>(hdr.ph)
                 << " RHC=" << static_cast<int>(hdr.rhc)
                 << " SEQN=" << static_cast<int>(hdr.seqn)
                 << " HMAC=0x" << std::hex << hdr.hmac << std::dec);

    return hdr;
}

void
RouterPipeline::serialize(const CaccHeader& hdr, uint8_t* out7)
{
    if (out7 == nullptr) return;

    out7[0] = hdr.ph;
    out7[1] = hdr.rhc;
    out7[2] = hdr.seqn;
    out7[3] = static_cast<uint8_t>((hdr.hmac >> 24) & 0xFF);
    out7[4] = static_cast<uint8_t>((hdr.hmac >> 16) & 0xFF);
    out7[5] = static_cast<uint8_t>((hdr.hmac >>  8) & 0xFF);
    out7[6] = static_cast<uint8_t>((hdr.hmac      ) & 0xFF);
}

// ===========================================================================
// MODULE B.1: HMAC Integrity Verification (Algorithm 1)
// ===========================================================================
bool
RouterPipeline::verifyHmac(const ::ndn::Name& contentName,
                           const CaccHeader& hdr) const
{
    // Algorithm 1, line 1:
    //   computed = Truncate(HMAC-SHA256(K, PH || RHC || SEQN || ContentName), 4)
    const uint32_t computed = m_security.computeHmac(contentName,
                                                     hdr.ph,
                                                     hdr.rhc,
                                                     hdr.seqn);

    // Algorithm 1, lines 2-4: DROP if mismatch
    if (computed != hdr.hmac) {
        NS_LOG_DEBUG("HMAC mismatch for " << contentName
                     << " (computed=0x" << std::hex << computed
                     << ", received=0x" << hdr.hmac << std::dec << ")");
        return false;
    }
    return true;
}

// ===========================================================================
// MODULE B.2: Anti-Replay Verification (Algorithm 2)
// ===========================================================================
bool
RouterPipeline::verifyAntiReplay(const ::ndn::Name& contentName,
                                 uint8_t seqn)
{
    // Delegates to SeqCache::validateSequence(), which implements
    // Algorithm 2 verbatim (circular distance on 8-bit space).
    //
    //   diff = (SEQN - last + 256) mod 256
    //   diff == 0        -> DROP (duplicate)
    //   diff >  128      -> DROP (suspicious backward jump)
    //   1 <= diff <= 128 -> ACCEPT and update
    const bool ok = m_seqCache.validateSequence(contentName, seqn);
    if (!ok) {
        NS_LOG_DEBUG("Anti-replay DROP for " << contentName
                     << " (SEQN=" << static_cast<int>(seqn) << ")");
    }
    return ok;
}

// ===========================================================================
// MODULE B.3: Rate Limiting for PH Inflation (Algorithm 3)
// ===========================================================================
bool
RouterPipeline::applyRateLimiter(const ::ndn::Name& contentName,
                                 uint8_t& ph /* in/out */)
{
    // Algorithm 3:
    //   window_count = rate_counter[ContentName].count_in_last_60s
    //   if window_count >= MAX_INCR_PER_WINDOW (10):
    //       PH <- previous_PH (clamp)
    //   else:
    //       rate_counter[ContentName] += 1
    const bool clamped = m_rateLimiter.checkAndUpdate(contentName, ph);
    if (clamped) {
        NS_LOG_DEBUG("Rate limiter clamped PH for " << contentName
                     << " (PH kept at " << static_cast<int>(ph) << ")");
    }
    return !clamped;   // true = not clamped (continue), false = clamped
}

// ===========================================================================
// MODULE B.4: Reputation-Based Trust Weighting (Algorithm 4)
// ===========================================================================
void
RouterPipeline::applyReputation(uint32_t prevHopId,
                                double& phEff /* in/out */,
                                double& rhcEff /* in/out */)
{
    // Algorithm 4:
    //   trust <- reputation_table[previous_hop]
    //   PH_effective  <- PH  * trust
    //   RHC_effective <- RHC * trust
    const double trust = m_reputation.getTrustScore(prevHopId);

    phEff  = phEff  * trust;
    rhcEff = rhcEff * trust;

    NS_LOG_DEBUG("Reputation: hop=" << prevHopId
                 << " trust=" << trust
                 << " -> PH_eff=" << phEff
                 << " RHC_eff=" << rhcEff);
}

// ===========================================================================
// MODULE D: Local State Update
// ===========================================================================
void
RouterPipeline::updateState(uint32_t prevHopId, bool consistent)
{
    // Algorithm 8, line 25:
    //   update_reputation(previous_hop, consistency_check)
    m_reputation.update(prevHopId, consistent);
}

// ===========================================================================
// MAIN PIPELINE (Algorithm 8)
// ===========================================================================
PipelineDecision
RouterPipeline::process(const ::ndn::Name& contentName,
                        const CaccHeader& hdr,
                        uint32_t prevHopId)
{
    NS_LOG_FUNCTION(this << contentName << static_cast<int>(hdr.seqn)
                    << prevHopId);

    ++m_stats.totalPackets;

    // -----------------------------------------------------------------------
    // MODULE B.1: HMAC Integrity Verification (Algorithm 1)
    // -----------------------------------------------------------------------
    if (!verifyHmac(contentName, hdr)) {
        ++m_stats.droppedTampering;
        updateState(prevHopId, /*consistent=*/false);
        return PipelineDecision::DROP_TAMPERING;
    }

    // -----------------------------------------------------------------------
    // MODULE B.2: Anti-Replay Verification (Algorithm 2)
    // -----------------------------------------------------------------------
    if (!verifyAntiReplay(contentName, hdr.seqn)) {
        ++m_stats.droppedReplay;
        updateState(prevHopId, /*consistent=*/false);
        return PipelineDecision::DROP_REPLAY;
    }

    // -----------------------------------------------------------------------
    // MODULE B.3: Rate Limiting for PH Inflation (Algorithm 3)
    // -----------------------------------------------------------------------
    uint8_t effectivePh = hdr.ph;   // may be clamped in-place
    const bool rateOk = applyRateLimiter(contentName, effectivePh);
    if (!rateOk) {
        ++m_stats.rateLimited;
        // Note: Algorithm 8 does NOT drop on rate limiting; it clamps PH
        // and continues. We therefore do not return here.
    }

    // -----------------------------------------------------------------------
    // MODULE B.4: Reputation-Based Trust (Algorithm 4)
    // -----------------------------------------------------------------------
    double phEff  = static_cast<double>(effectivePh);
    double rhcEff = static_cast<double>(hdr.rhc);
    applyReputation(prevHopId, phEff, rhcEff);

    // -----------------------------------------------------------------------
    // MODULE C: CACC Core Caching (Equation 1, Algorithm 5)
    // -----------------------------------------------------------------------
    // Algorithm 5 increments RHC_effective for the current hop, then
    // computes P and samples a uniform random variable r.
    const bool shouldCache = m_caccCore.decide(phEff, rhcEff);

    // -----------------------------------------------------------------------
    // MODULE D: Local State Update
    // -----------------------------------------------------------------------
    // The packet has passed all security checks; the reputation of the
    // previous hop is reinforced.
    updateState(prevHopId, /*consistent=*/true);

    // -----------------------------------------------------------------------
    // Final decision
    // -----------------------------------------------------------------------
    if (shouldCache) {
        ++m_stats.cached;
        ++m_stats.forwarded;   // cached packets are also forwarded
        NS_LOG_DEBUG("DECISION: CACHE_AND_FORWARD for " << contentName
                     << " (P=" << m_caccCore.lastProbability()
                     << ", r=" << m_caccCore.lastRandom() << ")");
        return PipelineDecision::CACHE_AND_FORWARD;
    }

    ++m_stats.forwarded;
    NS_LOG_DEBUG("DECISION: FORWARD_ONLY for " << contentName
                 << " (P=" << m_caccCore.lastProbability()
                 << ", r=" << m_caccCore.lastRandom() << ")");
    return PipelineDecision::FORWARD_ONLY;
}

} // namespace ndn
} // namespace ns3