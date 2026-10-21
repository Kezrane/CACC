// router-pipeline.hpp
//
// Algorithm 8: Router-Side Processing
//
// This class implements the complete CACC-Secure decision pipeline that
// every Data packet must traverse at each NDN router:
//
//   MODULE A: Header Parsing
//   MODULE B: Security Verification
//             B.1 HMAC integrity        (Algorithm 1)
//             B.2 Anti-replay (circular SEQN) (Algorithm 2)
//             B.3 Rate limiting         (Algorithm 3)
//             B.4 Reputation weighting  (Algorithm 4)
//   MODULE C: CACC Core Caching       (Equation 1, Algorithm 5)
//   MODULE D: Local State Update
//
// The pipeline is stateless with respect to other nodes: all decisions
// are made locally from the in-packet metadata (PH, RHC, SEQN, HMAC)
// and the local state tables (SEQN cache, rate limiter, reputation
// table). No control-plane signalling is required.

#ifndef CACC_SECURE_ROUTER_PIPELINE_HPP
#define CACC_SECURE_ROUTER_PIPELINE_HPP

#include "seq-cache.hpp"
#include "security-engine.hpp"
#include "rate-limiter.hpp"
#include "reputation.hpp"
#include "cacc-core.hpp"

#include <ndn-cxx/name.hpp>
#include <cstdint>
#include <string>

namespace ns3 {
namespace ndn {

/**
 * @brief Parsed metadata extracted from the 7-byte CACC-Secure header.
 *
 * Layout (see Figure 2 of the manuscript):
 *   byte 0     : PH     (1 byte)
 *   byte 1     : RHC    (1 byte)
 *   byte 2     : SEQN   (1 byte)
 *   bytes 3-6  : HMAC   (4 bytes, truncated HMAC-SHA256)
 */
struct CaccHeader {
    uint8_t  ph;        // Popularity Hint
    uint8_t  rhc;       // Retrieval Hop Count
    uint8_t  seqn;      // Sequence Number
    uint32_t hmac;      // 4-byte truncated HMAC

    CaccHeader() : ph(0), rhc(0), seqn(0), hmac(0) {}
};

/**
 * @brief Outcome of the router-side pipeline for a single Data packet.
 */
enum class PipelineDecision {
    FORWARD_ONLY,   // packet forwarded, not cached
    CACHE_AND_FORWARD,
    DROP_TAMPERING, // HMAC mismatch
    DROP_REPLAY,    // SEQN duplicate or backward jump
    DROP_RATE,      // rate limiter clamped (not a drop in Alg. 8, but
                    // exposed for diagnostics)
};

/**
 * @brief Diagnostic counters, updated after each process() call.
 *        Useful for Table 6 / Table 7 of the manuscript.
 */
struct PipelineStats {
    uint64_t totalPackets      = 0;
    uint64_t forwarded         = 0;
    uint64_t cached            = 0;
    uint64_t droppedTampering  = 0;
    uint64_t droppedReplay     = 0;
    uint64_t rateLimited       = 0;

    void reset() { *this = PipelineStats(); }
};

/**
 * @brief Complete CACC-Secure router-side pipeline (Algorithm 8).
 *
 * Usage (inside an ndnSIM forwarding strategy or a custom NetDevice):
 *
 *   RouterPipeline pipeline(/*nodeId=* /1);
 *   CaccHeader hdr = pipeline.parse(rawPacket);
 *   PipelineDecision d = pipeline.process(contentName, hdr, prevHopFaceId);
 *   if (d == PipelineDecision::CACHE_AND_FORWARD) { ... cache ... }
 *   ... forward ...
 */
class RouterPipeline {
public:
    /**
     * @param nodeId             Identifier of this router (for logs).
     * @param hmacKey            Pre-shared symmetric key K (16/32 bytes).
     * @param maxTrackedEntries  Size of the SEQN LRU cache (default 1000).
     * @param maxRatePerWindow   Rate-limiter threshold (default 10 inc/60s).
     * @param alpha              CACC core balance parameter (default 0.6).
     * @param maxHops            Network diameter H_max (default 20).
     */
    RouterPipeline(uint32_t nodeId,
                   const std::string& hmacKey,
                   size_t   maxTrackedEntries = 1000,
                   uint32_t maxRatePerWindow  = 10,
                   double   alpha             = 0.6,
                   uint8_t  maxHops           = 20);

    // -----------------------------------------------------------------------
    // MODULE A: Header Parsing
    // -----------------------------------------------------------------------
    /**
     * @brief Extract the 7-byte CACC-Secure header from the raw payload.
     * @param rawHeader  Pointer to the first byte of the header.
     * @return Parsed CaccHeader { PH, RHC, SEQN, HMAC }.
     */
    CaccHeader parse(const uint8_t* rawHeader) const;

    /**
     * @brief Serialize a CaccHeader back into its 7-byte representation.
     *        Used by Producer (Alg. 6) and Cache-Response (Alg. 7).
     */
    static void serialize(const CaccHeader& hdr, uint8_t* out7);

    // -----------------------------------------------------------------------
    // MODULE B + C + D: Full pipeline
    // -----------------------------------------------------------------------
    /**
     * @brief Execute Algorithm 8 on a single Data packet.
     *
     * @param contentName  The NDN name of the content object.
     * @param hdr          Parsed metadata (from parse()).
     * @param prevHopId    Identifier of the previous hop (for reputation).
     * @return             PipelineDecision (forward / cache / drop).
     */
    PipelineDecision process(const ::ndn::Name& contentName,
                             const CaccHeader& hdr,
                             uint32_t prevHopId);

    // -----------------------------------------------------------------------
    // Accessors (for simulations and tests)
    // -----------------------------------------------------------------------
    const PipelineStats& stats() const { return m_stats; }
    void resetStats() { m_stats.reset(); }

    SeqCache&       seqCache()       { return m_seqCache; }
    SecurityEngine& securityEngine() { return m_security; }
    RateLimiter&    rateLimiter()    { return m_rateLimiter; }
    ReputationTable& reputation()    { return m_reputation; }
    CaccCore&       caccCore()       { return m_caccCore; }

    uint32_t nodeId() const { return m_nodeId; }

private:
    // -----------------------------------------------------------------------
    // MODULE B: Security verification (returns true if packet survives)
    // -----------------------------------------------------------------------
    bool verifyHmac(const ::ndn::Name& contentName, const CaccHeader& hdr) const;
    bool verifyAntiReplay(const ::ndn::Name& contentName, uint8_t seqn);
    bool applyRateLimiter(const ::ndn::Name& contentName,
                          uint8_t& ph /* in/out */);

    // -----------------------------------------------------------------------
    // MODULE B.4: Reputation weighting
    // -----------------------------------------------------------------------
    void applyReputation(uint32_t prevHopId,
                         double& phEff /* in/out */,
                         double& rhcEff /* in/out */);

    // -----------------------------------------------------------------------
    // MODULE D: Local state update
    // -----------------------------------------------------------------------
    void updateState(uint32_t prevHopId, bool consistent);

private:
    uint32_t m_nodeId;

    // Sub-modules (each one implements its own algorithm)
    SecurityEngine  m_security;      // Alg. 1
    SeqCache        m_seqCache;      // Alg. 2
    RateLimiter     m_rateLimiter;   // Alg. 3
    ReputationTable m_reputation;    // Alg. 4
    CaccCore        m_caccCore;      // Eq. (1), Alg. 5

    PipelineStats m_stats;
};

} // namespace ndn
} // namespace ns3

#endif // CACC_SECURE_ROUTER_PIPELINE_HPP