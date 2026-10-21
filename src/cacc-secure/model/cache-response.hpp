// cache-response.hpp
//
// Algorithm 7: Cache Response Processing.
//
// When a Data packet is served from an intermediate cache, the router
// increments PH and SEQN, resets RHC to 0, and recomputes the HMAC.

#ifndef CACC_SECURE_CACHE_RESPONSE_HPP
#define CACC_SECURE_CACHE_RESPONSE_HPP

#include "security-engine.hpp"
#include "router-pipeline.hpp"

#include <ndn-cxx/name.hpp>
#include <cstdint>

namespace ns3 {
namespace ndn {

class CacheResponse {
public:
    explicit CacheResponse(const std::string& hmacKey);

    /**
     * @brief Algorithm 7: update the header of a cached Data packet.
     * @param contentName  NDN name of the content object.
     * @param cached       Header of the cached packet (in).
     * @return             Updated header with fresh PH, SEQN, RHC=0, HMAC.
     */
    CaccHeader updateHeader(const ::ndn::Name& contentName,
                            const CaccHeader& cached);

private:
    SecurityEngine m_security;
};

} // namespace ndn
} // namespace ns3

#endif // CACC_SECURE_CACHE_RESPONSE_HPP