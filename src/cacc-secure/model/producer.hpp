// producer.hpp
//
// Algorithm 6: Producer-Side Processing.
//
// Initializes a new Data packet with PH=0, RHC=0, a monotonic SEQN,
// and a valid HMAC.

#ifndef CACC_SECURE_PRODUCER_HPP
#define CACC_SECURE_PRODUCER_HPP

#include "security-engine.hpp"
#include "router-pipeline.hpp"

#include <ndn-cxx/name.hpp>
#include <cstdint>
#include <map>

namespace ns3 {
namespace ndn {

class Producer {
public:
    explicit Producer(const std::string& hmacKey);

    /**
     * @brief Algorithm 6: create a new Data packet header.
     * @param contentName  NDN name of the content object.
     * @return             7-byte header (PH, RHC, SEQN, HMAC), serialized.
     */
    CaccHeader createHeader(const ::ndn::Name& contentName);

    uint8_t nextSeqn(const ::ndn::Name& contentName);
    uint8_t currentSeqn(const ::ndn::Name& contentName) const;

    void reset() { m_globalSeqn.clear(); }

private:
    SecurityEngine m_security;
    std::map<::ndn::Name, uint8_t> m_globalSeqn;
};

} // namespace ndn
} // namespace ns3

#endif // CACC_SECURE_PRODUCER_HPP