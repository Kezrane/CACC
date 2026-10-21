// cacc-secure-helper.hpp
//
// Helper to install CaccSecure RouterPipeline on a set of ns-3 nodes.
// Mirrors the usage pattern of ndnSIM's StackHelper/AppHelper:
//   CaccSecureHelper helper("key");
//   helper.InstallAll(nodes);
//   Ptr<RouterPipeline> p = helper.GetPipeline(nodeId);

#ifndef CACC_SECURE_HELPER_HPP
#define CACC_SECURE_HELPER_HPP

#include "ns3/node-container.h"
#include "ns3/ptr.h"
#include "ns3/object-factory.h"

#include "cacc-secure/model/router-pipeline.hpp"

#include <map>
#include <string>

namespace ns3 {
namespace ndn {

class CaccSecureHelper {
public:
    /**
     * @param hmacKey Pre-shared symmetric key (16 or 32 bytes).
     */
    explicit CaccSecureHelper(const std::string& hmacKey);

    // -----------------------------------------------------------------------
    // Attribute configuration (mirrors ns3::ObjectFactory)
    // -----------------------------------------------------------------------
    void SetAttribute(const std::string& name, const AttributeValue& value);

    // -----------------------------------------------------------------------
    // Installation
    // -----------------------------------------------------------------------
    void InstallAll(const NodeContainer& nodes);
    void Install(Ptr<Node> node);

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------
    Ptr<RouterPipeline> GetPipeline(uint32_t nodeId) const;
    bool HasPipeline(uint32_t nodeId) const;

    const std::string& hmacKey() const { return m_hmacKey; }

private:
    Ptr<RouterPipeline> CreatePipeline(Ptr<Node> node);

private:
    std::string m_hmacKey;
    std::map<std::string, Ptr<AttributeValue>> m_attributes;
    std::map<uint32_t, Ptr<RouterPipeline>> m_pipelines;
};

} // namespace ndn
} // namespace ns3

#endif // CACC_SECURE_HELPER_HPP