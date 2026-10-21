// cacc-secure-helper.cpp

#include "cacc-secure-helper.hpp"

#include <ns3/log.h>
#include <ns3/node.h>

#include <algorithm>

namespace ns3 {
namespace ndn {

NS_LOG_COMPONENT_DEFINE("CaccSecureHelper");

// ===========================================================================
// Construction
// ===========================================================================
CaccSecureHelper::CaccSecureHelper(const std::string& hmacKey)
    : m_hmacKey(hmacKey)
{
    NS_LOG_FUNCTION(this << "key length=" << hmacKey.size());
}

// ===========================================================================
// SetAttribute: store the attribute value for later use in CreatePipeline()
// ===========================================================================
void
CaccSecureHelper::SetAttribute(const std::string& name,
                               const AttributeValue& value)
{
    // Store a clone of the attribute value so the caller can reuse theirs
    Ptr<AttributeValue> clone = value.Copy();
    m_attributes[name] = clone;

    NS_LOG_DEBUG("SetAttribute: " << name);
}

// ===========================================================================
// InstallAll
// ===========================================================================
void
CaccSecureHelper::InstallAll(const NodeContainer& nodes)
{
    for (auto it = nodes.Begin(); it != nodes.End(); ++it) {
        Install(*it);
    }
}

// ===========================================================================
// Install (single node)
// ===========================================================================
void
CaccSecureHelper::Install(Ptr<Node> node)
{
    const uint32_t nodeId = node->GetId();

    if (m_pipelines.find(nodeId) != m_pipelines.end()) {
        NS_LOG_WARN("CaccSecureHelper: pipeline already installed on node "
                    << nodeId << ", skipping");
        return;
    }

    Ptr<RouterPipeline> pipeline = CreatePipeline(node);
    m_pipelines[nodeId] = pipeline;

    NS_LOG_INFO("Installed CaccSecure pipeline on node " << nodeId);
}

// ===========================================================================
// CreatePipeline: read attributes and instantiate RouterPipeline
// ===========================================================================
Ptr<RouterPipeline>
CaccSecureHelper::CreatePipeline(Ptr<Node> node)
{
    // Defaults (match the manuscript's Table 2 and Section 4.2)
    size_t   maxTrackedEntries = 1000;
    uint32_t maxRatePerWindow  = 10;
    double   alpha             = 0.6;
    uint8_t  maxHops           = 20;

    // Override from attributes, if set
    auto readUint = [&](const std::string& name, uint32_t& out) {
        auto it = m_attributes.find(name);
        if (it != m_attributes.end()) {
            Ptr<UintegerValue> v = DynamicCast<UintegerValue>(it->second);
            if (v) out = v->Get();
        }
    };
    auto readDouble = [&](const std::string& name, double& out) {
        auto it = m_attributes.find(name);
        if (it != m_attributes.end()) {
            Ptr<DoubleValue> v = DynamicCast<DoubleValue>(it->second);
            if (v) out = v->Get();
        }
    };

    uint32_t tmp = 0;
    readUint("MaxTrackedEntries", tmp);
    if (tmp > 0) maxTrackedEntries = tmp;

    readUint("MaxRatePerWindow", tmp);
    if (tmp > 0) maxRatePerWindow = tmp;

    readDouble("Alpha", alpha);

    readUint("MaxHops", tmp);
    if (tmp > 0 && tmp <= 255) maxHops = static_cast<uint8_t>(tmp);

    // Instantiate the pipeline
    Ptr<RouterPipeline> pipeline = CreateObject<RouterPipeline>(
        node->GetId(),
        m_hmacKey,
        maxTrackedEntries,
        maxRatePerWindow,
        alpha,
        maxHops);

    return pipeline;
}

// ===========================================================================
// GetPipeline
// ===========================================================================
Ptr<RouterPipeline>
CaccSecureHelper::GetPipeline(uint32_t nodeId) const
{
    auto it = m_pipelines.find(nodeId);
    if (it == m_pipelines.end()) {
        NS_LOG_WARN("CaccSecureHelper: no pipeline on node " << nodeId);
        return nullptr;
    }
    return it->second;
}

bool
CaccSecureHelper::HasPipeline(uint32_t nodeId) const
{
    return m_pipelines.find(nodeId) != m_pipelines.end();
}

} // namespace ndn
} // namespace ns3