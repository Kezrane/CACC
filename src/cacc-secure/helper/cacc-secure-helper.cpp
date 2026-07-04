#include "cacc-secure-helper.hpp"
#include <ns3/string.h>
#include <ns3/double.h>
#include <ns3/integer.h>

namespace ns3 {
namespace ndn {

CaccSecureHelper::CaccSecureHelper()
    : m_alpha(0.5), m_maxHops(16), m_secretKey("CACC_SECRET") {}

void CaccSecureHelper::setParameter(const std::string& name, const std::string& value) {
    if (name == "Alpha") {
        m_alpha = std::stod(value);
    } else if (name == "MaxHops") {
        m_maxHops = static_cast<uint8_t>(std::stoi(value));
    } else if (name == "SecretKey") {
        m_secretKey = value;
    }
}

void CaccSecureHelper::install(const NodeContainer& c) {
    for (auto it = c.Begin(); it != c.End(); ++it) {
        install(*it);
    }
}

void CaccSecureHelper::install(Ptr<Node> node) {
    // Check if an engine instance is already linked to this node
    if (m_nodeRegistry.find(node) != m_nodeRegistry.end()) {
        return; 
    }

    // Allocate a dedicated, standalone secure core engine instance
    auto secureCore = std::make_shared<CaccCore>(m_alpha, m_maxHops, m_secretKey);
    
    // Bind the allocated instance handle inside our master lookup dictionary
    m_nodeRegistry[node] = secureCore;
}

std::shared_ptr<CaccCore> CaccSecureHelper::getCoreInstance(Ptr<Node> node) {
    auto it = m_nodeRegistry.find(node);
    if (it != m_nodeRegistry.end()) {
        return it->second;
    }
    return nullptr;
}

} // namespace ndn
} // namespace ns3