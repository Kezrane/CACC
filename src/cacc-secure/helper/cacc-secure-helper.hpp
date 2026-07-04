#ifndef NDN_SIM_CACC_SECURE_HELPER_HPP
#define NDN_SIM_CACC_SECURE_HELPER_HPP

#include "cacc-core.hpp"
#include <ns3/node-container.h>
#include <ns3/object-factory.h>
#include <memory>
#include <map>

namespace ns3 {
namespace ndn {

/**
 * @brief Helper class to instantiate, configure, and install CACC-Secure architectures across topologies.
 */
class CaccSecureHelper {
public:
    CaccSecureHelper();

    /**
     * @brief Parameters configuration adjustment interface.
     */
    void setParameter(const std::string& name, const std::string& value);

    /**
     * @brief Installs the CACC core tracking context onto a container pool of nodes.
     * @param c Nodes container mapping target system targets.
     */
    void install(const NodeContainer& c);

    /**
     * @brief Installs the CACC core tracking context onto a targeted specific node.
     * @param node Selected isolated pointer destination.
     */
    void install(Ptr<Node> node);

    /**
     * @brief Fetches the underlying tracking instance runtime for analytical probing.
     * @param node Targeted infrastructure pointer.
     */
    std::shared_ptr<CaccCore> getCoreInstance(Ptr<Node> node);

private:
    double m_alpha;
    uint8_t m_maxHops;
    std::string m_secretKey;

    // Local system instance management map
    std::map<Ptr<Node>, std::shared_ptr<CaccCore>> m_nodeRegistry;
};

} // namespace ndn
} // namespace ns3

#endif // NDN_SIM_CACC_SECURE_HELPER_HPP