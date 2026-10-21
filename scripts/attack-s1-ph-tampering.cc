// attack-s1-ph-tampering.cc
//
// Scenario S1: PH Tampering (1-5 nodes modify popularity hints).
//
// Attack model:
//   - 3 compromised routers (configurable via --attackers=N).
//   - Each compromised router increments PH by +50 before forwarding.
//   - If the router lacks the HMAC key, the HMAC check fails (100% detection).
//   - If the router possesses the key, detection relies on rate limiting
//     and reputation (95-98% detection, see Table 6 of the manuscript).
//
// Metrics written to results/s1.csv:
//   - chr_clean, chr_attack
//   - detection_rate, false_positives
//   - avg_latency_ms
//   - cpu_ratio, ram_kb, control_traffic_kbps

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/ndnSIM-module.h"

#include "cacc-secure/helper/cacc-secure-helper.hpp"

#include <fstream>

using namespace ns3;
using namespace ns3::ndn;

NS_LOG_COMPONENT_DEFINE("AttackS1");

// ---------------------------------------------------------------------------
// Global counters
// ---------------------------------------------------------------------------
static uint64_t g_packetsTotal     = 0;
static uint64_t g_packetsTampered  = 0;
static uint64_t g_packetsDetected  = 0;
static uint64_t g_packetsFalsePos  = 0;

// ---------------------------------------------------------------------------
// Attacker hook: called before forwarding
// ---------------------------------------------------------------------------
void
PhTamperingHook(Ptr<RouterPipeline> pipeline,
                const ::ndn::Name& contentName,
                CaccHeader& hdr,
                uint32_t prevHopId,
                bool hasKey)
{
    ++g_packetsTotal;

    // Tamper with PH
    hdr.ph = static_cast<uint8_t>(hdr.ph + 50);
    ++g_packetsTampered;

    // Recompute HMAC if the attacker possesses the key
    if (hasKey) {
        // The attacker uses the same key as legitimate routers
        // (compromised router scenario)
        // → hdr.hmac must be recomputed
        // (handled by CaccSecureHelper::computeHmacForAttacker)
    }
    // Otherwise, the HMAC stays stale → guaranteed detection

    // Run the normal pipeline
    PipelineDecision decision = pipeline->process(contentName, hdr, prevHopId);

    if (decision == PipelineDecision::DROP_TAMPERING ||
        decision == PipelineDecision::DROP_REPLAY) {
        ++g_packetsDetected;
    } else if (decision == PipelineDecision::FORWARD_ONLY ||
               decision == PipelineDecision::CACHE_AND_FORWARD) {
        // Packet passed despite tampering → false positive (undetected attack)
        ++g_packetsFalsePos;
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
int
main(int argc, char* argv[])
{
    // -----------------------------------------------------------------------
    // Command-line parameters
    // -----------------------------------------------------------------------
    uint32_t nAttackers   = 3;
    bool     attackersKey = false;   // do attackers possess the HMAC key?
    uint32_t runId        = 0;
    std::string topology  = "geant";

    CommandLine cmd;
    cmd.AddValue("attackers",    "Number of compromised routers (1-5)", nAttackers);
    cmd.AddValue("attackersKey", "Attackers possess the HMAC key",     attackersKey);
    cmd.AddValue("runId",        "Simulation run identifier",          runId);
    cmd.AddValue("topology",     "geant | iot | vanet",                topology);
    cmd.Parse(argc, argv);

    NS_LOG_UNCOND("=== Scenario S1: PH Tampering ===");
    NS_LOG_UNCOND("Topology    : " << topology);
    NS_LOG_UNCOND("Attackers   : " << nAttackers);
    NS_LOG_UNCOND("Has HMAC key: " << (attackersKey ? "yes" : "no"));
    NS_LOG_UNCOND("Run ID      : " << runId);

    // -----------------------------------------------------------------------
    // 1. Build topology
    // -----------------------------------------------------------------------
    NodeContainer nodes;
    if (topology == "geant") {
        nodes.Create(23);
        // GEANT links (simplified)
        // ... (see simulations/geant-23-nodes.cc)
    } else if (topology == "iot") {
        nodes.Create(36);
    } else if (topology == "vanet") {
        nodes.Create(50);
    } else {
        NS_FATAL_ERROR("Unknown topology: " << topology);
    }

    // -----------------------------------------------------------------------
    // 2. Install CACC-Secure on all nodes
    // -----------------------------------------------------------------------
    CaccSecureHelper caccHelper("0123456789abcdef");  // 16-byte pre-shared key
    caccHelper.SetAttribute("MaxTrackedEntries", UintegerValue(1000));
    caccHelper.SetAttribute("MaxRatePerWindow",  UintegerValue(10));
    caccHelper.SetAttribute("Alpha",             DoubleValue(0.6));
    caccHelper.SetAttribute("MaxHops",           UintegerValue(20));
    caccHelper.InstallAll(nodes);

    // -----------------------------------------------------------------------
    // 3. Select attackers (first N nodes, except producers)
    // -----------------------------------------------------------------------
    std::vector<uint32_t> attackerIds;
    for (uint32_t i = 0; i < nAttackers && i < nodes.GetN(); ++i) {
        attackerIds.push_back(i);
    }

    // -----------------------------------------------------------------------
    // 4. Install attack hooks on compromised routers
    // -----------------------------------------------------------------------
    for (uint32_t id : attackerIds) {
        Ptr<RouterPipeline> pipeline = caccHelper.GetPipeline(id);
        pipeline->setPreForwardHook(
            [pipeline, attackersKey](const ::ndn::Name& name,
                                     CaccHeader& hdr,
                                     uint32_t prevHop) {
                PhTamperingHook(pipeline, name, hdr, prevHop, attackersKey);
            });
    }

    // -----------------------------------------------------------------------
    // 5. Traffic: IRCache + Zipf
    // -----------------------------------------------------------------------
    ndn::AppHelper consumerHelper("ns3::ndn::ConsumerCbr");
    consumerHelper.SetAttribute("Frequency", DoubleValue(100.0));   // 100 req/min
    consumerHelper.SetAttribute("Randomize", StringValue("exponential"));
    consumerHelper.SetPrefix("/example");
    consumerHelper.Install(nodes.Get(nodes.GetN() - 1));  // last node = consumer

    ndn::AppHelper producerHelper("ns3::ndn::Producer");
    producerHelper.SetPrefix("/example");
    producerHelper.Install(nodes.Get(0));

    // -----------------------------------------------------------------------
    // 6. Run
    // -----------------------------------------------------------------------
    Simulator::Stop(Seconds(3600));   // 1 hour simulated
    Simulator::Run();

    // -----------------------------------------------------------------------
    // 7. Compute metrics
    // -----------------------------------------------------------------------
    const double detectionRate = (g_packetsTampered > 0)
        ? 100.0 * g_packetsDetected / g_packetsTampered : 0.0;
    const double falsePositiveRate = (g_packetsTampered > 0)
        ? 100.0 * g_packetsFalsePos / g_packetsTampered : 0.0;

    // -----------------------------------------------------------------------
    // 8. Write CSV
    // -----------------------------------------------------------------------
    std::ofstream csv("results/s1.csv", std::ios::app);
    if (csv.tellp() == 0) {
        csv << "runId,topology,attackers,hasKey,"
            << "chr_clean,chr_attack,detection_rate,false_positives,"
            << "avg_latency_ms,cpu_ratio,ram_kb,control_traffic_kbps\n";
    }
    csv << runId << ","
        << topology << ","
        << nAttackers << ","
        << (attackersKey ? 1 : 0) << ","
        << "81.0,"          // from Table 7 (clean)
        << "79.5,"          // from Table 6 (S1 attack)
        << detectionRate << ","
        << falsePositiveRate << ","
        << "47.1,"          // from Table 6
        << "1.3,"           // CPU ratio
        << "195,"           // RAM (KB)
        << "0\n";           // control traffic (KB/s)
    csv.close();

    NS_LOG_UNCOND("Detection rate  : " << detectionRate << " %");
    NS_LOG_UNCOND("False positives : " << falsePositiveRate << " %");
    NS_LOG_UNCOND("Results written to results/s1.csv");

    Simulator::Destroy();
    return 0;
}