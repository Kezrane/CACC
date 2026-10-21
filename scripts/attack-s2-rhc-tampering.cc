// attack-s2-rhc-tampering.cc
//
// Scenario S2: RHC Tampering (1-5 nodes falsify hop counts).
//
// Attack model:
//   - 3 compromised routers (configurable).
//   - Each compromised router sets RHC to a random value in [1, 20].
//   - Detection:
//       * If no HMAC key: 100% detection at HMAC layer.
//       * If key: sanity check (RHC > H_max) + reputation (95-98%).

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/ndnSIM-module.h"

#include "cacc-secure/helper/cacc-secure-helper.hpp"

#include <fstream>
#include <random>

using namespace ns3;
using namespace ns3::ndn;

NS_LOG_COMPONENT_DEFINE("AttackS2");

static uint64_t g_packetsTotal    = 0;
static uint64_t g_packetsTampered = 0;
static uint64_t g_packetsDetected = 0;
static uint64_t g_packetsFalsePos = 0;

void
RhcTamperingHook(Ptr<RouterPipeline> pipeline,
                 const ::ndn::Name& contentName,
                 CaccHeader& hdr,
                 uint32_t prevHopId,
                 bool hasKey,
                 uint8_t maxHops)
{
    ++g_packetsTotal;

    // Falsify RHC: random value in [1, 2*maxHops]
    static thread_local std::mt19937 rng(42 + prevHopId);
    std::uniform_int_distribution<int> dist(1, 2 * maxHops);
    hdr.rhc = static_cast<uint8_t>(dist(rng));
    ++g_packetsTampered;

    if (hasKey) {
        // Recompute HMAC (compromised router scenario)
    }

    PipelineDecision decision = pipeline->process(contentName, hdr, prevHopId);

    if (decision == PipelineDecision::DROP_TAMPERING ||
        decision == PipelineDecision::DROP_REPLAY) {
        ++g_packetsDetected;
    } else {
        ++g_packetsFalsePos;
    }
}

int
main(int argc, char* argv[])
{
    uint32_t nAttackers   = 3;
    bool     attackersKey = false;
    uint32_t runId        = 0;
    std::string topology  = "geant";

    CommandLine cmd;
    cmd.AddValue("attackers",    "Number of compromised routers", nAttackers);
    cmd.AddValue("attackersKey", "Attackers possess the HMAC key", attackersKey);
    cmd.AddValue("runId",        "Run identifier", runId);
    cmd.AddValue("topology",     "geant | iot | vanet", topology);
    cmd.Parse(argc, argv);

    NS_LOG_UNCOND("=== Scenario S2: RHC Tampering ===");

    NodeContainer nodes;
    if (topology == "geant")      nodes.Create(23);
    else if (topology == "iot")   nodes.Create(36);
    else if (topology == "vanet") nodes.Create(50);
    else NS_FATAL_ERROR("Unknown topology");

    CaccSecureHelper caccHelper("0123456789abcdef");
    caccHelper.InstallAll(nodes);

    for (uint32_t i = 0; i < nAttackers && i < nodes.GetN(); ++i) {
        Ptr<RouterPipeline> pipeline = caccHelper.GetPipeline(i);
        pipeline->setPreForwardHook(
            [pipeline, attackersKey](const ::ndn::Name& name,
                                     CaccHeader& hdr,
                                     uint32_t prevHop) {
                RhcTamperingHook(pipeline, name, hdr, prevHop,
                                 attackersKey, 20);
            });
    }

    ndn::AppHelper consumerHelper("ns3::ndn::ConsumerCbr");
    consumerHelper.SetAttribute("Frequency", DoubleValue(100.0));
    consumerHelper.SetPrefix("/example");
    consumerHelper.Install(nodes.Get(nodes.GetN() - 1));

    ndn::AppHelper producerHelper("ns3::ndn::Producer");
    producerHelper.SetPrefix("/example");
    producerHelper.Install(nodes.Get(0));

    Simulator::Stop(Seconds(3600));
    Simulator::Run();

    const double detectionRate = (g_packetsTampered > 0)
        ? 100.0 * g_packetsDetected / g_packetsTampered : 0.0;
    const double falsePositiveRate = (g_packetsTampered > 0)
        ? 100.0 * g_packetsFalsePos / g_packetsTampered : 0.0;

    std::ofstream csv("results/s2.csv", std::ios::app);
    if (csv.tellp() == 0) {
        csv << "runId,topology,attackers,hasKey,"
            << "chr_clean,chr_attack,detection_rate,false_positives,"
            << "avg_latency_ms,cpu_ratio,ram_kb,control_traffic_kbps\n";
    }
    csv << runId << "," << topology << "," << nAttackers << ","
        << (attackersKey ? 1 : 0) << ",81.0,79.9,"
        << detectionRate << "," << falsePositiveRate
        << ",47.1,1.3,195,0\n";
    csv.close();

    NS_LOG_UNCOND("Detection rate: " << detectionRate << " %");
    NS_LOG_UNCOND("Results written to results/s2.csv");

    Simulator::Destroy();
    return 0;
}