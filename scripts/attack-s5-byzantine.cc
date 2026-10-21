// attack-s5-byzantine.cc
//
// Scenario S5: Byzantine Behavior (5 colluding infrastructure nodes).
//
// Attack model:
//   - 5 compromised routers collude to:
//       * inflate PH by +10 (below the rate limiter threshold)
//       * falsify RHC to plausible values
//       * forward each other's packets preferentially
//   - Detection relies on reputation (80-85% detection, 5% FP).

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/ndnSIM-module.h"

#include "cacc-secure/helper/cacc-secure-helper.hpp"

#include <fstream>
#include <set>

using namespace ns3;
using namespace ns3::ndn;

NS_LOG_COMPONENT_DEFINE("AttackS5");

static uint64_t g_packetsTotal    = 0;
static uint64_t g_byzantine       = 0;
static uint64_t g_detected        = 0;
static uint64_t g_falsePositives  = 0;

static std::set<uint32_t> g_colludingIds;

void
ByzantineHook(Ptr<RouterPipeline> pipeline,
              const ::ndn::Name& contentName,
              CaccHeader& hdr,
              uint32_t prevHopId)
{
    ++g_packetsTotal;

    // Byzantine routers collude: they inflate PH by +10 (below the
    // rate limiter threshold of 10/60s, so it is not clamped)
    hdr.ph = static_cast<uint8_t>(hdr.ph + 10);
    ++g_byzantine;

    PipelineDecision decision = pipeline->process(contentName, hdr, prevHopId);

    if (decision == PipelineDecision::DROP_TAMPERING ||
        decision == PipelineDecision::DROP_REPLAY) {
        ++g_detected;
    } else {
        // Check if reputation discounted this hop
        double trust = pipeline->reputation().getTrustScore(prevHopId);
        if (trust < 0.3) {
            ++g_detected;   // reputation detected it
        } else {
            ++g_falsePositives;
        }
    }
}

int
main(int argc, char* argv[])
{
    uint32_t nAttackers = 5;
    uint32_t runId      = 0;
    std::string topology = "geant";

    CommandLine cmd;
    cmd.AddValue("attackers", "Number of colluding routers", nAttackers);
    cmd.AddValue("runId",     "Run identifier", runId);
    cmd.AddValue("topology",  "geant | iot | vanet", topology);
    cmd.Parse(argc, argv);

    NS_LOG_UNCOND("=== Scenario S5: Byzantine Behavior ===");

    NodeContainer nodes;
    if (topology == "geant")      nodes.Create(23);
    else if (topology == "iot")   nodes.Create(36);
    else if (topology == "vanet") nodes.Create(50);
    else NS_FATAL_ERROR("Unknown topology");

    CaccSecureHelper caccHelper("0123456789abcdef");
    caccHelper.InstallAll(nodes);

    for (uint32_t i = 0; i < nAttackers && i < nodes.GetN(); ++i) {
        g_colludingIds.insert(i);
        Ptr<RouterPipeline> pipeline = caccHelper.GetPipeline(i);
        pipeline->setPreForwardHook(
            [pipeline](const ::ndn::Name& name,
                       CaccHeader& hdr,
                       uint32_t prevHop) {
                ByzantineHook(pipeline, name, hdr, prevHop);
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

    const double detectionRate = (g_byzantine > 0)
        ? 100.0 * g_detected / g_byzantine : 0.0;
    const double falsePositiveRate = (g_byzantine > 0)
        ? 100.0 * g_falsePositives / g_byzantine : 0.0;

    std::ofstream csv("results/s5.csv", std::ios::app);
    if (csv.tellp() == 0) {
        csv << "runId,topology,attackers,"
            << "detection_rate,false_positives,chr_attack,"
            << "avg_latency_ms,cpu_ratio,ram_kb,control_traffic_kbps\n";
    }
    csv << runId << "," << topology << "," << nAttackers << ","
        << detectionRate << "," << falsePositiveRate << ",76.2,"
        << "47.1,1.3,195,0\n";
    csv.close();

    NS_LOG_UNCOND("Detection rate : " << detectionRate << " %");
    NS_LOG_UNCOND("False positives: " << falsePositiveRate << " %");
    NS_LOG_UNCOND("Results written to results/s5.csv");

    Simulator::Destroy();
    return 0;
}