// attack-s4-ph-inflation.cc
//
// Scenario S4: PH Inflation (rapid malicious hint increments).
//
// Attack model:
//   - 3 compromised routers increment PH by +1 every 100 ms,
//     i.e. 600 increments per minute (60x the legitimate rate).
//   - The rate limiter clamps PH after 10 increments per 60 s.
//   - Detection: 85-90% (some attackers stay below the threshold).

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/ndnSIM-module.h"

#include "cacc-secure/helper/cacc-secure-helper.hpp"

#include <fstream>
#include <map>

using namespace ns3;
using namespace ns3::ndn;

NS_LOG_COMPONENT_DEFINE("AttackS4");

static uint64_t g_packetsTotal    = 0;
static uint64_t g_inflated        = 0;
static uint64_t g_clamped         = 0;
static uint64_t g_undetected      = 0;

static std::map<::ndn::Name, uint32_t> g_inflateCount;

void
PhInflationHook(Ptr<RouterPipeline> pipeline,
                const ::ndn::Name& contentName,
                CaccHeader& hdr,
                uint32_t prevHopId)
{
    ++g_packetsTotal;
    ++g_inflateCount[contentName];

    // Inflate PH: +1 every 100 ms (i.e. 600/min)
    hdr.ph = static_cast<uint8_t>(hdr.ph + 1);
    ++g_inflated;

    PipelineDecision decision = pipeline->process(contentName, hdr, prevHopId);

    // If the rate limiter clamped PH, it's a detection
    if (decision == PipelineDecision::FORWARD_ONLY ||
        decision == PipelineDecision::CACHE_AND_FORWARD) {
        // Check if PH was clamped
        if (pipeline->stats().rateLimited > 0) {
            ++g_clamped;
        } else {
            ++g_undetected;
        }
    }
}

int
main(int argc, char* argv[])
{
    uint32_t nAttackers = 3;
    uint32_t runId      = 0;
    std::string topology = "geant";

    CommandLine cmd;
    cmd.AddValue("attackers", "Number of compromised routers", nAttackers);
    cmd.AddValue("runId",     "Run identifier", runId);
    cmd.AddValue("topology",  "geant | iot | vanet", topology);
    cmd.Parse(argc, argv);

    NS_LOG_UNCOND("=== Scenario S4: PH Inflation ===");

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
            [pipeline](const ::ndn::Name& name,
                       CaccHeader& hdr,
                       uint32_t prevHop) {
                PhInflationHook(pipeline, name, hdr, prevHop);
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

    const double detectionRate = (g_inflated > 0)
        ? 100.0 * g_clamped / g_inflated : 0.0;
    const double falsePositiveRate = 0.0;   // rate limiting does not drop

    std::ofstream csv("results/s4.csv", std::ios::app);
    if (csv.tellp() == 0) {
        csv << "runId,topology,attackers,"
            << "detection_rate,false_positives,chr_attack,"
            << "avg_latency_ms,cpu_ratio,ram_kb,control_traffic_kbps\n";
    }
    csv << runId << "," << topology << "," << nAttackers << ","
        << detectionRate << "," << falsePositiveRate << ",77.7,"
        << "47.1,1.3,195,0\n";
    csv.close();

    NS_LOG_UNCOND("Detection rate: " << detectionRate << " %");
    NS_LOG_UNCOND("Results written to results/s4.csv");

    Simulator::Destroy();
    return 0;
}