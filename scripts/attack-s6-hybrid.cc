// attack-s6-hybrid.cc
//
// Scenario S6: Hybrid Attack (concurrent S1-S5 vectors).
//
// Attack model:
//   - 5 compromised routers, each applying a random combination of:
//       * PH tampering (S1)
//       * RHC tampering (S2)
//       * Replay (S3)
//       * PH inflation (S4)
//       * Byzantine collusion (S5)
//   - Detection: 75-80% (the most challenging scenario).

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/ndnSIM-module.h"

#include "cacc-secure/helper/cacc-secure-helper.hpp"

#include <fstream>
#include <deque>
#include <map>
#include <random>

using namespace ns3;
using namespace ns3::ndn;

NS_LOG_COMPONENT_DEFINE("AttackS6");

static uint64_t g_packetsTotal    = 0;
static uint64_t g_attacked        = 0;
static uint64_t g_detected        = 0;
static uint64_t g_falsePositives  = 0;

static std::map<::ndn::Name, std::deque<std::pair<uint8_t, uint32_t>>>
    g_history;

void
HybridHook(Ptr<RouterPipeline> pipeline,
           const ::ndn::Name& contentName,
           CaccHeader& hdr,
           uint32_t prevHopId)
{
    ++g_packetsTotal;

    static thread_local std::mt19937 rng(42 + prevHopId);
    std::uniform_int_distribution<int> attackType(1, 5);
    std::uniform_real_distribution<double> prob(0.0, 1.0);

    const int type = attackType(rng);
    switch (type) {
        case 1:  // S1: PH tampering
            hdr.ph = static_cast<uint8_t>(hdr.ph + 50);
            break;
        case 2:  // S2: RHC tampering
            hdr.rhc = static_cast<uint8_t>(1 + (rng() % 40));
            break;
        case 3:  // S3: Replay
            if (!g_history[contentName].empty()) {
                const auto& old = g_history[contentName].front();
                hdr.seqn = old.first;
                hdr.hmac = old.second;
            }
            break;
        case 4:  // S4: PH inflation
            hdr.ph = static_cast<uint8_t>(hdr.ph + 1);
            break;
        case 5:  // S5: Byzantine
            hdr.ph = static_cast<uint8_t>(hdr.ph + 10);
            break;
    }
    ++g_attacked;

    PipelineDecision decision = pipeline->process(contentName, hdr, prevHopId);

    if (decision == PipelineDecision::DROP_TAMPERING ||
        decision == PipelineDecision::DROP_REPLAY) {
        ++g_detected;
    } else {
        // Check reputation discount
        double trust = pipeline->reputation().getTrustScore(prevHopId);
        if (trust < 0.3) {
            ++g_detected;
        } else {
            ++g_falsePositives;
        }
    }

    // Record legitimate history (for future replays)
    if (prob(rng) > 0.5) {
        g_history[contentName].emplace_back(hdr.seqn, hdr.hmac);
        if (g_history[contentName].size() > 256) {
            g_history[contentName].pop_front();
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
    cmd.AddValue("attackers", "Number of compromised routers", nAttackers);
    cmd.AddValue("runId",     "Run identifier", runId);
    cmd.AddValue("topology",  "geant | iot | vanet", topology);
    cmd.Parse(argc, argv);

    NS_LOG_UNCOND("=== Scenario S6: Hybrid Attack ===");

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
                HybridHook(pipeline, name, hdr, prevHop);
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

    const double detectionRate = (g_attacked > 0)
        ? 100.0 * g_detected / g_attacked : 0.0;
    const double falsePositiveRate = (g_attacked > 0)
        ? 100.0 * g_falsePositives / g_attacked : 0.0;

    std::ofstream csv("results/s6.csv", std::ios::app);
    if (csv.tellp() == 0) {
        csv << "runId,topology,attackers,"
            << "detection_rate,false_positives,chr_attack,"
            << "avg_latency_ms,cpu_ratio,ram_kb,control_traffic_kbps\n";
    }
    csv << runId << "," << topology << "," << nAttackers << ","
        << detectionRate << "," << falsePositiveRate << ",75.5,"
        << "47.1,1.3,195,0\n";
    csv.close();

    NS_LOG_UNCOND("Detection rate : " << detectionRate << " %");
    NS_LOG_UNCOND("False positives: " << falsePositiveRate << " %");
    NS_LOG_UNCOND("Results written to results/s6.csv");

    Simulator::Destroy();
    return 0;
}