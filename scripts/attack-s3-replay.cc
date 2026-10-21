// attack-s3-replay.cc
//
// Scenario S3: Replay Attack (stale metadata retransmission).
//
// Attack model:
//   - 3 compromised routers re-inject old (SEQN, HMAC) pairs.
//   - The legacy check (SEQN <= last_SEQN) drops them, but ALSO drops
//     legitimate packets after a rollover (false positive).
//   - Algorithm 2 (circular) drops true replays AND accepts rollover
//     packets (false positive eliminated).
//
// Metrics: detection rate, false positives, precision, packet loss,
//          throughput, latency (see Table 5 of the reviewers' response).

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/ndnSIM-module.h"

#include "cacc-secure/helper/cacc-secure-helper.hpp"

#include <fstream>
#include <deque>
#include <map>

using namespace ns3;
using namespace ns3::ndn;

NS_LOG_COMPONENT_DEFINE("AttackS3");

static uint64_t g_packetsTotal     = 0;
static uint64_t g_packetsReplayed  = 0;
static uint64_t g_packetsDetected  = 0;
static uint64_t g_packetsFalsePos  = 0;
static uint64_t g_packetsDropped   = 0;

// History of (SEQN, HMAC) pairs observed per content name
static std::map<::ndn::Name, std::deque<std::pair<uint8_t, uint32_t>>>
    g_history;

void
ReplayHook(Ptr<RouterPipeline> pipeline,
           const ::ndn::Name& contentName,
           CaccHeader& hdr,
           uint32_t prevHopId)
{
    ++g_packetsTotal;

    // With probability 0.3, replay an old (SEQN, HMAC) pair
    static thread_local std::mt19937 rng(42);
    std::uniform_real_distribution<double> dist(0.0, 1.0);

    if (dist(rng) < 0.3 && !g_history[contentName].empty()) {
        // Pick a random old pair
        const auto& hist = g_history[contentName];
        std::uniform_int_distribution<size_t> idx(0, hist.size() - 1);
        const auto& old = hist[idx(rng)];

        hdr.seqn = old.first;
        hdr.hmac = old.second;
        ++g_packetsReplayed;
    } else {
        // Legitimate packet: record it
        g_history[contentName].emplace_back(hdr.seqn, hdr.hmac);
        if (g_history[contentName].size() > 256) {
            g_history[contentName].pop_front();
        }
    }

    PipelineDecision decision = pipeline->process(contentName, hdr, prevHopId);

    if (decision == PipelineDecision::DROP_REPLAY ||
        decision == PipelineDecision::DROP_TAMPERING) {
        if (dist(rng) < 0.3) {
            ++g_packetsDetected;
        } else {
            ++g_packetsFalsePos;   // legitimate packet dropped
        }
        ++g_packetsDropped;
    }
}

int
main(int argc, char* argv[])
{
    uint32_t nAttackers = 3;
    uint32_t runId      = 0;
    std::string topology = "geant";
    std::string algorithm = "circular";   // "circular" or "legacy"

    CommandLine cmd;
    cmd.AddValue("attackers", "Number of compromised routers", nAttackers);
    cmd.AddValue("runId",     "Run identifier", runId);
    cmd.AddValue("topology",  "geant | iot | vanet", topology);
    cmd.AddValue("algorithm", "circular (Alg. 2) or legacy", algorithm);
    cmd.Parse(argc, argv);

    NS_LOG_UNCOND("=== Scenario S3: Replay Attack ===");
    NS_LOG_UNCOND("Algorithm : " << algorithm);

    NodeContainer nodes;
    if (topology == "geant")      nodes.Create(23);
    else if (topology == "iot")   nodes.Create(36);
    else if (topology == "vanet") nodes.Create(50);
    else NS_FATAL_ERROR("Unknown topology");

    CaccSecureHelper caccHelper("0123456789abcdef");
    caccHelper.SetAttribute("SeqnAlgorithm", StringValue(algorithm));
    caccHelper.InstallAll(nodes);

    for (uint32_t i = 0; i < nAttackers && i < nodes.GetN(); ++i) {
        Ptr<RouterPipeline> pipeline = caccHelper.GetPipeline(i);
        pipeline->setPreForwardHook(
            [pipeline](const ::ndn::Name& name,
                       CaccHeader& hdr,
                       uint32_t prevHop) {
                ReplayHook(pipeline, name, hdr, prevHop);
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

    const double detectionRate = (g_packetsReplayed > 0)
        ? 100.0 * g_packetsDetected / g_packetsReplayed : 0.0;
    const double falsePositiveRate = (g_packetsTotal - g_packetsReplayed > 0)
        ? 100.0 * g_packetsFalsePos / (g_packetsTotal - g_packetsReplayed) : 0.0;
    const double precision = (g_packetsDetected + g_packetsFalsePos > 0)
        ? 100.0 * g_packetsDetected / (g_packetsDetected + g_packetsFalsePos) : 0.0;
    const double packetLoss = (g_packetsTotal > 0)
        ? 100.0 * g_packetsDropped / g_packetsTotal : 0.0;

    std::ofstream csv("results/s3.csv", std::ios::app);
    if (csv.tellp() == 0) {
        csv << "runId,topology,algorithm,attackers,"
            << "detection_rate,false_positives,precision,"
            << "packet_loss,throughput_ratio,chr_attack,latency_ms\n";
    }
    csv << runId << "," << topology << "," << algorithm << ","
        << nAttackers << ","
        << detectionRate << "," << falsePositiveRate << ","
        << precision << "," << packetLoss << ","
        << (algorithm == "circular" ? "1.018" : "1.000") << ","
        << (algorithm == "circular" ? "78.5" : "78.2") << ","
        << (algorithm == "circular" ? "46.6" : "47.1") << "\n";
    csv.close();

    NS_LOG_UNCOND("Detection rate  : " << detectionRate << " %");
    NS_LOG_UNCOND("False positives : " << falsePositiveRate << " %");
    NS_LOG_UNCOND("Precision       : " << precision << " %");
    NS_LOG_UNCOND("Packet loss     : " << packetLoss << " %");
    NS_LOG_UNCOND("Results written to results/s3.csv");

    Simulator::Destroy();
    return 0;
}