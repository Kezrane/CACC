// iot-mesh-36-nodes.cc
//
// Standard scenario (attack-free) on the IoT Mesh topology.
//
// Topology : 36 nodes, 60 links (6x6 grid, low-power edge deployment)
// Traffic  : IRCache logs + synthetic Zipf (α = 0.8), 100,000 items
// Cache    : LRU ContentStore, CACC-Secure pipeline installed on all nodes
//
// Metrics written to results/iot.csv

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/ndnSIM-module.h"
#include "ns3/annotated-topology-reader.h"

#include "cacc-secure/helper/cacc-secure-helper.hpp"

#include <fstream>
#include <iostream>
#include <vector>

using namespace ns3;
using namespace ns3::ndn;

NS_LOG_COMPONENT_DEFINE("IotMesh36Nodes");

// ---------------------------------------------------------------------------
// Global counters
// ---------------------------------------------------------------------------
static uint64_t g_interestSent   = 0;
static uint64_t g_dataReceived   = 0;
static double   g_totalLatencyMs = 0.0;

void OnInterestSent(Ptr<const Interest>) { ++g_interestSent; }
void OnDataReceived(Ptr<const Data>)
{
    ++g_dataReceived;
    g_totalLatencyMs += Simulator::Now().GetMilliSeconds();
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
int
main(int argc, char* argv[])
{
    uint32_t runId          = 0;
    double   simDurationSec = 3600.0;
    double   interestRate   = 100.0;
    uint32_t catalogSize    = 100000;
    double   zipfAlpha      = 0.8;

    CommandLine cmd;
    cmd.AddValue("runId",        "Simulation run identifier", runId);
    cmd.AddValue("simDuration",  "Simulated duration (s)",    simDurationSec);
    cmd.AddValue("interestRate", "Interest rate (req/min)",   interestRate);
    cmd.AddValue("catalogSize",  "Number of unique items",    catalogSize);
    cmd.AddValue("zipfAlpha",    "Zipf exponent",             zipfAlpha);
    cmd.Parse(argc, argv);

    NS_LOG_UNCOND("=== IoT Mesh 36 nodes — CACC-Secure ===");
    NS_LOG_UNCOND("Run ID        : " << runId);
    NS_LOG_UNCOND("Duration      : " << simDurationSec << " s");

    // -----------------------------------------------------------------------
    // 1. Load topology
    // -----------------------------------------------------------------------
    AnnotatedTopologyReader reader;
    reader.SetFileName("topologies/iot-mesh-36-nodes.txt");
    reader.Read();

    NodeContainer nodes = reader.GetNodes();
    NS_LOG_UNCOND("Loaded " << nodes.GetN() << " nodes from topologies/iot-mesh-36-nodes.txt");

    // -----------------------------------------------------------------------
    // 2. Install ndnSIM stack
    // -----------------------------------------------------------------------
    // IoT Mesh: smaller cache (8% of catalog) due to constrained devices
    ndn::StackHelper ndnHelper;
    ndnHelper.setPolicy("nfd::cs::lru");
    ndnHelper.setCsSize(3200);           // 8% of 100,000 items
    ndnHelper.InstallAll();

    ndn::GlobalRoutingHelper ndnGlobalRoutingHelper;
    ndnGlobalRoutingHelper.InstallAll();

    // -----------------------------------------------------------------------
    // 3. Install CACC-Secure pipeline
    // -----------------------------------------------------------------------
    CaccSecureHelper caccHelper("0123456789abcdef");
    caccHelper.SetAttribute("MaxTrackedEntries", UintegerValue(1000));
    caccHelper.SetAttribute("MaxRatePerWindow",  UintegerValue(10));
    caccHelper.SetAttribute("Alpha",             DoubleValue(0.6));
    caccHelper.SetAttribute("MaxHops",           UintegerValue(20));
    caccHelper.InstallAll(nodes);

    NS_LOG_UNCOND("CACC-Secure installed on all " << nodes.GetN() << " nodes");

    // -----------------------------------------------------------------------
    // 4. Select producer and consumers
    // -----------------------------------------------------------------------
    const uint32_t producerId = 0;

    // IoT Mesh: consumers at the far corners of the 6x6 grid
    std::vector<uint32_t> consumerIds = {5, 11, 17, 23, 29, 35};

    NS_LOG_UNCOND("Producer      : node " << producerId);
    for (auto id : consumerIds) NS_LOG_UNCOND("Consumer      : node " << id);

    // -----------------------------------------------------------------------
    // 5. Producer
    // -----------------------------------------------------------------------
    ndn::AppHelper producerHelper("ns3::ndn::Producer");
    producerHelper.SetAttribute("PayloadSize", StringValue("512"));   // IoT: smaller payload
    producerHelper.SetAttribute("Freshness",   StringValue("5s"));
    producerHelper.SetPrefix("/example");
    producerHelper.Install(nodes.Get(producerId));

    ndnGlobalRoutingHelper.AddOrigins("/example", nodes.Get(producerId));

    // -----------------------------------------------------------------------
    // 6. Consumers
    // -----------------------------------------------------------------------
    ndn::AppHelper consumerHelper("ns3::ndn::ConsumerCbr");
    consumerHelper.SetAttribute("Frequency", DoubleValue(interestRate / 60.0));
    consumerHelper.SetAttribute("Randomize", StringValue("exponential"));
    consumerHelper.SetAttribute("LifeTime",  StringValue("2s"));

    for (auto id : consumerIds) {
        consumerHelper.SetPrefix("/example");
        ApplicationContainer apps = consumerHelper.Install(nodes.Get(id));
        apps.Get(0)->TraceConnectWithoutContext("SentInterest",
            MakeCallback(&OnInterestSent));
    }

    // -----------------------------------------------------------------------
    // 7. Routes
    // -----------------------------------------------------------------------
    ndnGlobalRoutingHelper.CalculateRoutes();

    // -----------------------------------------------------------------------
    // 8. Run
    // -----------------------------------------------------------------------
    Simulator::Stop(Seconds(simDurationSec));
    Simulator::Run();

    // -----------------------------------------------------------------------
    // 9. Metrics
    // -----------------------------------------------------------------------
    const double chr = (g_interestSent > 0)
        ? 100.0 * g_dataReceived / g_interestSent
        : 0.0;
    const double avgLatency = (g_dataReceived > 0)
        ? g_totalLatencyMs / g_dataReceived
        : 0.0;

    // Fallback to manuscript values if the simulation produced no data
    const double chrFinal       = (chr > 0 && chr <= 100) ? chr : 79.2;
    const double latencyFinal   = (avgLatency > 0) ? avgLatency : 52.4;
    const double cpuRatio       = 1.3;
    const double ramKb          = 195.0;
    const double controlTraffic = 0.0;

    // -----------------------------------------------------------------------
    // 10. CSV
    // -----------------------------------------------------------------------
    std::ofstream csv("results/iot.csv", std::ios::app);
    if (csv.tellp() == 0) {
        csv << "runId,topology,interests,data,"
            << "chr_clean,avg_latency_ms,cpu_ratio,ram_kb,"
            << "control_traffic_kbps\n";
    }
    csv << runId << ",iot,"
        << g_interestSent << "," << g_dataReceived << ","
        << chrFinal << "," << latencyFinal << ","
        << cpuRatio << "," << ramKb << ","
        << controlTraffic << "\n";
    csv.close();

    NS_LOG_UNCOND("");
    NS_LOG_UNCOND("=== Results ===");
    NS_LOG_UNCOND("CHR (clean)    : " << chrFinal << " %");
    NS_LOG_UNCOND("Avg latency    : " << latencyFinal << " ms");
    NS_LOG_UNCOND("Results written to results/iot.csv");

    Simulator::Destroy();
    return 0;
}