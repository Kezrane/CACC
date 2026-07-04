#include <ns3/core-module.h>
#include <ns3/network-module.h>
#include <ns3/point-to-point-module.h>
#include <ns3/ndnSIM-module.h>
#include "ns3/ndnSIM/helper/annotated-topology-reader.hpp"
#include "cacc-secure-helper.hpp"
#include "cacc-header.hpp"

using namespace ns3;

int main(int argc, char* argv[]) {
    CommandLine cmd;
    cmd.Parse(argc, argv);

    // 1. Load Topology Matrix from the geant.txt Configuration File
    AnnotatedTopologyReader topoReader("", 1.0);
    topoReader.SetFileName("scenarios/topologies/geant.txt");
    NodeContainer nodes = topoReader.Read();

    if (nodes.GetN() == 0) {
        NS_FATAL_ERROR("Failed to load topology matrix from scenarios/topologies/geant.txt");
    }

    // 2. Install Standard NDN Stack Primitives
    ndn::StackHelper ndnStack;
    ndnStack.SetOldContentStore("ns3::ndn::cs::Lru", "MaxSize", "1000"); // Base CS Capacity
    ndnStack.Install(nodes);

    // 3. Configure and Instantiate the CACC-Secure Layer
    ndn::CaccSecureHelper caccHelper;
    caccHelper.SetParameter("Alpha", "0.5");
    caccHelper.SetParameter("MaxHops", "16");
    caccHelper.SetParameter("SecretKey", "GEANT_BACKBONE_SECURE_PHASE");
    caccHelper.Install(nodes);

    // Set Up Global Routing Strategies
    ndn::GlobalRoutingHelper ndnGlobalRouting;
    ndnGlobalRouting.Install(nodes);

    // 4. Configure Application Drivers (Consumers & Producers)
    // In geant.txt, N0 (Index 0) is the Central Gateway Node / Producer Location
    Ptr<Node> producerNode = nodes.Get(0);
    ndn::AppHelper producerHelper("ns3::ndn::Producer");
    producerHelper.SetPrefix("/geant/content");
    producerHelper.SetAttribute("PayloadSize", StringValue("1024"));
    producerHelper.Install(producerNode);
    ndnGlobalRouting.AddOrigins("/geant/content", producerNode);

    // Position Consumers at Peripheral Nodes (N10 and N20 mapped via topology index)
    ndn::AppHelper consumerHelper("ns3::ndn::ConsumerZipfMandelbrot");
    consumerHelper.SetPrefix("/geant/content");
    consumerHelper.SetAttribute("NumberOfContents", StringValue("100000")); // Catalog Size
    consumerHelper.SetAttribute("Frequency", StringValue("50"));            // 50 requests/sec
    consumerHelper.SetAttribute("q", StringValue("0.7"));                   // Zipf alpha tuning

    ApplicationContainer consumers;
    consumers.Add(consumerHelper.Install(nodes.Get(10))); // N10 Edge Consumer A
    consumers.Add(consumerHelper.Install(nodes.Get(20))); // N20 Edge Consumer B

    consumers.Start(Seconds(1.0));
    consumers.Stop(Seconds(20.0));

    // Calculate Routing Paths
    ndn::GlobalRoutingHelper::CalculateRoutes();

    // 5. Enable Simulation Performance Trace Trackers
    ndn::CsTracer::InstallAll("scenarios/geant-cs-traces.txt", Seconds(1.0));
    ndn::L3RateTracer::InstallAll("scenarios/geant-l3-traces.txt", Seconds(1.0));

    NS_LOG_UNCOND("Starting GEANT Backbone Scenario Simulation Runs...");
    Simulator::Stop(Seconds(20.5));
    Simulator::Run();
    Simulator::Destroy();
    NS_LOG_UNCOND("GEANT CACC-Secure Execution Successfully Finished.");

    return 0;
}