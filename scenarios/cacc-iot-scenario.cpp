#include <ns3/core-module.h>
#include <ns3/network-module.h>
#include <ns3/internet-module.h>
#include <ns3/point-to-point-module.h>
#include <ns3/ndnSIM-module.h>
#include "ns3/ndnSIM/helper/annotated-topology-reader.hpp"
#include "cacc-secure-helper.hpp"
#include "cacc-header.hpp"

using namespace ns3;

int main(int argc, char* argv[]) {
    CommandLine cmd;
    cmd.Parse(argc, argv);

    // 1. Load Topology Matrix from the iot-mesh.txt Grid File
    AnnotatedTopologyReader topoReader("", 1.0);
    topoReader.SetFileName("scenarios/topologies/iot-mesh.txt");
    NodeContainer nodes = topoReader.Read();

    if (nodes.GetN() == 0) {
        NS_FATAL_ERROR("Failed to load topology matrix from scenarios/topologies/iot-mesh.txt");
    }

    // 2. Install NDN Stack with Strict Space Constraints
    ndn::StackHelper ndnStack;
    // Severely restricted Cache size to test resource containment (100 elements)
    ndnStack.SetOldContentStore("ns3::ndn::cs::Lru", "MaxSize", "100"); 
    ndnStack.Install(nodes);

    // 3. Instantiate CACC-Secure with Tightened Target Thresholds
    ndn::CaccSecureHelper caccHelper;
    caccHelper.SetParameter("Alpha", "0.6");     // Higher weight towards popularity
    caccHelper.SetParameter("MaxHops", "10");     // Smaller operational network diameter
    caccHelper.SetParameter("SecretKey", "CONSTRAINED_IOT_MESH_SECRET_KEY");
    caccHelper.Install(nodes);

    ndn::GlobalRoutingHelper ndnGlobalRouting;
    ndnGlobalRouting.Install(nodes);

    // 4. Set up IoT Central Aggregation Station (Producer at Central Node N17)
    Ptr<Node> gatewayNode = nodes.Get(17);
    ndn::AppHelper producerHelper("ns3::ndn::Producer");
    producerHelper.SetPrefix("/iot/sensor-data");
    producerHelper.SetAttribute("PayloadSize", StringValue("512")); // Smaller packet footprint
    producerHelper.Install(gatewayNode);
    ndnGlobalRouting.AddOrigins("/iot/sensor-data", gatewayNode);

    // Set up Peripheral Sensor Consumers generating dynamic environmental requests
    ndn::AppHelper consumerHelper("ns3::ndn::ConsumerZipfMandelbrot");
    consumerHelper.SetPrefix("/iot/sensor-data");
    consumerHelper.SetAttribute("NumberOfContents", StringValue("10000")); // Constrained trace set
    consumerHelper.SetAttribute("Frequency", StringValue("10"));           // 10 requests/sec per sensor
    consumerHelper.SetAttribute("q", StringValue("0.85"));                  // Highly localized skewness

    // Distribute edge consumers at geometric boundary nodes (N0, N5, N30, N35)
    ApplicationContainer consumers;
    consumers.Add(consumerHelper.Install(nodes.Get(0)));  // N0 Corner
    consumers.Add(consumerHelper.Install(nodes.Get(5)));  // N5 Corner
    consumers.Add(consumerHelper.Install(nodes.Get(30))); // N30 Corner
    consumers.Add(consumerHelper.Install(nodes.Get(35))); // N35 Corner

    consumers.Start(Seconds(0.5));
    consumers.Stop(Seconds(15.0));

    // Calculate Routing Tables Across Mesh Topology
    ndn::GlobalRoutingHelper::CalculateRoutes();

    // 5. Setup Trace Log Outputs for Data Extraction
    ndn::CsTracer::InstallAll("scenarios/iot-cs-traces.txt", Seconds(1.0));
    ndn::L3RateTracer::InstallAll("scenarios/iot-l3-traces.txt", Seconds(1.0));

    NS_LOG_UNCOND("Starting Low-Power IoT Mesh Scenario Simulation Runs...");
    Simulator::Stop(Seconds(15.5));
    Simulator::Run();
    Simulator::Destroy();
    NS_LOG_UNCOND("IoT Mesh CACC-Secure Execution Successfully Finished.");

    return 0;
}