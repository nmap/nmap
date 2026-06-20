 #include <fstream>
  /* #include "core-module.h"
   #include "internet-module.h"
    #include "csma-module.h"
    #include "internet-apps-module.h" */
    #include "ipv6-static-routing-helper.h"
    
  //  #include "ipv6-routing-table-entry.h"
    

    
    NS_LOG_COMPONENT_DEFINE ("FragmentationIpv6TwoMtuExample");
    
    int main (int argc, char** argv)
    {
      bool connection = false;
    
      CommandLine cmd;
      cmd.AddValue ("connection", "turn on log components", connection);
      cmd.Parse (argc, argv);
    
      if (connection)
        {
          LogComponentEnable ("Ipv6L3Protocol", LOG_LEVEL_ALL);
          LogComponentEnable ("Icmpv6L4Protocol", LOG_LEVEL_ALL);
          LogComponentEnable ("Ipv6StaticRouting", LOG_LEVEL_ALL);
          LogComponentEnable ("Ipv6Interface", LOG_LEVEL_ALL);
          LogComponentEnable ("Ping6Application", LOG_LEVEL_ALL);
        }
    
    /*  NS_LOG_INFO ("Create nodes.");
      Ptr<Node> n0 = CreateObject<Node> ();
      Ptr<Node> r = CreateObject<Node> ();
      Ptr<Node> n1 = CreateObject<Node> ();
    
      NodeContainer net1 (n0, r);
      NodeContainer net2 (r, n1);
      NodeContainer all (n0, r, n1);
    
      NS_LOG_INFO ("Create IPv6 Internet Stack");
      InternetStackHelper internetv6;
      internetv6.Install (all);
    
      NS_LOG_INFO ("Create channels.");
      CsmaHelper csma;
      csma.SetChannelAttribute ("DataRate", DataRateValue (5000000));
      csma.SetChannelAttribute ("Delay", TimeValue (MilliSeconds (2)));
      NetDeviceContainer d2 = csma.Install (net2);
      csma.SetDeviceAttribute ("Mtu", UintegerValue (5000));
      NetDeviceContainer d1 = csma.Install (net1);
    
      NS_LOG_INFO ("Create networks and assign IPv6 Addresses.");
      Ipv6AddressHelper ipv6;
      ipv6.SetBase (Ipv6Address ("2001:1::"), Ipv6Prefix (64));
      Ipv6InterfaceContainer i1 = ipv6.Assign (d1);
      i1.SetForwarding (1, true);
      i1.SetDefaultRouteInAllNodes (1);
      ipv6.SetBase (Ipv6Address ("2001:2::"), Ipv6Prefix (64));
      Ipv6InterfaceContainer i2 = ipv6.Assign (d2);
      i2.SetForwarding (0, true);
      i2.SetDefaultRouteInAllNodes (0);
    
      Ipv6StaticRoutingHelper routingHelper;
      Ptr<OutputStreamWrapper> routingStream = Create<OutputStreamWrapper> (&std::cout);
      routingHelper.PrintRoutingTableAt (Seconds (0), n0, routingStream);*/
    
      /* Create a Ping6 application to send ICMPv6 echo request from n0 to n1 via r */
    uint32_t packetSize = 4096;
     uint32_t maxPacketCount = 5;
     Time interPacketInterval = Seconds (1.0);
     Ping6Helper ping6;
   
     ping6.SetLocal (i1.GetAddress (0, 1));
     ping6.SetRemote (i2.GetAddress (1, 1)); 
   
     ping6.SetAttribute ("MaxPackets", UintegerValue (maxPacketCount));
     ping6.SetAttribute ("Interval", TimeValue (interPacketInterval));
     ping6.SetAttribute ("PacketSize", UintegerValue (packetSize));
     ApplicationContainer apps = ping6.Install (net1.Get (0));
     apps.Start (Seconds (2.0));
     apps.Stop (Seconds (20.0));
   
     AsciiTraceHelper ascii;
     csma.EnableAsciiAll (ascii.CreateFileStream ("fragmentation-ipv6-two-mtu.tr"));
     csma.EnablePcapAll (std::string ("fragmentation-ipv6-two-mtu"), true);
   
     NS_LOG_INFO ("Run Simulation.");
     Simulator::Run ();
     Simulator::Destroy ();
     NS_LOG_INFO ("Done.");
   }
