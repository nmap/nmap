/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
     /*
      * Copyright (c) 2008-2009 Strasbourg University
      *
      * This program is free software; you can redistribute it and/or modify
      * it under the terms of the GNU General Public License version 2 as
      * published by the Free Software Foundation;
      *
      * This program is distributed in the hope that it will be useful,
     * but WITHOUT ANY WARRANTY; without even the implied warranty of
     * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
     * GNU General Public License for more details.
     *
     * You should have received a copy of the GNU General Public License
     * along with this program; if not, write to the Free Software
     * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
     *
     * Author: Sebastien Vincent <vincent@clarinet.u-strasbg.fr>
     */
    
    #include "assert.h"
    #include "log.h"
    #include "ptr.h"
    #include "node.h"
    #include "net-device.h"
    #include "loopback-net-device.h"
    #include "mac16-address.h"
    #include "mac48-address.h"
    #include "mac64-address.h"
    #include "ipv6.h"
    #include "ipv6-address-generator.h"
    #include "traffic-control-helper.h"
    #include "traffic-control-layer.h"
    
    #include "ipv6-address-helper.h"
    
   
    NS_LOG_COMPONENT_DEFINE ("Ipv6AddressHelper");
    
    Ipv6AddressHelper::Ipv6AddressHelper ()
    {
      NS_LOG_FUNCTION (this);
      Ipv6AddressGenerator::Init (Ipv6Address ("2001:db8::"), Ipv6Prefix (64));
    }
    
    Ipv6AddressHelper::Ipv6AddressHelper (Ipv6Address network, Ipv6Prefix prefix,
                                          Ipv6Address base)
    {
      NS_LOG_FUNCTION (this << network << prefix << base);
      Ipv6AddressGenerator::Init (network, prefix, base);
    }
    
    void Ipv6AddressHelper::SetBase (Ipv6Address network, Ipv6Prefix prefix,
                                Ipv6Address base)
    {
      NS_LOG_FUNCTION (this << network << prefix << base);
      Ipv6AddressGenerator::Init (network, Ipv6Prefix (64), base);
    }
    
    
    Ipv6Address Ipv6AddressHelper::NewAddress (Address addr)
    {
      NS_LOG_FUNCTION (this << addr);
      if (Mac64Address::IsMatchingType (addr))
        {
          Ipv6Address network = Ipv6AddressGenerator::GetNetwork (Ipv6Prefix (64));
          Ipv6Address address = Ipv6Address::MakeAutoconfiguredAddress (Mac64Address::ConvertFrom (addr), network);
          Ipv6AddressGenerator::AddAllocated (address);
          return address;
        }
      else if (Mac48Address::IsMatchingType (addr))
        {
          Ipv6Address network = Ipv6AddressGenerator::GetNetwork (Ipv6Prefix (64));
         Ipv6Address address = Ipv6Address::MakeAutoconfiguredAddress (Mac48Address::ConvertFrom (addr), network);
          Ipv6AddressGenerator::AddAllocated (address);
          return address;
        }
      else if (Mac16Address::IsMatchingType (addr))
        {
          Ipv6Address network = Ipv6AddressGenerator::GetNetwork (Ipv6Prefix (64));
          Ipv6Address address = Ipv6Address::MakeAutoconfiguredAddress (Mac16Address::ConvertFrom (addr), network);
          Ipv6AddressGenerator::AddAllocated (address);
          return address;
        }
      else
        {
          NS_FATAL_ERROR ("Did not pass in a valid Mac Address (16, 48 or 64 bits)");
        }
      /* never reached */
      return Ipv6Address ("::");
    }
    
    Ipv6Address Ipv6AddressHelper::NewAddress (void)
    {
     NS_LOG_FUNCTION (this);
  //
  // The way this is expected to be used is that an address and network number
   // are initialized, and then NewAddress() is called repeatedly to allocate and
   // get new addresses on a given subnet.  The client will expect that the first
   // address she gets back is the one she used to initialize the generator with.
   // This implies that this operation is a post-increment.
   //
     return Ipv6AddressGenerator::NextAddress (Ipv6Prefix (64));
   }
   
   void Ipv6AddressHelper::NewNetwork (void)
   {
     NS_LOG_FUNCTION (this);
     Ipv6AddressGenerator::NextNetwork (Ipv6Prefix (64));
   }
   
   Ipv6InterfaceContainer Ipv6AddressHelper::Assign (const NetDeviceContainer &c)
   {
     NS_LOG_FUNCTION (this);
     Ipv6InterfaceContainer retval;
   
     for (uint32_t i = 0; i < c.GetN (); ++i) 
       {
         Ptr<NetDevice> device = c.Get (i);
   
         Ptr<Node> node = device->GetNode ();
         NS_ASSERT_MSG (node, "Ipv6AddressHelper::Allocate (): Bad node");
   
         Ptr<Ipv6> ipv6 = node->GetObject<Ipv6> ();
         NS_ASSERT_MSG (ipv6, "Ipv6AddressHelper::Allocate (): Bad ipv6");
         int32_t ifIndex = 0;
   
         ifIndex = ipv6->GetInterfaceForDevice (device);
         if (ifIndex == -1)
           {
             ifIndex = ipv6->AddInterface (device);
           }
         NS_ASSERT_MSG (ifIndex >= 0, "Ipv6AddressHelper::Allocate (): "
                        "Interface index not found");
   
       Ipv6InterfaceAddress ipv6Addr = Ipv6InterfaceAddress (NewAddress (device->GetAddress ()), Ipv6Prefix (64));
         ipv6->SetMetric (ifIndex, 1);
         ipv6->AddAddress (ifIndex, ipv6Addr);
         ipv6->SetUp (ifIndex);
   
         retval.Add (ipv6, ifIndex);
   
         // Install the default traffic control configuration if the traffic
         // control layer has been aggregated, if this is not
         // a loopback interface, and there is no queue disc installed already
         Ptr<TrafficControlLayer> tc = node->GetObject<TrafficControlLayer> ();
         if (tc && DynamicCast<LoopbackNetDevice> (device) == 0 && tc->GetRootQueueDiscOnDevice (device) == 0)
           {
             NS_LOG_LOGIC ("Installing default traffic control configuration");
             TrafficControlHelper tcHelper = TrafficControlHelper::Default ();
             tcHelper.Install (device);
           }
       }
     return retval;
   }
   
   Ipv6InterfaceContainer Ipv6AddressHelper::Assign (const NetDeviceContainer &c, std::vector<bool> withConfiguration)
   {
     NS_LOG_FUNCTION (this);
     Ipv6InterfaceContainer retval;
     for (uint32_t i = 0; i < c.GetN (); ++i) 
       {
         Ptr<NetDevice> device = c.Get (i);
   
         Ptr<Node> node = device->GetNode ();
         NS_ASSERT_MSG (node, "Ipv6AddressHelper::Allocate (): Bad node");
   
         Ptr<Ipv6> ipv6 = node->GetObject<Ipv6> ();
         NS_ASSERT_MSG (ipv6, "Ipv6AddressHelper::Allocate (): Bad ipv6");
   
         int32_t ifIndex = ipv6->GetInterfaceForDevice (device);
         if (ifIndex == -1)
           {
             ifIndex = ipv6->AddInterface (device);
           }
         NS_ASSERT_MSG (ifIndex >= 0, "Ipv6AddressHelper::Allocate (): "
                        "Interface index not found");
   
         ipv6->SetMetric (ifIndex, 1);
   
         if (withConfiguration.at (i))
           {
             Ipv6InterfaceAddress ipv6Addr = Ipv6InterfaceAddress (NewAddress (device->GetAddress ()), Ipv6Prefix (64));
             ipv6->AddAddress (ifIndex, ipv6Addr);
           }
   
         ipv6->SetUp (ifIndex);
         retval.Add (ipv6, ifIndex);
   
         // Install the default traffic control configuration if the traffic
         // control layer has been aggregated, if this is not
         // a loopback interface, and there is no queue disc installed already
         Ptr<TrafficControlLayer> tc = node->GetObject<TrafficControlLayer> ();
         if (tc && DynamicCast<LoopbackNetDevice> (device) == 0 && tc->GetRootQueueDiscOnDevice (device) == 0)
           {
             NS_LOG_LOGIC ("Installing default traffic control configuration");
             TrafficControlHelper tcHelper = TrafficControlHelper::Default ();
             tcHelper.Install (device);
          }
       }
     return retval;
   }
   
   // Helper API that is redundant with Assign (c, false);
   Ipv6InterfaceContainer Ipv6AddressHelper::AssignWithoutAddress (const NetDeviceContainer &c)
   {
     NS_LOG_FUNCTION (this);
     std::vector<bool> withConfiguration;
     for (uint32_t i = 0; i < c.GetN (); ++i) 
       {
         withConfiguration.push_back (false);
       }
     return Assign (c, withConfiguration);
   }

