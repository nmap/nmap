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
     * modified by Tom Henderson for ns-3.14 release
     */
    
    #ifndef IPV6_ADDRESS_HELPER_H
    #define IPV6_ADDRESS_HELPER_H
    
    #include <vector>
    
    #include "ipv6-address.h"
    #include "net-device-container.h"
    #include "ipv6-interface-container.h"
    
   
    
    class Ipv6AddressHelper
    {
    public:
      Ipv6AddressHelper ();
    
      Ipv6AddressHelper (Ipv6Address network, Ipv6Prefix prefix,  
                         Ipv6Address base = Ipv6Address ("::1"));
   
     void SetBase (Ipv6Address network, Ipv6Prefix prefix,
                   Ipv6Address base = Ipv6Address ("::1"));
   
     void NewNetwork (void);
   
    Ipv6Address NewAddress (Address addr);
   
     Ipv6Address NewAddress (void);
   
     Ipv6InterfaceContainer Assign (const NetDeviceContainer &c);
   
     Ipv6InterfaceContainer Assign (const NetDeviceContainer &c, std::vector<bool> withConfiguration);
   
     Ipv6InterfaceContainer AssignWithoutAddress (const NetDeviceContainer &c);
   
   };
   
   #endif /* IPV6_ADDRESS_STATIC_H */
