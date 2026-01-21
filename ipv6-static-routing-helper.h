
    #define IPV6_STATIC_ROUTING_HELPER_H
    
    #include "ipv6.h"
    #include "ipv6-static-routing.h"
    #include "ptr.h"
    #include "ipv6-address.h"
    #include "node.h"
    #include "net-device.h"
    
    #include "node-container.h"
    #include "net-device-container.h"
    #include "ipv6-routing-helper.h"
    
  
    class Ipv6StaticRoutingHelper : public Ipv6RoutingHelper
    {
    public:
      Ipv6StaticRoutingHelper ();
    
      Ipv6StaticRoutingHelper (const Ipv6StaticRoutingHelper &);
    
      Ipv6StaticRoutingHelper* Copy (void) const;
    
      virtual Ptr<Ipv6RoutingProtocol> Create (Ptr<Node> node) const;
    
      Ptr<Ipv6StaticRouting> GetStaticRouting (Ptr<Ipv6> ipv6) const;
  /*  
      void AddMulticastRoute (Ptr<Node> n, Ipv6Address source, Ipv6Address group,
                             Ptr<NetDevice> input, NetDeviceContainer output);
    
    void AddMulticastRoute (std::string n, Ipv6Address source, Ipv6Address group,
                             Ptr<NetDevice> input, NetDeviceContainer output);
   
     void AddMulticastRoute (Ptr<Node> n, Ipv6Address source, Ipv6Address group,
                             std::string inputName, NetDeviceContainer output);
   
     void AddMulticastRoute (std::string nName, Ipv6Address source, Ipv6Address group,
                             std::string inputName, NetDeviceContainer output);
   */
   #if 0
   
     void SetDefaultMulticastRoute (Ptr<Node> n, Ptr<NetDevice> nd);
     void SetDefaultMulticastRoute (Ptr<Node> n, std::string ndName);
     void SetDefaultMulticastRoute (std::string nName, Ptr<NetDevice> nd);
     void SetDefaultMulticastRoute (std::string nName, std::string ndName);
   #endif
   private:
     Ipv6StaticRoutingHelper &operator = (const Ipv6StaticRoutingHelper &o);
   };
   
