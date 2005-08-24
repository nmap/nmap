/********************************************************************/
/**                     Microsoft LAN Manager                      **/
/**               Copyright(c) Microsoft Corp., 1990-1999          **/
/********************************************************************/
/* :ts=4 */

//** IPEXPORT.H - IP public definitions.
//
//  This file contains public definitions exported to transport layer and
//  application software.
//

#ifndef IP_EXPORT_INCLUDED
#define IP_EXPORT_INCLUDED  1

#if _MSC_VER > 1000
#pragma once
#endif

//#include <windef.h> // for FAR decl
#undef FAR
#define FAR

//
// IP type definitions.
//
typedef unsigned long   IPAddr;     // An IP address.
typedef unsigned long   IPMask;     // An IP subnet mask.
typedef unsigned long   IP_STATUS;  // Status code returned from IP APIs.


/*INC*/

//
// The ip_option_information structure describes the options to be
// included in the header of an IP packet. The TTL, TOS, and Flags
// values are carried in specific fields in the header. The OptionsData
// bytes are carried in the options area following the standard IP header.
// With the exception of source route options, this data must be in the
// format to be transmitted on the wire as specified in RFC 791. A source
// route option should contain the full route - first hop thru final
// destination - in the route data. The first hop will be pulled out of the
// data and the option will be reformatted accordingly. Otherwise, the route
// option should be formatted as specified in RFC 791.
//
struct ip_option_information {
    unsigned char      Ttl;             // Time To Live
    unsigned char      Tos;             // Type Of Service
    unsigned char      Flags;           // IP header flags
    unsigned char      OptionsSize;     // Size in bytes of options data
    unsigned char FAR *OptionsData;     // Pointer to options data
}; /* ip_option_information */

//
// The icmp_echo_reply structure describes the data returned in response
// to an echo request.
//
struct icmp_echo_reply {
    IPAddr                         Address;         // Replying address
    unsigned long                  Status;          // Reply IP_STATUS
    unsigned long                  RoundTripTime;   // RTT in milliseconds
    unsigned short                 DataSize;        // Reply data size in bytes
    unsigned short                 Reserved;        // Reserved for system use
    void FAR                      *Data;            // Pointer to the reply data
    struct ip_option_information   Options;         // Reply options
}; /* icmp_echo_reply */


/*NOINC*/

typedef struct ip_option_information IP_OPTION_INFORMATION,
                                     FAR *PIP_OPTION_INFORMATION;

typedef struct icmp_echo_reply ICMP_ECHO_REPLY,
                               FAR *PICMP_ECHO_REPLY;

/*INC*/



struct ArpRequestBuffer {
   IPAddr DestAddress;
   IPAddr SrcAddress;
}; /* ArpRequestBuffer */

/*NOINC*/

typedef struct ArpRequestBuffer ARP_SEND_REPLY,
                               FAR *PARP_SEND_REPLY;

typedef struct _TCP_RESERVE_PORT_RANGE
{

   USHORT  UpperRange;
   USHORT  LowerRange;
}TCP_RESERVE_PORT_RANGE, *PTCP_RESERVE_PORT_RANGE;

#define MAX_ADAPTER_NAME 128

typedef struct _IP_ADAPTER_INDEX_MAP
{
   ULONG Index;
   WCHAR  Name[MAX_ADAPTER_NAME];
}IP_ADAPTER_INDEX_MAP, *PIP_ADAPTER_INDEX_MAP;

typedef struct _IP_INTERFACE_INFO
{
     LONG    NumAdapters;
     IP_ADAPTER_INDEX_MAP Adapter[1];
} IP_INTERFACE_INFO,*PIP_INTERFACE_INFO;

typedef struct _IP_UNIDIRECTIONAL_ADAPTER_ADDRESS
{
     ULONG    NumAdapters;
     IPAddr  Address[1];
} IP_UNIDIRECTIONAL_ADAPTER_ADDRESS, *PIP_UNIDIRECTIONAL_ADAPTER_ADDRESS;

typedef struct _IP_ADAPTER_ORDER_MAP
{
    ULONG NumAdapters;
    ULONG AdapterOrder[1];
} IP_ADAPTER_ORDER_MAP, *PIP_ADAPTER_ORDER_MAP;

//
// IP_STATUS codes returned from IP APIs
//

#define IP_STATUS_BASE              11000

#define IP_SUCCESS                  0
#define IP_BUF_TOO_SMALL            (IP_STATUS_BASE + 1)
#define IP_DEST_NET_UNREACHABLE     (IP_STATUS_BASE + 2)
#define IP_DEST_HOST_UNREACHABLE    (IP_STATUS_BASE + 3)
#define IP_DEST_PROT_UNREACHABLE    (IP_STATUS_BASE + 4)
#define IP_DEST_PORT_UNREACHABLE    (IP_STATUS_BASE + 5)
#define IP_NO_RESOURCES             (IP_STATUS_BASE + 6)
#define IP_BAD_OPTION               (IP_STATUS_BASE + 7)
#define IP_HW_ERROR                 (IP_STATUS_BASE + 8)
#define IP_PACKET_TOO_BIG           (IP_STATUS_BASE + 9)
#define IP_REQ_TIMED_OUT            (IP_STATUS_BASE + 10)
#define IP_BAD_REQ                  (IP_STATUS_BASE + 11)
#define IP_BAD_ROUTE                (IP_STATUS_BASE + 12)
#define IP_TTL_EXPIRED_TRANSIT      (IP_STATUS_BASE + 13)
#define IP_TTL_EXPIRED_REASSEM      (IP_STATUS_BASE + 14)
#define IP_PARAM_PROBLEM            (IP_STATUS_BASE + 15)
#define IP_SOURCE_QUENCH            (IP_STATUS_BASE + 16)
#define IP_OPTION_TOO_BIG           (IP_STATUS_BASE + 17)
#define IP_BAD_DESTINATION          (IP_STATUS_BASE + 18)


//
// The next group are status codes passed up on status indications to
// transport layer protocols.
//
#define IP_ADDR_DELETED             (IP_STATUS_BASE + 19)
#define IP_SPEC_MTU_CHANGE          (IP_STATUS_BASE + 20)
#define IP_MTU_CHANGE               (IP_STATUS_BASE + 21)
#define IP_UNLOAD                   (IP_STATUS_BASE + 22)
#define IP_ADDR_ADDED               (IP_STATUS_BASE + 23)
#define IP_MEDIA_CONNECT            (IP_STATUS_BASE + 24)
#define IP_MEDIA_DISCONNECT         (IP_STATUS_BASE + 25)
#define IP_BIND_ADAPTER             (IP_STATUS_BASE + 26)
#define IP_UNBIND_ADAPTER           (IP_STATUS_BASE + 27)
#define IP_DEVICE_DOES_NOT_EXIST    (IP_STATUS_BASE + 28)
#define IP_DUPLICATE_ADDRESS        (IP_STATUS_BASE + 29)
#define IP_INTERFACE_METRIC_CHANGE  (IP_STATUS_BASE + 30)
#define IP_RECONFIG_SECFLTR         (IP_STATUS_BASE + 31)
#define IP_NEGOTIATING_IPSEC        (IP_STATUS_BASE + 32)
#define IP_INTERFACE_WOL_CAPABILITY_CHANGE  (IP_STATUS_BASE + 33)
#define IP_DUPLICATE_IPADD          (IP_STATUS_BASE + 34)

#define IP_GENERAL_FAILURE          (IP_STATUS_BASE + 50)
#define MAX_IP_STATUS               IP_GENERAL_FAILURE
#define IP_PENDING                  (IP_STATUS_BASE + 255)


//
// Values used in the IP header Flags field.
//
#define IP_FLAG_DF      0x2         // Don't fragment this packet.

//
// Supported IP Option Types.
//
// These types define the options which may be used in the OptionsData field
// of the ip_option_information structure.  See RFC 791 for a complete
// description of each.
//
/* THESE ARE DEFINED IN DNET -- SO EXCLUDED
#define IP_OPT_EOL      0          // End of list option
#define IP_OPT_NOP      1          // No operation
#define IP_OPT_SECURITY 0x82       // Security option
#define IP_OPT_LSRR     0x83       // Loose source route
#define IP_OPT_SSRR     0x89       // Strict source route
#define IP_OPT_RR       0x7        // Record route
#define IP_OPT_TS       0x44       // Timestamp
#define IP_OPT_SID      0x88       // Stream ID (obsolete)
#define IP_OPT_ROUTER_ALERT 0x94  // Router Alert Option
*/

#define MAX_OPT_SIZE    40         // Maximum length of IP options in bytes

#ifdef CHICAGO

// Ioctls code exposed by Memphis tcpip stack.
// For NT these ioctls are define in ntddip.h  (private\inc)

#define IOCTL_IP_RTCHANGE_NOTIFY_REQUEST   101
#define IOCTL_IP_ADDCHANGE_NOTIFY_REQUEST  102
#define IOCTL_ARP_SEND_REQUEST             103
#define IOCTL_IP_INTERFACE_INFO            104
#define IOCTL_IP_GET_BEST_INTERFACE        105
#define IOCTL_IP_UNIDIRECTIONAL_ADAPTER_ADDRESS        106

#endif


#endif // IP_EXPORT_INCLUDED
