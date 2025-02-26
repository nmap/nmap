
/***************************************************************************
 * NpingTarget.cc -- The NpingTarget class encapsulates much of the        *
 * information Nping has about a host. Things like next hop address or the *
 * network interface that should be used to send probes to the target, are *
 * stored in this class as they are determined.                            *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *
 * The Nmap Security Scanner is (C) 1996-2025 Nmap Software LLC ("The Nmap
 * Project"). Nmap is also a registered trademark of the Nmap Project.
 *
 * This program is distributed under the terms of the Nmap Public Source
 * License (NPSL). The exact license text applying to a particular Nmap
 * release or source code control revision is contained in the LICENSE
 * file distributed with that version of Nmap or source code control
 * revision. More Nmap copyright/legal information is available from
 * https://nmap.org/book/man-legal.html, and further information on the
 * NPSL license itself can be found at https://nmap.org/npsl/ . This
 * header summarizes some key points from the Nmap license, but is no
 * substitute for the actual license text.
 *
 * Nmap is generally free for end users to download and use themselves,
 * including commercial use. It is available from https://nmap.org.
 *
 * The Nmap license generally prohibits companies from using and
 * redistributing Nmap in commercial products, but we sell a special Nmap
 * OEM Edition with a more permissive license and special features for
 * this purpose. See https://nmap.org/oem/
 *
 * If you have received a written Nmap license agreement or contract
 * stating terms other than these (such as an Nmap OEM license), you may
 * choose to use and redistribute Nmap under those terms instead.
 *
 * The official Nmap Windows builds include the Npcap software
 * (https://npcap.com) for packet capture and transmission. It is under
 * separate license terms which forbid redistribution without special
 * permission. So the official Nmap Windows builds may not be redistributed
 * without special permission (such as an Nmap OEM license).
 *
 * Source is provided to this software because we believe users have a
 * right to know exactly what a program is going to do before they run it.
 * This also allows you to audit the software for security holes.
 *
 * Source code also allows you to port Nmap to new platforms, fix bugs, and
 * add new features. You are highly encouraged to submit your changes as a
 * Github PR or by email to the dev@nmap.org mailing list for possible
 * incorporation into the main distribution. Unless you specify otherwise, it
 * is understood that you are offering us very broad rights to use your
 * submissions as described in the Nmap Public Source License Contributor
 * Agreement. This is important because we fund the project by selling licenses
 * with various terms, and also because the inability to relicense code has
 * caused devastating problems for other Free Software projects (such as KDE
 * and NASM).
 *
 * The free version of Nmap is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Warranties,
 * indemnification and commercial support are all available through the
 * Npcap OEM program--see https://nmap.org/oem/
 *
 ***************************************************************************/


#ifdef WIN32
#include "nping_winconfig.h"
#endif

#ifndef FQDN_LEN
#define FQDN_LEN 254
#endif

#include "NpingTarget.h"
#include <dnet.h>
#include "nbase.h"
#include "nping.h"
#include "output.h"
#include "common.h"
#include "stats.h"
#include "common_modified.h"



/** Constructor */
NpingTarget::NpingTarget() {
  this->Initialize();
} /* End of NpingTarget constructor */


/** Initializes object attributes  */
void NpingTarget::Initialize() {
  memset(this->devname, 0, sizeof(this->devname));
  memset(this->devfullname, 0, sizeof(this->devfullname));
  dev_type=devt_other;
  directly_connected = -1;
  distance = -1;
  nameIPBuf = NULL;
  hostname = NULL;
  namedhost=-1;
  targetname = NULL;
  addressfamily=-1;
  memset(&targetsock, 0, sizeof(targetsock));
  memset(&sourcesock, 0, sizeof(sourcesock));
  memset(&spoofedsrcsock, 0, sizeof(spoofedsrcsock));
  memset(&nexthopsock, 0, sizeof(nexthopsock));
  targetsocklen = 0;
  sourcesocklen = 0;
  spoofedsrcsocklen=0;
  nexthopsocklen = 0;
  spoofedsrc_set=false;
  memset(this->targetipstring, 0, INET6_ADDRSTRLEN);
  targetipstring_set=false;
  memset(&MACaddress, 0, sizeof(MACaddress));
  memset(&SrcMACaddress, 0, sizeof(SrcMACaddress));
  memset(&NextHopMACaddress, 0, sizeof(NextHopMACaddress));
  MACaddress_set = false;
  SrcMACaddress_set = false;
  NextHopMACaddress_set = false;
  icmp_id = get_random_u16();
  icmp_seq = 1;
  memset(sentprobes, 0, sizeof(pktstat_t)* MAX_SENTPROBEINFO_ENTRIES);
  current_stat=0;
  total_stats=0;
  sent_total=0;
  recv_total=0;
  max_rtt=0;
  max_rtt_set=false;
  min_rtt=0;
  min_rtt_set=false;
  avg_rtt=0;
  avg_rtt_set=false;
} /* End of Initialize() */


/** Recycles the object by freeing internal objects and reinitializing
  * to default state */
void NpingTarget::Recycle() {
  this->FreeInternal();
  this->Initialize();
} /* End of Recycle() */


/** Destructor */
NpingTarget::~NpingTarget() {
  this->FreeInternal();
} /* End of NpingTarget destructor */


/** Frees memory allocated inside this object */
void NpingTarget::FreeInternal() {
  /* Free the DNS name if we resolved one */
  if (hostname){
    free(hostname);
    hostname=NULL;
  }
  /* Free user supplied host name if we got one */
  if (targetname){
    free(targetname);
    targetname=NULL;
  }
  /* Free IP-Name info string */
  if (nameIPBuf) {
    free(nameIPBuf);
    nameIPBuf = NULL;
  }
} /* End of FreeInternal() */


/** Fills a sockaddr_storage with the AF_INET or AF_INET6 address
     information of the target.  This is a preferred way to get the
     address since it is portable for IPv6 hosts.  Returns 0 for
     success. ss_len must be provided.  It is not examined, but is set
     to the size of the sockaddr copied in. */
int NpingTarget::getTargetSockAddr(struct sockaddr_storage *ss, size_t *ss_len) {
  assert(ss);
  assert(ss_len);  
  if (targetsocklen <= 0)
    return 1;
  assert(targetsocklen <= sizeof(*ss));
  memcpy(ss, &targetsock, targetsocklen);
  *ss_len = targetsocklen;
  return 0;

} /* End of getTargetSockAddr() */


/** Note that it is OK to pass in a sockaddr_in or sockaddr_in6 casted
     to sockaddr_storage */
int NpingTarget::setTargetSockAddr(struct sockaddr_storage *ss, size_t ss_len) {
  assert(ss_len > 0 && ss_len <= sizeof(*ss));
  struct sockaddr_in *tmp=(struct sockaddr_in *)ss;
  this->addressfamily=tmp->sin_family;
  memcpy(&targetsock, ss, ss_len);
  targetsocklen = ss_len;
  generateIPString();
  return OP_SUCCESS;
} /* End of setTargetSockAddr() */


/** Returns IPv4 host address or {0} if unavailable. */
struct in_addr NpingTarget::getIPv4Address() {
  const struct in_addr *addy = getIPv4Address_aux();
  struct in_addr in;
  if (addy) return *addy;
  in.s_addr = 0;
  return in;
} /* End of getIPv4Address() */


/** Aux function for getIPv4Address() */
const struct in_addr *NpingTarget::getIPv4Address_aux(){
  struct sockaddr_in *sin = (struct sockaddr_in *) &targetsock;
  if (sin->sin_family == AF_INET) {
    return &(sin->sin_addr);
  }
  return NULL;
} /* End of getIPv4Address_aux() */


u8 *NpingTarget::getIPv6Address_u8(){
  const struct in6_addr *in = getIPv6Address_aux();
  if( in==NULL )
    return NULL;
  else
    return (u8*)in->s6_addr;
} /* End of getIPv6Address_u8() */


/** Returns IPv6 host address or {0} if unavailable. */
struct in6_addr NpingTarget::getIPv6Address() {
  const struct in6_addr *addy = getIPv6Address_aux();
  struct in6_addr in;
  if (addy) return *addy;
  memset(&in, 0, sizeof(struct in6_addr));
  return in;
} /* End of getIPv6Address() */


/** Aux function for getIPv6Address() */
const struct in6_addr *NpingTarget::getIPv6Address_aux(){
  struct sockaddr_in6 *sin = (struct sockaddr_in6 *) &targetsock;
  if (sin->sin6_family == AF_INET6) {
    return &(sin->sin6_addr);
  }
  return NULL;
} /* End of getIPv6Address_aux() */


/** Get source address used to reach the target.  */
int NpingTarget::getSourceSockAddr(struct sockaddr_storage *ss, size_t *ss_len) {
  if (sourcesocklen <= 0)
    return 1;
  assert(sourcesocklen <= sizeof(*ss));
  if (ss)
    memcpy(ss, &sourcesock, sourcesocklen);
  if (ss_len)
    *ss_len = sourcesocklen;
  return 0;
} /* End of getSourceSockAddr() */


/** Set source address used to reach the target.
  * Note that it is OK to pass in a sockaddr_in or sockaddr_in6 casted
  * to sockaddr_storage */
int NpingTarget::setSourceSockAddr(struct sockaddr_storage *ss, size_t ss_len) {
  assert(ss_len > 0 && ss_len <= sizeof(*ss));
  memcpy(&sourcesock, ss, ss_len);
  sourcesocklen = ss_len;
  return OP_SUCCESS;
} /* End of setSourceSockAddr() */


/** Set source address used to reach the target.
  * Note that it is OK to pass in a sockaddr_in or sockaddr_in6 casted
  * to sockaddr_storage */
int NpingTarget::setSpoofedSourceSockAddr(struct sockaddr_storage *ss, size_t ss_len) {
  assert(ss_len > 0 && ss_len <= sizeof(*ss));
  memcpy(&spoofedsrcsock, ss, ss_len);
  spoofedsrcsocklen = ss_len;
  this->spoofedsrc_set=true;
  return OP_SUCCESS;
} /* End of setSpoofedSourceSockAddr() */


/** Get source address used to reach the target.  */
int NpingTarget::getSpoofedSourceSockAddr(struct sockaddr_storage *ss, size_t *ss_len) {
  if (spoofedsrcsocklen <= 0)
    return 1;
  assert(spoofedsrcsocklen <= sizeof(*ss));
  if (ss)
    memcpy(ss, &spoofedsrcsock, spoofedsrcsocklen);
  if (ss_len)
    *ss_len = spoofedsrcsocklen;
  return 0;
} /* End of getSpoofedSourceSockAddr() */


bool NpingTarget::spoofingSourceAddress(){
  return this->spoofedsrc_set;
} /* End of spoofingSourceAddress()*/


/** Returns IPv4 host address or {0} if unavailable. */
struct in_addr NpingTarget::getIPv4SourceAddress() {
  const struct in_addr *addy = getIPv4SourceAddress_aux();
  struct in_addr in;
  if (addy) return *addy;
  in.s_addr = 0;
  return in;
} /* End of getIPv4SourceAddress() */


/** Returns IPv4 host address or NULL if unavailable.*/
const struct in_addr *NpingTarget::getIPv4SourceAddress_aux() {
  struct sockaddr_in *sin = (struct sockaddr_in *) &sourcesock;
  if (sin->sin_family == AF_INET) {
    return &(sin->sin_addr);
  }
  return NULL;
} /* End of getIPv4SourceAddress_aux() */




/** Returns IPv4 host address or {0} if unavailable. */
struct in_addr NpingTarget::getIPv4SpoofedSourceAddress() {
  const struct in_addr *addy = getIPv4SpoofedSourceAddress_aux();
  struct in_addr in;
  if (addy) return *addy;
  in.s_addr = 0;
  return in;
} /* End of getIPv4SourceAddress() */


/** Returns IPv4 host address or NULL if unavailable.*/
const struct in_addr *NpingTarget::getIPv4SpoofedSourceAddress_aux() {
  struct sockaddr_in *sin = (struct sockaddr_in *) &spoofedsrcsock;
  if (sin->sin_family == AF_INET) {
    return &(sin->sin_addr);
  }
  return NULL;
} /* End of getIPv4SpoofedSourceAddress_aux() */


/** Returns IPv6 host address or {0} if unavailable. */
struct in6_addr NpingTarget::getIPv6SourceAddress() {
  const struct in6_addr *addy = getIPv6SourceAddress_aux();
  struct in6_addr in;
  if (addy) return *addy;
  memset(&in, 0, sizeof(struct in6_addr));
  return in;
} /* End of getIPv6SourceAddress() */


/** Returns IPv6 host address or NULL if unavailable.*/
const struct in6_addr *NpingTarget::getIPv6SourceAddress_aux() {
  struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &sourcesock;
  if (sin6->sin6_family == AF_INET) {
    return &(sin6->sin6_addr);
  }
  return NULL;
} /* End of getIPv6SourceAddress_aux() */


u8 *NpingTarget::getIPv6SourceAddress_u8(){
  const struct in6_addr *in = getIPv6SourceAddress_aux();
  if( in==NULL )
    return NULL;
  else
    return (u8*)in->s6_addr;
} /* End of getIPv6Address_u8() */


/** If the host is directly connected on a network, set and retrieve
  * that information here.  directlyConnected() will abort if it hasn't
  * been set yet.  */
void NpingTarget::setDirectlyConnected(bool connected) {
  directly_connected = (connected) ? 1 : 0;
} /* End of setDirectlyConnected() */


int NpingTarget::isDirectlyConnectedOrUnset(){
  return directly_connected;
} /* End of isDirectlyConnectedOrUnset() */


bool NpingTarget::isDirectlyConnected() {
  assert(directly_connected == 0 || directly_connected == 1);
  return directly_connected;
} /* End of isDirectlyConnected() */


/** Returns the next hop for sending packets to this host.  Returns true if
  * next_hop was filled in.  It might be false, for example, if
  * next_hop has never been set */
bool NpingTarget::getNextHop(struct sockaddr_storage *next_hop, size_t *next_hop_len) {
  if (nexthopsocklen <= 0)
    return false;
  assert(nexthopsocklen <= sizeof(*next_hop));
  if (next_hop)
    memcpy(next_hop, &nexthopsock, nexthopsocklen);
  if (next_hop_len)
    *next_hop_len = nexthopsocklen;
  return true;
} /* End of getNextHop() */


/** Sets the next hop for sending packets to this host. Note that it is OK to
  *  pass in a sockaddr_in or sockaddr_in6 casted to sockaddr_storage */
void NpingTarget::setNextHop(struct sockaddr_storage *next_hop, size_t next_hop_len) {
  assert(next_hop_len > 0 && next_hop_len <= sizeof(nexthopsock));
  memcpy(&nexthopsock, next_hop, next_hop_len);
  nexthopsocklen = next_hop_len;
} /* End of setNextHop() */


/** Sets next hop MAC address
 *  @warning addy must contain at least 6 bytes. */
int NpingTarget::setNextHopMACAddress(const u8 *addy) {
  if (addy==NULL)
    return OP_FAILURE;
  memcpy(NextHopMACaddress, addy, 6);
  NextHopMACaddress_set = 1;
  return OP_SUCCESS;
} /* End of setNextHopMACAddress() */


/** Returns a pointer to a 6 byte buffer that contains next hop MAC address */
const u8 *NpingTarget::getNextHopMACAddress() {
  return (NextHopMACaddress_set)? NextHopMACaddress : NULL;
} /* End of getNextHopMACAddress() */


/** Sets target MAC address.
  * Returns OP_SUCCESS if MAC address set successfully and OP_FAILURE in case
  * of error. */
int NpingTarget::setMACAddress(const u8 *addy) {
  if (addy==NULL)
    return OP_FAILURE;
  memcpy(MACaddress, addy, 6);
  MACaddress_set = 1;
  return OP_SUCCESS;
} /* End of setMACAddress() */


/** Returns the 6-byte long MAC address, or NULL if none has been set */
const u8 *NpingTarget::getMACAddress(){
  return (MACaddress_set)? MACaddress : NULL;
} /* End of getMACAddress() */


/** Sets the MAC address that should be used when sending raw ethernet frames
 *  from this host to the target.
  * Returns OP_SUCCESS if MAC address set successfully and OP_FAILURE in case
  * of error. */
int NpingTarget::setSrcMACAddress(const u8 *addy) {
  if (addy==NULL)
    return OP_FAILURE;
  memcpy(SrcMACaddress, addy, 6);
  SrcMACaddress_set = 1;
  return OP_SUCCESS;
} /* End of setSrcMACAddress() */


/** Returns the 6-byte long Source MAC address, or NULL if none has been set */
const u8 *NpingTarget::getSrcMACAddress() {
  return (SrcMACaddress_set)? SrcMACaddress : NULL;
} /* End of getSrcMACAddress() */


/** Set the device names so that they can be returned by deviceName()
    and deviceFullName().  The normal name may not include alias
    qualifier, while the full name may include it (e.g. "eth1:1").  If
    these are non-null, they will overwrite the stored version */
void NpingTarget::setDeviceNames(const char *name, const char *fullname) {
  if (name)
      Strncpy(devname, name, sizeof(devname));
  if (fullname)
      Strncpy(devfullname, fullname, sizeof(devfullname));
} /* End of setDeviceNames() */


/** Returns device normal name (e.g. eth0) */
const char * NpingTarget::getDeviceName() {
  return (devname[0] != '\0')? devname : NULL;
} /* End of getDeviceName() */


/** Returns device full name (e.g. eth0:1) */
const char * NpingTarget::getDeviceFullName() {
  return (devfullname[0] != '\0')? devfullname : NULL;
} /* End of getDeviceFullName() */


int NpingTarget::setDeviceType(devtype type){
  this->dev_type = type;
  return OP_SUCCESS;
} /* End of setDeviceType() */


devtype NpingTarget::getDeviceType(){
  return this->dev_type;
} /* End of getDeviceType() */


/** Set target resolved host name. You can set to NULL to erase a name or if
  * it failed to resolve, or just don't call this if it fails to resolve */
void NpingTarget::setResolvedHostName(char *name) {
  char *p;
  if (hostname) {
    free(hostname);
    hostname = NULL;
  }
  if (name) {
    p = hostname = strdup(name);
    while (*p) {
      // I think only a-z A-Z 0-9 . and - are allowed, but I'll be a little more
      // generous.
      if (!isalnum(*p) && !strchr(".-+=:_~*", *p)) {
    nping_warning(QT_2, "Illegal character(s) in hostname -- replacing with '*'\n");
    *p = '*';
      }
      p++;
    }
  }
} /* End of setResolvedHostName() */


/** Give the name from the last setHostName() call, which should be
    the name obtained from reverse-resolution (PTR query) of the IP (v4
    or v6).  If the name has not been set, or was set to NULL, an empty
    string ("") is returned to make printing easier. */
const char *NpingTarget::getResolvedHostName(){
  return hostname? hostname : "";
} /* End of getResolvedHostName() */


/** Set user supplied host name. You can set to NULL to erase a name. */
int NpingTarget::setSuppliedHostName(char *name) {
  if(name==NULL)
    return OP_FAILURE;
  if (targetname) {
    free(targetname);
    targetname = NULL;
  }
  targetname = strdup(name);
  return OP_SUCCESS;
} /* End of setSuppliedHostName() */


/** Give the name from the last setTargetName() call, which is the 
    name of the target given on the command line if it's a named
    host. */
const char *NpingTarget::getSuppliedHostName(){
  return targetname;
} /* End of getSuppliedHostName() */


int NpingTarget::setNamedHost(bool val){
  this->namedhost= (val)? 1 : 0;
  return OP_SUCCESS;
} /* End of setNamedHost() */


bool NpingTarget::isNamedHost(){
  assert(this->namedhost==1 || this->namedhost==0 );
  return (this->namedhost==1);
} /* End of isNamedHost() */


/**  Creates a "presentation" formatted string out of the IPv4/IPv6 address.
    Called when the IP changes */
void NpingTarget::generateIPString() {
  const char *ret=NULL;    
  struct sockaddr_in *sin = (struct sockaddr_in *) &targetsock;
  struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &targetsock;
  if (sin->sin_family == AF_INET){
    ret=inet_ntop(AF_INET, (char *) &sin->sin_addr, targetipstring, sizeof(targetipstring));
  }else if(sin->sin_family == AF_INET6){
    ret=inet_ntop(AF_INET6, (char *) &sin6->sin6_addr, targetipstring, sizeof(targetipstring));
  }else{
    nping_fatal(QT_3, "NpingTarget::GenerateIPString(): Unsupported address family");
  }
  if( ret==NULL )
    nping_fatal(QT_3, "NpingTarget::GenerateIPString(): Unsupported address family");
 targetipstring_set=true;
} /* End of generateIPString() */


/**  Creates a "presentation" formatted string out of the IPv4/IPv6 address.
    Called when the IP changes */
const char *NpingTarget::getSourceIPStr() {
  static char buffer[256];
  const char *ret=NULL;
  struct sockaddr_in *sin = (struct sockaddr_in *) &sourcesock;
  struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &sourcesock;

  if (sin->sin_family == AF_INET){
    ret=inet_ntop(AF_INET, (char *) &sin->sin_addr, buffer, sizeof(buffer));
  }else if(sin->sin_family == AF_INET6){
    ret=inet_ntop(AF_INET6, (char *) &sin6->sin6_addr, buffer, sizeof(buffer));
  }else{
    nping_fatal(QT_3, "NpingTarget::getSourceIPString(): Unsupported address family");
  }
  if(ret==NULL)
    return NULL;
  else
    return buffer;
} /* End of getSourceIPStr() */




/**  Creates a "presentation" formatted string out of the IPv4/IPv6 address.
    Called when the IP changes */
const char *NpingTarget::getSpoofedSourceIPStr() {
  static char buffer[256];
  const char *ret=NULL;
  struct sockaddr_in *sin = (struct sockaddr_in *) &spoofedsrcsock;
  struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &spoofedsrcsock;

  if (sin->sin_family == AF_INET){
    ret=inet_ntop(AF_INET, (char *) &sin->sin_addr, buffer, sizeof(buffer));
  }else if(sin->sin_family == AF_INET6){
    ret=inet_ntop(AF_INET6, (char *) &sin6->sin6_addr, buffer, sizeof(buffer));
  }else{
    nping_fatal(QT_3, "NpingTarget::getSourceIPString(): Unsupported address family");
  }
  if(ret==NULL)
    return NULL;
  else
    return buffer;
} /* End of getSpoofedSourceIPStr() */


const char *NpingTarget::getNextHopIPStr(){
  static char buffer[256];
  const char *ret=NULL;
  struct sockaddr_in *sin = (struct sockaddr_in *) &nexthopsock;
  struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) &nexthopsock;
  if (sin->sin_family == AF_INET){
    ret=inet_ntop(AF_INET, (char *) &sin->sin_addr, buffer, sizeof(buffer));
  }else if(sin->sin_family == AF_INET6){
    ret=inet_ntop(AF_INET6, (char *) &sin6->sin6_addr, buffer, sizeof(buffer));
  }else{
    nping_fatal(QT_3, "NpingTarget::getNextHopIPStr(): Unsupported address family");
  }
  if(ret==NULL)
    return NULL;
  else
    return buffer;
} /* End of getNextHopIPStr() */


const char *NpingTarget::getMACStr(u8 *mac){
  static char buffer[256];
  assert(mac!=NULL);
  sprintf(buffer, "%02x:%02x:%02x:%02x:%02x:%02x", (u8)mac[0],(u8)mac[1],
          (u8)mac[2], (u8)mac[4],(u8)mac[4],(u8)mac[5]);
  return buffer;
}

const char *NpingTarget::getTargetMACStr(){
    return getMACStr(this->MACaddress);
}


const char *NpingTarget::getSourceMACStr(){
    return getMACStr(this->SrcMACaddress);
}


const char *NpingTarget::getNextHopMACStr(){
    return getMACStr(this->NextHopMACaddress);
}


/** Returns a "presentation" formatted string for the targetIPv4/IPv6 address. */
const char *NpingTarget::getTargetIPstr(){
  if( targetipstring_set == false )
    this->generateIPString();
  return targetipstring;
} /* End of getTargetIPstr() */


/** Generates a printable string consisting of the host's IP address and
  * hostname (if available).  Eg "www.insecure.org (64.71.184.53)" or
  * "fe80::202:e3ff:fe14:1102".  The name is written into the buffer provided,
  * which is also returned.  Results that do not fit in buflen will be
  * truncated.
  */
const char *NpingTarget::getNameAndIP(char *buf, size_t buflen) {
  assert(buf);
  assert(buflen > 8);
  if (hostname) {
    Snprintf(buf, buflen, "%s (%s)", hostname, targetipstring);
  }else if (targetname){
    Snprintf(buf, buflen, "%s (%s)", targetname, targetipstring);
  }else Strncpy(buf, targetipstring, buflen);
  return buf;
} /* End of getNameAndIP() */

/** This next version returns a static buffer -- so no concurrency */
const char *NpingTarget::getNameAndIP() {
  if(!nameIPBuf)
    nameIPBuf = (char *)safe_malloc(FQDN_LEN + INET6_ADDRSTRLEN + 4);
  return getNameAndIP(nameIPBuf, FQDN_LEN + INET6_ADDRSTRLEN + 4);
} /* End of getNameAndIP() */


/* This method returns a number suitable to be used as a ICMP sequence field.
 * The first time this function is called, 1 is returned. The internal icmp_seq
 * attribute is incremented in every call so subsequent calls will return
 * n+1 where n is the value returned by last call. */
u16 NpingTarget::obtainICMPSequence() {
  return this->icmp_seq++;
} /* End of obtainICMPSequence() */


u16 NpingTarget::getICMPIdentifier(){
  return this->icmp_id;
} /* End of getICMPIdentifier()*/


/* This function ensures that the next hop MAC address for a target is
   filled in.  This address is the target's own MAC if it is directly
   connected, and the next hop mac otherwise.  Returns true if the
   address is set when the function ends, false if not.  This function
   firt checks if it is already set, if not it tries the arp cache,
   and if that fails it sends an ARP request itself.  This should be
   called after an ARP scan if many directly connected machines are
   involved. setDirectlyConnected() (whether true or false) should
   have already been called on target before this.  The target device
   and src mac address should also already be set.  */
bool NpingTarget::determineNextHopMACAddress() {
  struct sockaddr_storage targetss, srcss;
  size_t sslen;
  arp_t *a;
  u8 mac[6];
  struct arp_entry ae;

  if (this->getDeviceType() != devt_ethernet)
    return false; /* Duh. */

  /* First check if we already have it, duh. */
  if ( this->getNextHopMACAddress() )
    return true;

  nping_print(DBG_2,"Determining target %s MAC address or next hop MAC address...", this->getTargetIPstr() );
  /* For connected machines, it is the same as the target addy */
  if (this->isDirectlyConnected() && this->getMACAddress() ) {
    this->setNextHopMACAddress(this->getMACAddress());
    return true;
  }

  if (this->isDirectlyConnected()) {
    this->getTargetSockAddr(&targetss, &sslen);
  } else {
    if (!this->getNextHop(&targetss, &sslen))
      fatal("%s: Failed to determine nextHop to target", __func__);
  }

  /* First, let us check the ARP cache ... */
  if (mac_cache_get(&targetss, mac)) {
    this->setNextHopMACAddress(mac);
    return true;
  }

  /* Maybe the system ARP cache will be more helpful */
  nping_print(DBG_3,"    > Checking system's ARP cache...");
  a = arp_open();
  addr_ston((sockaddr *)&targetss, &ae.arp_pa);
  if (arp_get(a, &ae) == 0) {
    mac_cache_set(&targetss, ae.arp_ha.addr_eth.data);
    this->setNextHopMACAddress(ae.arp_ha.addr_eth.data);
    arp_close(a);
    nping_print(DBG_3,"    > Success: Entry found [%s]", this->getNextHopMACStr() );
    return true;
  }
  arp_close(a);
  nping_print(DBG_3,"    > No relevant entries found in system's ARP cache.");


  /* OK, the last choice is to send our own damn ARP request (and
     retransmissions if necessary) to determine the MAC */
  /* We first try sending the ARP with our spoofed IP address on it */
  if( this->spoofingSourceAddress() ){
    nping_print(DBG_3,"    > Sending ARP request using spoofed IP %s...", this->getSpoofedSourceIPStr() );
      this->getSpoofedSourceSockAddr(&srcss, NULL);
      if (doArp(this->getDeviceName(), this->getSrcMACAddress(), &srcss, &targetss, mac, NULL)) {
        mac_cache_set(&targetss, mac);
        this->setNextHopMACAddress(mac);
        nping_print(DBG_4,"    > Success: 1 ARP response received [%s]", this->getNextHopMACStr() );
        return true;
      }
  }
  nping_print(DBG_3,"    > No ARP responses received." );

  /* If our spoofed IP address didn't work, try our real IP */
  nping_print(DBG_4,"    > Sending ARP request using our real IP %s...", this->getSourceIPStr() );
  this->getSourceSockAddr(&srcss, NULL);
  if (doArp(this->getDeviceName(), this->getSrcMACAddress(), &srcss, &targetss, mac, NULL)) {
    mac_cache_set(&targetss, mac);
    this->setNextHopMACAddress(mac);
    nping_print(DBG_3,"    > Success: 1 ARP response received [%s]", this->getNextHopMACStr() );
    return true;
  }
  nping_print(DBG_3,"    > No ARP responses received" );

  /* I'm afraid that we couldn't find it!  Maybe it doesn't exist?*/
  return false;
}


/* Sets Target MAC if is directly connected to us. In that case, Next Hop MAC
 * address is copied into the target mac */
bool NpingTarget::determineTargetMACAddress() {
  if( this->isDirectlyConnected() ){
     if(this->NextHopMACaddress_set){
        memcpy(MACaddress, NextHopMACaddress, 6);
        return true;
    }
  }
  return false;
} /* End of determineTargetMACAddress() */ 


/* Prints target details. Used for testing. */
void NpingTarget::printTargetDetails(){
  devtype aux = this->getDeviceType();
  const char *type=NULL;

  switch(aux){
    case devt_ethernet: type="Ethernet"; break;
    case devt_loopback: type="Loopback"; break;
    case devt_p2p:      type="P2P";      break;
    default:    type="Unknown";  break;
  }

    printf("+-----------------TARGET-----------------+\n");
    printf("Device Name:            %s\n", this->getDeviceName() );
    printf("Device FullName:        %s\n", this->getDeviceFullName());
    printf("Device Type:            %s\n", type);
    printf("Directly connected?:    %s\n", this->isDirectlyConnected()? "yes" : "no");
    printf("Address family:         %s\n", this->addressfamily==AF_INET? "AF_INET" : "AF_INET6/OTHER");
    printf("Resolved Hostname:      %s\n", this->getResolvedHostName());
    printf("Supplied Hostname:      %s\n", this->getSuppliedHostName());
    printf("Target Address:         %s\n", this->getTargetIPstr());
    printf("Source Address:         %s\n", this->getSourceIPStr());
    if(this->spoofedsrc_set)
        printf("Spoofed Address:        %s\n", this->getSpoofedSourceIPStr() );
    printf("Next Hop Address:       %s\n", this->getNextHopIPStr());
    printf("Target MAC Address:     %s\n", this->getTargetMACStr());
    printf("Source MAC Address:     %s\n", this->getSourceMACStr());
    printf("Next Hop MAC Address:   %s\n", this->getNextHopMACStr());
   return;
} /* End of printTargetDetails() */





/* Update info about the last TCP probe sent */
int NpingTarget::setProbeSentTCP(u16 sport, u16 dport){
  this->sent_total++;
 /* Check if we already have an entry for the supplied dst port */
 for(int i=0; i<MAX_SENTPROBEINFO_ENTRIES && i<total_stats; i++){
    if( this->sentprobes[i].tcp_port==dport ){
        gettimeofday(&this->sentprobes[i].sent, NULL); /* overwrite previous value? TODO: think about this */
        return OP_SUCCESS;
    }
  }
  /* If we get here means that we don't have the dst port on our small
   * stats "cache", so we have to overwrite an existing port with this one */
  gettimeofday(&this->sentprobes[current_stat].sent, NULL);
  this->sentprobes[current_stat].tcp_port=dport;
  current_stat=(current_stat+1)%MAX_SENTPROBEINFO_ENTRIES;
  if( total_stats< MAX_SENTPROBEINFO_ENTRIES)
    total_stats++;
  return OP_SUCCESS;
} /* End of setProbeSentTCP() */


/* Update info about the last TCP probe received */
int NpingTarget::setProbeRecvTCP(u16 sport, u16 dport){
  int i=0;
  unsigned long int diff=0;
  this->recv_total++;
/* Let's see if we have the supplied source port in our stats "cache". */
 for(i=0; i<MAX_SENTPROBEINFO_ENTRIES; i++){
    if( this->sentprobes[i].tcp_port == sport ){
        gettimeofday(&this->sentprobes[i].recv, NULL);
          /* Update stats info */
          diff= TIMEVAL_SUBTRACT(this->sentprobes[i].recv, this->sentprobes[i].sent);
          this->updateRTTs(diff);

        return OP_SUCCESS;
    }
  }
  /* If we get here means that, for some reason, we don't have a tx time for
   * the received packet so there is no point on updating anything since we
   * cannot compute the rtt without the initial time. */
  return OP_FAILURE;
} /* End of setProbeRecvTCP() */


/* For the moment we are treating TCP and UDP the same way. However, this
 * function is provided just in case we want to differentiate in the future. */
int NpingTarget::setProbeRecvUDP(u16 sport, u16 dport){
    return this->setProbeRecvTCP(sport, dport);
} /* End of setProbeRecvUDP() */


/* For the moment we are treating TCP and UDP the same way. However, this
 * function is provided just in case we want to differentiate in the future. */
int NpingTarget::setProbeSentUDP(u16 sport, u16 dport){
    return this->setProbeSentTCP(sport, dport);
} /* End of setProbeSentUDP() */


/* Update info about the last ICMP probe sent */
int NpingTarget::setProbeSentICMP(u16 id, u16 seq){
  this->sent_total++;
 /* Check if we already have an entry for the supplied id and seq numbers */
 for(int i=0; i<MAX_SENTPROBEINFO_ENTRIES && i<total_stats; i++){
    if( this->sentprobes[i].icmp_id==id && this->sentprobes[i].icmp_seq==seq){
        gettimeofday(&this->sentprobes[i].sent, NULL); /* overwrite previous value? TODO: think about this */
        return OP_SUCCESS;
    }
  }
  /* If we get here means that we don't have the id/seq on our small
   * stats "cache", so we have to overwrite an existing entry with this one */
  gettimeofday(&this->sentprobes[current_stat].sent, NULL);
  this->sentprobes[current_stat].icmp_id=id;
  this->sentprobes[current_stat].icmp_seq=seq;
  current_stat=(current_stat+1)%MAX_SENTPROBEINFO_ENTRIES;
  if( total_stats< MAX_SENTPROBEINFO_ENTRIES)
    total_stats++;
  return OP_SUCCESS;
} /* End of setProbeSentARP() */




/* Update info about the last ICMP probe received */
int NpingTarget::setProbeRecvICMP(u16 id, u16 seq){
  int i= this->current_stat-1;
  unsigned long int diff=0;

  if( i<0 && total_stats>=MAX_SENTPROBEINFO_ENTRIES)
    i=MAX_SENTPROBEINFO_ENTRIES-1;

  gettimeofday(&this->sentprobes[i].recv, NULL);

  /* Update stats info */
  recv_total++;
  diff= TIMEVAL_SUBTRACT(this->sentprobes[i].recv, this->sentprobes[i].sent);
  this->updateRTTs(diff);
  return OP_FAILURE;
} /* End of setProbeRecvICMP() */


/* Update info about the last ARP probe sent */
int NpingTarget::setProbeSentARP(){
  this->sent_total++;
  return OP_SUCCESS;   
} /* End of setProbeSentARP() */


/* Update info about the last ICMP probe received */
int NpingTarget::setProbeRecvARP(){
  //int i= this->current_stat-1;
  //unsigned long int diff=0;
  return OP_FAILURE;
} /* End of setProbeRecvICMP() */


/* Assumes recv_total has already been incremented */
int NpingTarget::updateRTTs(unsigned long int diff){
  if( diff > max_rtt || max_rtt==0 ){
    max_rtt=diff;
    max_rtt_set=true;
  }
  if( diff < min_rtt || min_rtt==0){
    min_rtt=diff;
    min_rtt_set=true;
  }

  /* Update average round trip time */
  if(!avg_rtt_set || recv_total<=1)
    avg_rtt = diff;
  else
    avg_rtt = ((avg_rtt*(recv_total-1))+diff) / (recv_total);
  avg_rtt_set=true;

  return OP_SUCCESS;
} /* End of updateRTTs() */


int NpingTarget::printStats(){
  nping_print(VB_0, "Statistics for host %s:", this->getNameAndIP());
  nping_print(VB_0|NO_NEWLINE," |  ");
  this->printCounts();
  nping_print(VB_0|NO_NEWLINE," |_ ");
  this->printRTTs();
  return OP_SUCCESS;
} /* End of printStats() */


/* Print packet counts */
void NpingTarget::printCounts(){
  unsigned long int lost = this->sent_total - this->recv_total;

  /* Sent Packets */
  nping_print(VB_0|NO_NEWLINE, "Probes Sent: %ld ", this->sent_total);
  /* Received Packets */
  nping_print(VB_0|NO_NEWLINE,"| Rcvd: %ld ", this->recv_total );
  /* Lost Packets */
  nping_print(VB_0|NO_NEWLINE,"| Lost: %ld ", lost );

  /* Only compute percentage if we actually sent packets, don't do divisions
   * by zero! (this could happen when user presses CTRL-C and we print the
   * stats */
  float percentlost=0.0;
  if( lost!=0 && this->sent_total!=0)
    percentlost=((double)lost)/((double)this->sent_total) * 100;    
  nping_print(VB_0," (%.2lf%%)", percentlost);
} /* End of printCounts() */


/* Print round trip times */
void NpingTarget::printRTTs(){
  if( max_rtt_set )
    nping_print(QT_1|NO_NEWLINE,"Max rtt: %.3lfms ", this->max_rtt/1000.0 );
  else
    nping_print(QT_1|NO_NEWLINE,"Max rtt: N/A ");

  if( min_rtt_set )  
    nping_print(QT_1|NO_NEWLINE,"| Min rtt: %.3lfms ", this->min_rtt/1000.0 );
  else
    nping_print(QT_1|NO_NEWLINE,"| Min rtt: N/A " );

  if( avg_rtt_set)  
    nping_print(QT_1,"| Avg rtt: %.3lfms", this->avg_rtt/1000.0 );
  else
    nping_print(QT_1,"| Avg rtt: N/A" );
} /* End of printRTTs() */
