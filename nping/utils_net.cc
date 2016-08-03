
/***************************************************************************
 * utils_net.cc -- Miscellaneous network-related functions that perform    *
 * various tasks.                                                          *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2016 Insecure.Com LLC. Nmap is    *
 * also a registered trademark of Insecure.Com LLC.  This program is free  *
 * software; you may redistribute and/or modify it under the terms of the  *
 * GNU General Public License as published by the Free Software            *
 * Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE CLARIFICATIONS  *
 * AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your right to use,    *
 * modify, and redistribute this software under certain conditions.  If    *
 * you wish to embed Nmap technology into proprietary software, we sell    *
 * alternative licenses (contact sales@nmap.com).  Dozens of software      *
 * vendors already license Nmap technology such as host discovery, port    *
 * scanning, OS detection, version detection, and the Nmap Scripting       *
 * Engine.                                                                 *
 *                                                                         *
 * Note that the GPL places important restrictions on "derivative works",  *
 * yet it does not provide a detailed definition of that term.  To avoid   *
 * misunderstandings, we interpret that term as broadly as copyright law   *
 * allows.  For example, we consider an application to constitute a        *
 * derivative work for the purpose of this license if it does any of the   *
 * following with any software or content covered by this license          *
 * ("Covered Software"):                                                   *
 *                                                                         *
 * o Integrates source code from Covered Software.                         *
 *                                                                         *
 * o Reads or includes copyrighted data files, such as Nmap's nmap-os-db   *
 * or nmap-service-probes.                                                 *
 *                                                                         *
 * o Is designed specifically to execute Covered Software and parse the    *
 * results (as opposed to typical shell or execution-menu apps, which will *
 * execute anything you tell them to).                                     *
 *                                                                         *
 * o Includes Covered Software in a proprietary executable installer.  The *
 * installers produced by InstallShield are an example of this.  Including *
 * Nmap with other software in compressed or archival form does not        *
 * trigger this provision, provided appropriate open source decompression  *
 * or de-archiving software is widely available for no charge.  For the    *
 * purposes of this license, an installer is considered to include Covered *
 * Software even if it actually retrieves a copy of Covered Software from  *
 * another source during runtime (such as by downloading it from the       *
 * Internet).                                                              *
 *                                                                         *
 * o Links (statically or dynamically) to a library which does any of the  *
 * above.                                                                  *
 *                                                                         *
 * o Executes a helper program, module, or script to do any of the above.  *
 *                                                                         *
 * This list is not exclusive, but is meant to clarify our interpretation  *
 * of derived works with some common examples.  Other people may interpret *
 * the plain GPL differently, so we consider this a special exception to   *
 * the GPL that we apply to Covered Software.  Works which meet any of     *
 * these conditions must conform to all of the terms of this license,      *
 * particularly including the GPL Section 3 requirements of providing      *
 * source code and allowing free redistribution of the work as a whole.    *
 *                                                                         *
 * As another special exception to the GPL terms, Insecure.Com LLC grants  *
 * permission to link the code of this program with any version of the     *
 * OpenSSL library which is distributed under a license identical to that  *
 * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
 * linked combinations including the two.                                  *
 *                                                                         *
 * Any redistribution of Covered Software, including any derived works,    *
 * must obey and carry forward all of the terms of this license, including *
 * obeying all GPL rules and restrictions.  For example, source code of    *
 * the whole work must be provided and free redistribution must be         *
 * allowed.  All GPL references to "this License", are to be treated as    *
 * including the terms and conditions of this license text as well.        *
 *                                                                         *
 * Because this license imposes special exceptions to the GPL, Covered     *
 * Work may not be combined (even as part of a larger work) with plain GPL *
 * software.  The terms, conditions, and exceptions of this license must   *
 * be included as well.  This license is incompatible with some other open *
 * source licenses as well.  In some cases we can relicense portions of    *
 * Nmap or grant special permissions to use it in other open source        *
 * software.  Please contact fyodor@nmap.org with any such requests.       *
 * Similarly, we don't incorporate incompatible open source software into  *
 * Covered Software without special permission from the copyright holders. *
 *                                                                         *
 * If you have any questions about the licensing restrictions on using     *
 * Nmap in other works, are happy to help.  As mentioned above, we also    *
 * offer alternative license to integrate Nmap into proprietary            *
 * applications and appliances.  These contracts have been sold to dozens  *
 * of software vendors, and generally include a perpetual license as well  *
 * as providing for priority support and updates.  They also fund the      *
 * continued development of Nmap.  Please email sales@nmap.com for further *
 * information.                                                            *
 *                                                                         *
 * If you have received a written license agreement or contract for        *
 * Covered Software stating terms other than these, you may choose to use  *
 * and redistribute Covered Software under those terms instead of these.   *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to send your changes   *
 * to the dev@nmap.org mailing list for possible incorporation into the    *
 * main distribution.  By sending these changes to Fyodor or one of the    *
 * Insecure.Org development mailing lists, or checking them into the Nmap  *
 * source code repository, it is understood (unless you specify otherwise) *
 * that you are offering the Nmap Project (Insecure.Com LLC) the           *
 * unlimited, non-exclusive right to reuse, modify, and relicense the      *
 * code.  Nmap will always be available Open Source, but this is important *
 * because the inability to relicense code has caused devastating problems *
 * for other Free Software projects (such as KDE and NASM).  We also       *
 * occasionally relicense the code to third parties as discussed above.    *
 * If you wish to specify special license conditions of your               *
 * contributions, just say so when you send them.                          *
 *                                                                         *
 * This program is distributed in the hope that it will be useful, but     *
 * WITHOUT ANY WARRANTY; without even the implied warranty of              *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the Nmap      *
 * license file for more details (it's in a COPYING file included with     *
 * Nmap, and also available from https://svn.nmap.org/nmap/COPYING)        *
 *                                                                         *
 ***************************************************************************/
#include "nping.h"
#include "utils.h"
#include "utils_net.h"
#include "NpingOps.h"
#include "global_structures.h"
#include "output.h"
#include "nbase.h"
#include "pcap.h"
#include "dnet.h"
#include <vector>

extern NpingOps o;

int atoIP(const char *hostname, struct in_addr *dst){
  struct sockaddr_in i;
  unsigned int stlen=0;
  if ( resolve(hostname, 0, (sockaddr_storage*)&i, (size_t *)&stlen , PF_INET) != 0 )
    return OP_FAILURE;
  *dst=i.sin_addr;
  return OP_SUCCESS;
} /* End of atoIP */

int atoIP(const char *hostname, struct sockaddr_storage *ss, int family){
  size_t stlen=0;
  if(ss==NULL || hostname==NULL)
    return OP_FAILURE;
  if(family!=AF_INET && family!=AF_INET6)
    return OP_FAILURE;
  if ( resolve(hostname, 0, ss, &stlen , family) != 0 )
    return OP_FAILURE;
  return OP_SUCCESS;
} /* End of atoIP */


/** @warning The string is returned in a statically allocated buffer, which
 *  subsequent calls will overwrite.*/
char *IPtoa(u32 i){
  static char buffer[24];
  char *aux=NULL;
  memset(buffer, 0, 24);
  struct in_addr myip;
  myip.s_addr=i;
  aux=inet_ntoa(myip);
  /* Get our own copy of the data so only subsequent calls to IPtoa overwrite
   * the returned buffer (not subsequent calls to inet_ntoa() made by other
   * methods. */
  if(aux!=NULL){
      strncpy(buffer, aux, 23);
      return buffer;
  }
  else
    return NULL;
} /* End of IPtoa() */


/** @warning The string is returned in a statically allocated buffer, which
 *  subsequent calls will overwrite.*/
char *IPtoa(struct sockaddr_storage *ss){
  struct sockaddr_in  *s4=(struct sockaddr_in *)ss;
  struct sockaddr_in6 *s6=(struct sockaddr_in6 *)ss;
  static char ipstring[256];
  memset(ipstring, 0, 256);
  if( ss==NULL ){
    snprintf(ipstring,256, "[[NULL address supplied to IPtoa()]]");
    return ipstring;
  }
  if(s6->sin6_family==AF_INET6){
    inet_ntop(AF_INET6, &s6->sin6_addr, ipstring, sizeof(ipstring));
  }else if( s4->sin_family == AF_INET ) {
    inet_ntop(AF_INET, &s4->sin_addr, ipstring, sizeof(ipstring));
  }else{
    snprintf(ipstring,256,"[[Unknown address family sockaddr supplied to IPtoa()]]");
  }
 return ipstring;
} /* End of IPtoa() */


char *IPtoa(struct sockaddr_storage ss){
  return IPtoa(&ss);
} /* End of IPtoa() */

char *IPtoa(struct sockaddr_storage *ss, int family){
  if(ss==NULL){
      return NULL;
  }else if(family==AF_INET){
      struct sockaddr_in *s4=(struct sockaddr_in *)ss;
      return IPtoa(s4->sin_addr);
  }else if(family==AF_INET6){
      struct sockaddr_in6 *s6=(struct sockaddr_in6 *)ss;
      return IPtoa(s6->sin6_addr);
  }else{
    return NULL;
  }
} /* End of IPtoa() */


/** @warning The string is returned in a statically allocated buffer, which
 *  subsequent calls will overwrite.*/
char *IPtoa(struct in_addr addr){
  static char ipstring[256];
  memset(ipstring, 0, 256);
  inet_ntop(AF_INET, &addr, ipstring, sizeof(ipstring));
  return ipstring;
} /* End of IPtoa() */


/** @warning The string is returned in a statically allocated buffer, which
 *  subsequent calls will overwrite.*/
char *IPtoa(struct in6_addr addr){
  static char ipstring[256];
  memset(ipstring, 0, 256);
  inet_ntop(AF_INET6, &addr, ipstring, sizeof(ipstring));
  return ipstring;
} /* End of IPtoa() */


/** @warning The string is returned in a statically allocated buffer, which
 *  subsequent calls will overwrite.*/
char *IPtoa(u8 *ipv6addr){
  static char ipstring[256];
  memset(ipstring, 0, 256);
  struct in6_addr s6;
  memcpy(s6.s6_addr, ipv6addr, 16);
  inet_ntop(AF_INET6, &s6, ipstring, sizeof(ipstring));
  return ipstring;
} /* End of IPtoa() */


/** Returns true if supplied value corresponds to a valid RFC compliant ICMP
 *  type. Otherwise it returns false. */
bool isICMPType(u8 type){
    switch (type){
        case 0:
        case 3:
        case 4:
        case 5:
        case 8:
        case 9:
        case 10:
        case 11:
        case 12:
        case 13:
        case 14:
        case 15:
        case 16:
        case 17:
        case 18:
        case 30:
            return true;
        break;

        default:
            return false;
        break;
    }
  return false;
} /* End of isICMPType() */


u16 sockaddr2port(struct sockaddr_storage ss){
  return sockaddr2port(&ss);
}


u16 sockaddr2port(struct sockaddr_storage *ss){
  assert(ss!=NULL);
  if(ss->ss_family==AF_INET)
    return sockaddr2port( (struct sockaddr_in *)ss );
  else if( ss->ss_family==AF_INET6){
    return sockaddr2port( (struct sockaddr_in6 *)ss );
  }else{
    return 0;
  }
}


u16 sockaddr2port(struct sockaddr_in *s4){
  assert(s4!=NULL);
  return ntohs(s4->sin_port);
}


u16 sockaddr2port(struct sockaddr_in6 *s6){
  assert(s6!=NULL);
  return ntohs(s6->sin6_port);
}


/* Sets the address family member of the supplied sockaddr. */
int setsockaddrfamily(struct sockaddr_storage *ss, int family){
  struct sockaddr_in *s4=(struct sockaddr_in *)ss;
  s4->sin_family=family;
  return OP_SUCCESS;
} /* End of setsockaddrfamily() */


/* Sets the special INADDR_ANY or in6addr_an constant on the sin_family or
 * sin6_addr member of the supplied sockaddr. Note that for this to work,
 * the supplied sockaddr_storage MUST have a correct address family set 
 * already (sin_family or sin6_family). */
int setsockaddrany(struct sockaddr_storage *ss){
  struct sockaddr_in *s4=(struct sockaddr_in *)ss;
  struct sockaddr_in6 *s6=(struct sockaddr_in6 *)ss;
  if(s4->sin_family==AF_INET)
    s4->sin_addr.s_addr=INADDR_ANY;
  else if(s6->sin6_family==AF_INET6)
    s6->sin6_addr=in6addr_any;
  else
    return OP_FAILURE;
  return OP_SUCCESS;
} /* End of setsockaddrany() */


/** Returns true if supplied value corresponds to a valid RFC compliant ICMP
 *  Code. Otherwise it returns false.
 *  @warning The fact that a given value matches a standard code does not
 *  mean the code is correct because it depends on the type being used */
bool isICMPCode(u8 code){
  /* Correct as of 25 June 09.
   * http://www.iana.org/assignments/icmp-parameters */
  if( code<=16 )
    return true;
  else
    return false;
} /* End of isICMPType() */



/** Returns true if supplied value corresponds to a valid RFC compliant ICMP
 *  Code for the supplied type
 *  @warning The fact that a given value matches a standard code does not
 *  mean the code is correct because it depends on the type being used */
bool isICMPCode(u8 code, u8 type){
   /* Correct as of 25 June 09.
    * http://www.iana.org/assignments/icmp-parameters */
  switch (type){
    case 0:  /* Echo Reply */
        if(code==0) return true;
    break;

    case 3:  /* Destination Unreachable */
        if(code<=15) return true;
    break;

    case 4:  /* Source Quench */
        if(code==0) return true;
    break;

    case 5:  /* Redirect */
        if(code<=3) return true;
    break;

    case 6:  /* Alternate Address for Host */
        if(code==0) return true;
    break;

    case 8:  /* Echo */
        if(code==0) return true;
    break;

    case 9:  /* Router Advertisement */
        if(code==0 || code==16) return true;
    break;

    case 10:  /* Router Selection */
        if(code==0) return true;
    break;

    case 11:  /* Time Exceeded */
        if(code==0 || code==1) return true;
    break;

    case 12:  /* Parameter Problem */
        if(code<=2) return true;
    break;

    case 13:  /* Timestamp */
        if(code==0) return true;
    break;

    case 14:  /* Timestamp Reply */
        if(code==0) return true;
    break;

    case 15:  /* Information Request */
        if(code==0) return true;
    break;

    case 16:  /* Information Reply */
        if(code==0) return true;
    break;

    case 17:  /* Address Mask Request */
        if(code==0) return true;
    break;

    case 18:  /* Address Mask Reply */
        if(code==0) return true;
    break;

    case 30:  /* Traceroute */
        return true;
    break;

    case 40: /* Experimental ICMP Security Failures Messages [RFC 2521] */
        if(code<=5) return true;
    break;

    default:
        return false;
    break;
  }
  return false;
} /* End of isICMPType() */


/* This function fills buffer "dstbuff" with a printable string that
 * represents the supplied packet. When sending IPv6 packet at raw TCP
 * level, the caller may specify source and/or destination address so they
 * also get included in the returned information. However, this is optional
 * and is safe to pass NULL values. */
int getPacketStrInfo(const char *proto, const u8 *packet, u32 len, u8 *dstbuff,
                     u32 dstlen, struct sockaddr_storage *ss_src, struct sockaddr_storage *ss_dst){
  char *b=NULL;
  int detail;

  if ( dstbuff == NULL || dstlen < 512 )
    nping_fatal(QT_3,"safe_ippackethdrinfo() Invalid values supplied.");

  if(o.getVerbosity()>=VB_2)
    detail=HIGH_DETAIL;
  else if (o.getVerbosity()==VB_1)
    detail=MEDIUM_DETAIL;
  else
    detail=LOW_DETAIL;

  if( !strcasecmp(proto, "IP") || !strcasecmp(proto, "IPv4") || !strcasecmp(proto, "IPv6")){
    b=(char *)ippackethdrinfo(packet, len, detail);
    strncpy((char*)dstbuff, b, dstlen);
    dstbuff[dstlen-1]=0; /* Just to be sure, NULL-terminate the last position*/
  }else if( !strcasecmp(proto, "ARP") || !strcasecmp(proto, "RARP") ){
    return  arppackethdrinfo(packet, len, dstbuff, dstlen);
  }else if( !strcasecmp(proto, "IPv6_NO_HEADER") || o.ipv6UsingSocket() ){
    if( o.getMode()==TCP )
        return  tcppackethdrinfo(packet, len, dstbuff, dstlen, detail, ss_src, ss_dst);
    else if ( o.getMode()==UDP )
        return  udppackethdrinfo(packet, len, dstbuff, dstlen, detail, ss_src, ss_dst);
    else
        nping_fatal(QT_3, "getPacketStrInfo(): Unable to determinate transport layer protocol");
  }else{
    nping_fatal(QT_3, "getPacketStrInfo(): Unknown protocol");
  }
  return OP_SUCCESS;
} /* getPacketStrInfo() */


/* Same as previous one but passes NULL sockaddr values automatically. */
int getPacketStrInfo(const char *proto, const u8 *packet, u32 len, u8 *dstbuff, u32 dstlen){
  return getPacketStrInfo(proto,packet,len,dstbuff,dstlen,NULL,NULL);
} /* getPacketStrInfo() */


/** This function converts a port ranges specification into an array of u16
  * integers that represent each of the specified ports. It allocates space
  * for the port lists and stores the pointer in the supplied "list" parameter.
  * Also, the number of ports in the array is returned through the supplied
  * "count" pointer.
  * @warning the caller is the one responsible for free()ing the allocated
  * list of ports.
  */  
int nping_getpts_simple(const char *origexpr, u16 **list, int *count) {
  u8 *porttbl;
  int portwarning = 0;
  int i, j;

  /* Allocate array to hold 2^16 ports */
  porttbl = (u8 *) safe_zalloc(65536);

  /* Get the ports but do not allow changing the type with T:, U:, or P:. */
  getpts_aux(origexpr, 0, porttbl, &portwarning);

  /* Count how many are set. */
  *count = 0;
  for (i = 0; i <= 65535; i++) {
    if (porttbl[i])
      (*count)++;
  }

  if (*count == 0){
    free(porttbl);
    return OP_FAILURE;
  }

  *list = (unsigned short *) safe_zalloc(*count * sizeof(u16));

  /* Fill in the list. */
  for (i = 0, j = 0; i <= 65535; i++) {
    if (porttbl[i])
      (*list)[j++] = i;
  }
  free(porttbl);
  return OP_SUCCESS;
} /* End of nping_getpts_simple() */




/** Determines the net iface that should be used when sending packets
 *  to "destination".
 *  @return OP_SUCCESS on success and OP_FAILUIRE in case of error.
 *  @warning "*dev" must be able to hold at least 16 bytes */
int getNetworkInterfaceName(u32 destination, char *dev){
  struct route_nfo rnfo;
  struct sockaddr_in dst, src;
  bool result=false;
  if(dev==NULL)
    nping_fatal(QT_3, "getNetworkInterfaceName(): NULL value supplied.");
  memset(&rnfo, 0, sizeof(struct route_nfo) );
  memset(&dst, 0, sizeof(struct sockaddr_in) );
  memset(&src, 0, sizeof(struct sockaddr_in) );
  dst.sin_addr.s_addr = destination;
  dst.sin_family = AF_INET;
  result=route_dst((struct sockaddr_storage *)&dst, &rnfo, NULL, NULL); 
  if( result == false )
    return OP_FAILURE;
  strncpy( dev,  rnfo.ii.devname, 16 );
  return OP_SUCCESS;
} /* End of getSourceAddress() */



/** Determines the net iface that should be used when sending packets
 *  to "destination".
 *  @return OP_SUCCESS on success and OP_FAILUIRE in case of error.
 *  @warning "*dev" must be able to hold at least 16 bytes */
int getNetworkInterfaceName(struct sockaddr_storage *dst, char *dev){
  struct route_nfo rnfo;
  struct sockaddr_storage src;
  bool result=false;
  if(dev==NULL)
    nping_fatal(QT_3, "getNetworkInterfaceName(): NULL value supplied.");
  memset(&rnfo, 0, sizeof(struct route_nfo) );
  memset(&src, 0, sizeof(struct sockaddr_in) );
  result=route_dst(dst, &rnfo, NULL, NULL); 
  if( result == false )
    return OP_FAILURE;
  strncpy( dev,  rnfo.ii.devname, 16 );
  return OP_SUCCESS;
} /* End of getSourceAddress() */


typedef struct cached_host{
  char hostname[MAX_CACHED_HOSTNAME_LEN];
  struct sockaddr_storage ss;
  size_t sslen;
}cached_host_t;


int resolveCached(char *host, struct sockaddr_storage *ss, size_t *sslen, int pf) {
  static cached_host_t archive[MAX_CACHED_HOSTS];
  static int cached_count=0;
  static int current_index=0; /* Used when we reach the end of the array and we do circular buffer */
  int result=0;
  //static int way=1;
  static int misses=0, hits=0;

  /* Used for debug. When called with NULL,0x1337, print stats */
  if(host==NULL && pf == 1337){
	nping_print(DBG_4, "resolveCached(): MISSES: %d,  HITS: %d\n", misses, hits);
	return OP_SUCCESS;
  }


  if( ss==NULL || sslen==NULL || host==NULL)
	nping_fatal(QT_3, "resolveCached(): NULL values supplied");

  /* First we check if we have the host already cached */
  for(int i=0; i<MAX_CACHED_HOSTS && i<cached_count; i++){
    if( !strcasecmp( archive[i].hostname , host ) ){ /* Cache hit */
		*sslen=archive[i].sslen;
		memcpy(ss, &(archive[i].ss) , *sslen);
		hits++;
		nping_print(DBG_4, "resolveCached(): Cache hit %d for %s\n", hits, host);
		return OP_SUCCESS;		
	}
  }

  /* Cache miss */
  misses++;
  nping_print(DBG_4, "resolveCached(): Cache miss %d for %s\n", misses, host);

  if( (result=resolve(host, 0, ss, sslen, pf)) == 0 ){

	  /* Increment count */
	  if( cached_count < MAX_CACHED_HOSTS )
		cached_count++;

      /* Store info */
	  memset(&(archive[current_index]), 0, sizeof(cached_host_t) );
	  strncpy(archive[current_index].hostname, host, MAX_CACHED_HOSTNAME_LEN);
	  archive[current_index].sslen = *sslen;
	  memcpy(&(archive[current_index].ss), ss, *sslen);


	  /* I run some tests to see what is the best approach when the cache
	   * is full. The thing is that in Nping, we are likely to call
	   * this function over and over with specifying the same hosts. Deleting
	   * the oldest entry results in 100% cache misses. I also tried to start
	   * overwriting entries first backwards and then upwards. That showed
	   * much better results. However, if we simply overwrite the last
	   * cache entry over an over we get the best results. */
	  if( current_index < MAX_CACHED_HOSTS-1 )
		  current_index++;					
	  return 0;



	  ///* Watch out for the overflow. If cache is full,  */
	  //if( cached_count == MAX_CACHED_HOSTS ){
			//if( way%2==1 ){
				//if( current_index > 0 )
					//current_index--;
				//else{
					//current_index=1;
					//way++;
				//}
			//}
			//else{
				//if( current_index < MAX_CACHED_HOSTS-1 )
					//current_index++;
				//else{
					//current_index=MAX_CACHED_HOSTS-2;
					//way++;
				//}
			//}
	  //}
	  //else
		//current_index++;		
	  //return OP_SUCCESS;

  }else{
		nping_warning(QT_2, "Error resolving %s\n",host);
		return OP_FAILURE;
  }
} /* End of resolveCached() */


typedef struct gethostbyname_cached{
  char hostname[MAX_CACHED_HOSTNAME_LEN];
  struct hostent *h;
}gethostbynamecached_t;


struct hostent *gethostbynameCached(char *host){
  static gethostbynamecached_t archive[MAX_CACHED_HOSTS];
  static int cached_count=0;
  static int current_index=0;
  struct hostent *result=NULL;
  static int misses=0, hits=0;
  int i=0;

  if( host==NULL)
	nping_fatal(QT_3, "gethostbynameCached(): NULL values supplied");

  /* First we check if we have the host already cached */
  for(i=0; i<MAX_CACHED_HOSTS && i<cached_count; i++){
    if( !strcasecmp( archive[i].hostname , host ) ){ /* Cache hit */
		hits++;
		nping_print(DBG_4, "gethostbynameCached(): Cache hit %d for %s", hits, host);
		return  archive[i].h;
	}
  }

  /* Cache miss */
  misses++;
  nping_print(DBG_4, "gethostbynameCached(): Cache miss %d for %s", misses, host);

  if( (result=gethostbyname(host) ) != NULL ){

	  /* Increment cache entry count */
	  if( cached_count < MAX_CACHED_HOSTS )
		cached_count++;

      /* If we've reached the max number of cached hosts, free the
       * hostent entry that is in the last slot so we can insert a new
       * one in its place */
      if ( current_index==MAX_CACHED_HOSTS-1 && archive[current_index].h != NULL )
        hostentfree( archive[current_index].h );

      /* Store the hostent entry in the cache */   
	  memset(&(archive[current_index]), 0, sizeof(gethostbynamecached_t) );
	  strncpy(archive[current_index].hostname, host, MAX_CACHED_HOSTNAME_LEN);
	  archive[current_index].h = hostentcpy( result );

      /* Return the entry that we've just added */
	  if( current_index < MAX_CACHED_HOSTS-1 ){
		  current_index++;
		  return  archive[current_index-1].h;
	  }
	  else{
		  return  archive[current_index].h;
	  }

  }else{
    return NULL;
  }
} /* End of resolveCached() */


struct hostent *hostentcpy(struct hostent *src){
  struct hostent *st=NULL;
  int aliases=0;
  int addrs=0;

  if( src == NULL )
    return NULL;

  st=(struct hostent *)safe_zalloc( sizeof(struct hostent) );

  /* Copy host name */
  if( src->h_name!= NULL )
    st->h_name = strdup( src->h_name );

  /* Copy aliases */
  if( src->h_aliases != NULL ){
      while(  src->h_aliases[aliases] )   /* Fist count how many*/
        aliases++;
      st->h_aliases = (char **)safe_zalloc( aliases * sizeof(char*) ); /* Allocate array */
      for( int i=0; i<aliases; i++) /* Copy all entries */
        st->h_aliases[i] = strdup( src->h_aliases[i] );
  }
  /* Copy address type an length */
  st->h_addrtype=src->h_addrtype;
  st->h_length=src->h_length;

  /* Copy list of addresses */
  if(  src->h_addr_list != NULL ){

      while(  src->h_addr_list[addrs] )   /* Fist count how many*/
        addrs++;

      st->h_addr_list = (char **)safe_zalloc( addrs * sizeof(char*) ); /* Allocate array */

      for( int j=0; j<addrs; j++) /* Copy all entries */
        st->h_addr_list[j] = strdup( src->h_addr_list[j] );

      /* Create dummy synonym for h_addr_list[0]*/
      st->h_addr=st->h_addr_list[0];
  }
  return st;
} /* End of hostentcpy() */


/** Free a hostend structure.
  * @warning This function can ONLY be used with hostent structs returned by
  * hostentcpy. Do NOT attempt to use this on a hostent returned by
  * gethostbyname() because the structure may contain pointers to statically
  * allocated memory regions.*/
int hostentfree(struct hostent *src){
  int aliases=0;
  int addrs=0;

  if( src == NULL )
    return OP_SUCCESS;

  /* Free host name */
  if ( src->h_name != NULL )
    free( src->h_name );

  /* Free aliases */
  if( src->h_aliases != NULL ){
      while(  src->h_aliases[aliases] ){
        free(src->h_aliases[aliases]);
        aliases++;
      }
      free(src->h_aliases);
   }

  /* Free list of addresses */
  if(  src->h_addr_list != NULL ){

      while(  src->h_addr_list[addrs] ){
        addrs++;
        free( src->h_addr_list[addrs] );
      }
      free( src->h_addr_list );
  }

  /* Finally free the base hostent struct */
  free( src );
  return OP_SUCCESS;
} /* End of hostentfree() */



/** Receives a MAC address as a string of format 00:13:01:e6:c7:ae or
 *  00-13-01-e6-c7-ae and stores in targetbuff the 6 corresponding bytes.
 *  The "txt" parameter may take the special value "rand" or "random",
 *  in which case, 6 random bytes will be stored in "targetbuff".
 *  @return OP_SUCCESS on success and OP_FAILURE in case of error.
 *  Buffer targetbuff is NOT modified if "txt" does not have the proper
 *  format */
int parseMAC(const char *txt, u8 *targetbuff){
  u8 mac_data[6];
  char tmphex[3];
  int i=0, j=0;

  if( txt==NULL || targetbuff==NULL )
    return OP_FAILURE;

  /* Set up a random MAC if user requested so. */
  if( meansRandom(txt) ){
    get_random_bytes(targetbuff, 6);
    return OP_SUCCESS;
  /* Or set it to FF:FF:FF:FF:FF:FF if user chose broadcast */
  }else if( !strcasecmp(optarg, "broadcast") || !strcasecmp(optarg, "bcast") ){
    memset(targetbuff, 0xFF, 6);
    return OP_SUCCESS;
  }

  /* Array should look like  00:13:01:e6:c7:ae  or  00-13-01-e6-c7-ae
     Array positions:        01234567890123456      01234567890123456  */
  if( strlen(txt)!=17 )
    return OP_FAILURE;
  /* Check MAC has the correct ':' or '-' characters */
  if( (txt[2]!=':' && txt[2]!='-') || (txt[5]!=':' && txt[5]!='-')   ||
      (txt[8]!=':' && txt[8]!='-') || (txt[11]!=':' && txt[11]!='-') ||
      (txt[14]!=':' && txt[14]!='-') )
      return OP_FAILURE;

  /* Convert txt into actual bytes */
  for(i=0, j=0; i<6; i++, j+=3 ){
    if( !isxdigit(txt[j]) || !isxdigit(txt[j+1]) )
        return OP_FAILURE;
    tmphex[0] = txt[j];
    tmphex[1] = txt[j+1];
    tmphex[2] = '\0';
    mac_data[i] = (u8) strtol(tmphex, NULL, 16);
  }
  memcpy(targetbuff, mac_data, 6);
  return OP_SUCCESS;
} /* End of parseMAC() */



char *MACtoa(u8 *mac){
  static char macinfo[24];
  memset(macinfo, 0, 24);
  sprintf(macinfo,"%02X:%02X:%02X:%02X:%02X:%02X",
          mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
  return macinfo;
} /* End of MACtoa() */




/* Returns a buffer of ASCII information about an ARP/RARP packet that may look
   like "ARP who has 192.168.10.1? Tell 192.168.10.98"
   Since this is a static buffer, don't use threads or call twice
   within (say) printf().  And certainly don't try to free() it!  The
   returned buffer is NUL-terminated */
const char *arppackethdrinfo(const u8 *packet, u32 len, int detail){
  static char protoinfo[512];
  if (packet==NULL)
    nping_fatal(QT_3, "arppackethdrinfo(): NULL value supplied");
  if( len < 28 )
    return "BOGUS!  Packet too short.";
  u16 *htype = (u16 *)packet;
  u16 *ptype = (u16 *)(packet+2);
  u8  *hlen = (u8 *)(packet+4);
  u8  *plen = (u8 *)(packet+5);
  u16 *op = (u16 *)(packet+6);
  u8 *sMAC= (u8 *)(packet+8);
  u32 *sIP = (u32 *)(packet+14);
  u8 *tMAC = (u8 *)(packet+18);
  u32 *tIP = (u32 *)(packet+24);

  if( ntohs(*op) == 1 ){ /* ARP Request */
    sprintf(protoinfo, "ARP who has %s? ", IPtoa(*tIP));
    sprintf(protoinfo+strlen(protoinfo),"Tell %s", IPtoa(*sIP) );
  }
  else if( ntohs(*op) == 2 ){ /* ARP Reply */
    sprintf(protoinfo, "ARP reply %s ", IPtoa(*sIP));
    sprintf(protoinfo+strlen(protoinfo),"is at %s", MACtoa(sMAC) );
  }
  else if( ntohs(*op) == 3 ){ /* RARP Request */
    sprintf(protoinfo, "RARP who is %s? Tell %s", MACtoa(tMAC), MACtoa(sMAC) );
  }
  else if( ntohs(*op) ==4 ){ /* RARP Reply */
    sprintf(protoinfo, "RARP reply: %s is at %s", MACtoa(tMAC), IPtoa(*tIP) );
  }
  else{
    sprintf(protoinfo, "HTYPE:%04X PTYPE:%04X HLEN:%d PLEN:%d OP:%04X SMAC:%s SIP:%s DMAC:%s DIP:%s",
            *htype, *ptype, *hlen, *plen, *op, MACtoa(sMAC), IPtoa(*sIP), MACtoa(tMAC), IPtoa(*tIP));
  }
 return protoinfo;
} /* End of arppackethdrinfo() */




int arppackethdrinfo(const u8 *packet, u32 len, u8 *dstbuff, u32 dstlen){
  char *b=NULL;
  int detail=0;

  if ( dstbuff == NULL || dstlen < 512 )
    nping_fatal(QT_3,"safe_arppackethdrinfo() Invalid values supplied.");

  /* Determine level of detail in packet output from current verbosity level */
  if(o.getVerbosity()>=VB_2)
    detail=HIGH_DETAIL;
  else if (o.getVerbosity()==VB_1)
    detail=MEDIUM_DETAIL;
  else
    detail=LOW_DETAIL;

  b=(char *)arppackethdrinfo(packet, len, detail);
  strncpy((char*)dstbuff, b, dstlen);
  dstbuff[dstlen-1]=0; /* Just to be sure, NULL-terminate the last position*/
  return OP_SUCCESS;
} /* End of arppackethdrinfo() */



int tcppackethdrinfo(const u8 *packet, size_t len, u8 *dstbuff, size_t dstlen,
     int detail, struct sockaddr_storage *src, struct sockaddr_storage *dst){

  struct tcp_hdr *tcp=NULL; ;           /* TCP header structure.             */
  char *p = NULL;                       /* Aux pointer.                      */
  static char protoinfo[1024] = "";     /* Stores final info string.         */
  char tflags[10];
  char tcpinfo[64] = "";
  char buf[32];
  char tcpoptinfo[256] = "";
  struct sockaddr_in *s4=(struct sockaddr_in *)src;
  struct sockaddr_in6 *s6=(struct sockaddr_in6 *)src;
  struct sockaddr_in *d4=(struct sockaddr_in *)dst;
  struct sockaddr_in6 *d6=(struct sockaddr_in6 *)dst;
  char srcipstring[128];
  char dstipstring[128];

 assert(packet);
 assert(dstbuff);
 assert(len>=20);

 tcp=(struct tcp_hdr *)packet;

   /* Ensure we end up with a valid detail number */
  if( detail!=LOW_DETAIL && detail!=MEDIUM_DETAIL && detail!=HIGH_DETAIL)
    detail=LOW_DETAIL;


  /* Determine target IP address */
  if(src!=NULL){
    if( s4->sin_family==AF_INET ){
        inet_ntop(AF_INET, &s4->sin_addr, srcipstring, sizeof(srcipstring));
    }
    else if( s6->sin6_family==AF_INET6){
        inet_ntop(AF_INET6, &s6->sin6_addr, srcipstring, sizeof(srcipstring));
    }else{
        sprintf(dstipstring, "unknown_addr_family");
    }
  }else{
    sprintf(srcipstring, "this_host");
  }

  /* Determine source IP address */
  if(dst!=NULL){
    if( d4->sin_family==AF_INET ){
        inet_ntop(AF_INET, &d4->sin_addr, dstipstring, sizeof(dstipstring));
    }
    else if( d6->sin6_family==AF_INET6){
        inet_ntop(AF_INET6, &d6->sin6_addr, dstipstring, sizeof(dstipstring));
    }else{
        sprintf(dstipstring, "unknown_addr_family");
    }
  }else{
    sprintf(dstipstring, "unknown_host");
  }

  /* TCP Flags */
  p = tflags;
  /* These are basically in tcpdump order */
  if (tcp->th_flags & TH_SYN) *p++ = 'S';
  if (tcp->th_flags & TH_FIN) *p++ = 'F';
  if (tcp->th_flags & TH_RST) *p++ = 'R';
  if (tcp->th_flags & TH_PUSH) *p++ = 'P';
  if (tcp->th_flags & TH_ACK){ *p++ = 'A';
    Snprintf(buf, sizeof(buf), " ack=%lu",
         (unsigned long) ntohl(tcp->th_ack));
    strncat(tcpinfo, buf, sizeof(tcpinfo) - strlen(tcpinfo) - 1);
  }
  if (tcp->th_flags & TH_URG) *p++ = 'U';
  if (tcp->th_flags & TH_ECE) *p++ = 'E'; /* rfc 2481/3168 */
  if (tcp->th_flags & TH_CWR) *p++ = 'C'; /* rfc 2481/3168 */
  *p++ = '\0';


  /* TCP Options */
  if((u32) tcp->th_off * 4 > sizeof(struct tcp_hdr)) {
    if(len < (u32) tcp->th_off * 4) {
      Snprintf(tcpoptinfo, sizeof(tcpoptinfo), "option incomplete");

    } else {
      tcppacketoptinfo((u8*) tcp + sizeof(struct tcp_hdr),
                 tcp->th_off*4 - sizeof(struct tcp_hdr),
                 tcpoptinfo, sizeof(tcpoptinfo));
    }
  }

  /* Rest of header fields */
  if( detail == LOW_DETAIL ){
    Snprintf(protoinfo, sizeof(protoinfo), "TCP %s:%d > %s:%d %s seq=%lu win=%hu %s",
       srcipstring, ntohs(tcp->th_sport), dstipstring, ntohs(tcp->th_dport),
           tflags, (unsigned long) ntohl(tcp->th_seq),
           ntohs(tcp->th_win), tcpoptinfo);               
  }else if( detail == MEDIUM_DETAIL ){
    Snprintf(protoinfo, sizeof(protoinfo), "TCP [%s:%d > %s:%d %s seq=%lu win=%hu csum=0x%04X%s%s]",
       srcipstring, ntohs(tcp->th_sport), dstipstring, ntohs(tcp->th_dport),
           tflags, (unsigned long) ntohl(tcp->th_seq),
           ntohs(tcp->th_win),  ntohs(tcp->th_sum),
           (tcpoptinfo[0]!='\0') ? " " : "",
           tcpoptinfo);                 
  }else if( detail==HIGH_DETAIL ){
    Snprintf(protoinfo, sizeof(protoinfo), "TCP [%s:%d > %s:%d %s seq=%lu ack=%lu off=%d res=%d win=%hu csum=0x%04X urp=%d%s%s] ",
       srcipstring, ntohs(tcp->th_sport),
       dstipstring, ntohs(tcp->th_dport),
       tflags, (unsigned long) ntohl(tcp->th_seq),
       (unsigned long) ntohl(tcp->th_ack),
       (u8)tcp->th_off, (u8)tcp->th_x2, ntohs(tcp->th_win),
       ntohs(tcp->th_sum), ntohs(tcp->th_urp),
       (tcpoptinfo[0]!='\0') ? " " : "",
       tcpoptinfo);  
  }

  strncpy((char*)dstbuff, protoinfo, dstlen);

  return OP_SUCCESS;

} /* End of tcppackethdrinfo() */




int udppackethdrinfo(const u8 *packet, size_t len, u8 *dstbuff, size_t dstlen,
    int detail, struct sockaddr_storage *src, struct sockaddr_storage *dst){

  struct udp_hdr *udp = NULL;           /* UDP header structure.             */
  static char protoinfo[1024] = "";     /* Stores final info string.         */
  struct sockaddr_in *s4=(struct sockaddr_in *)src;
  struct sockaddr_in6 *s6=(struct sockaddr_in6 *)src;
  struct sockaddr_in *d4=(struct sockaddr_in *)dst;
  struct sockaddr_in6 *d6=(struct sockaddr_in6 *)dst;
  char srcipstring[128];
  char dstipstring[128];

 assert(packet);
 assert(dstbuff);
 assert(len>=8);

 udp=(struct udp_hdr *)packet;

   /* Ensure we end up with a valid detail number */
  if( detail!=LOW_DETAIL && detail!=MEDIUM_DETAIL && detail!=HIGH_DETAIL)
    detail=LOW_DETAIL;


  /* Determine target IP address */
  if(src!=NULL){
    if( s4->sin_family==AF_INET ){
        inet_ntop(AF_INET, &s4->sin_addr, srcipstring, sizeof(srcipstring));
    }
    else if( s6->sin6_family==AF_INET6){
        inet_ntop(AF_INET6, &s6->sin6_addr, srcipstring, sizeof(srcipstring));
    }else{
        sprintf(dstipstring, "unknown_addr_family");
    }
  }else{
    sprintf(srcipstring, "this_host");
  }

  /* Determine source IP address */
  if(dst!=NULL){
    if( d4->sin_family==AF_INET ){
        inet_ntop(AF_INET, &d4->sin_addr, dstipstring, sizeof(dstipstring));
    }
    else if( d6->sin6_family==AF_INET6){
        inet_ntop(AF_INET6, &d6->sin6_addr, dstipstring, sizeof(dstipstring));
    }else{
        sprintf(dstipstring, "unknown_addr_family");
    }
  }else{
    sprintf(dstipstring, "unknown_host");
  }

  if( detail == LOW_DETAIL ){
    Snprintf(protoinfo, sizeof(protoinfo), "UDP %s:%d > %s:%d",
         srcipstring, ntohs(udp->uh_sport), dstipstring, ntohs(udp->uh_dport));
  }else if( detail == MEDIUM_DETAIL ){
    Snprintf(protoinfo, sizeof(protoinfo), "UDP [%s:%d > %s:%d csum=0x%04X]",
         srcipstring, ntohs(udp->uh_sport), dstipstring, ntohs(udp->uh_dport), ntohs(udp->uh_sum));
  }else if( detail==HIGH_DETAIL ){
    Snprintf(protoinfo, sizeof(protoinfo), "UDP [%s:%d > %s:%d len=%d csum=0x%04X]",
         srcipstring, ntohs(udp->uh_sport), dstipstring, ntohs(udp->uh_dport),
         ntohs(udp->uh_ulen), ntohs(udp->uh_sum));
  }

  strncpy((char*)dstbuff, protoinfo, dstlen);

  return OP_SUCCESS;

} /* End of udppackethdrinfo() */



/** Returns a random (null-terminated) ASCII string with no special
  * meaning. Returned string may be between 1 and 512 bytes and contain
  * random letters and some whitespace.
  * @warning Returned string is stored in a static buffer that subsequent
  * calls will overwrite.
  * Note that the entropy of the returned data is very low (returned
  * values are always formed by lowercase letters and whitespace). */
const char *getRandomTextPayload(){    
  int len=0, i=0;
  static char buffer[512+1];
  const char letters[26]={'a','b','c','d','e','f','g','h','i','j','k',
                           'l','m','n','o','p','q','r','s','t','u','v',
                           'w','z','y','z'};

  /* Determine how long the text should be */
  while( (len=(2*get_random_u8())-1) == 0 );
  /* Create the string */
  for(i=0; i<len; i++){
    if( get_random_u8()%5==0 )
        buffer[i] = ' '; // Whitespace
    else
        buffer[i] = letters[ get_random_u8()%26 ];
  }
  buffer[len]='\0';
  return buffer;
} /* End of getRandomTextPayload() */



/** UNIMPLEMENTED */
int send_packet(NpingTarget *target, int rawfd, u8 *pkt, size_t pktLen){
  int res;
  struct sockaddr_in6 s6;
  assert(pkt);
  assert(target);
  assert(pktLen > 0);

  if ( o.sendEth() ){
    eth_t *ethsd = eth_open_cached(o.getDevice());
    eth_send(ethsd, pkt, pktLen);
  }else{
    if( o.ipv6() ){ /* IPv6 */
        memset(&s6, 0, sizeof(struct sockaddr_in6));
        s6.sin6_family=AF_INET6;
        s6.sin6_addr = target->getIPv6Address();

        /*
        if( o.getMode()==TCP ){
            dport=getDstPortFromTCPHeader(pkt, pktLen);
            if(dport!=NULL)
                s6.sin6_port = *dport;
            else
                nping_fatal(QT_3, "send_packet(): Could not determine TCP destination port.");
        }
        else if( o.getMode()==UDP){
            dport=getDstPortFromUDPHeader(pkt, pktLen);
            if(dport!=NULL)
                s6.sin6_port = *dport;
            else
                nping_fatal(QT_3, "send_packet(): Could not determine UDP destination port.");
        }
        */

        /* Linux doesn't seem to like sin6_port to be set to other value
         * than 0. Unless we set it to zero, the sendto() call returns
         * "Invalid argument" error. Does this happen in other systems?
         * TODO: Should we check here if #ifdef LINUX and set the port to
         * zero? */
         s6.sin6_port=0;

        res = Sendto("send_packet", rawfd, pkt, pktLen, 0, (struct sockaddr *)&s6, (int) sizeof(struct sockaddr_in6));
        /*Sendto returns errors as -1 according to netutil.cc so lets catch that and return OP_FAILURE*/
        if (res == -1) return OP_FAILURE;
    }else{ /* IPv4 */
        struct sockaddr_storage dst;
        size_t dstlen;

        dstlen = sizeof(dst);
        target->getTargetSockAddr(&dst, &dstlen);
        assert(dst.ss_family == AF_INET);
        if( o.issetMTU() == true )
            res = send_frag_ip_packet(rawfd, NULL, (struct sockaddr_in *) &dst, pkt, pktLen, o.getMTU() );
        else
            res = send_ip_packet_sd(rawfd, (struct sockaddr_in *) &dst, pkt, pktLen);
        /*send_ip_packet_sd calls Sendto which returns errors as -1 according to netutil.cc so lets catch that and return OP_FAILURE*/
        if (res == -1) return OP_FAILURE;
    }
  }
  return OP_SUCCESS;
} /* End of send_packet() */



int print_dnet_interface(const struct intf_entry *entry, void *arg) {
  if (entry==NULL)
    return 0;
  printf("*************************************************\n");
  printf("intf_len = %d\n", entry->intf_len);
  printf("intf_name = %s\n", entry->intf_name);
  printf("intf_type = %u\n", entry->intf_type);
  printf("intf_flags = %02x\n", entry->intf_flags);
  printf("intf_mtu = %d\n", entry->intf_mtu);
  printf("intf_addr = %s\n", addr_ntoa(&entry->intf_addr));
  printf("intf_dst_addr = %s\n", addr_ntoa(&entry->intf_dst_addr));
  printf("intf_link_addr = %s\n", addr_ntoa(&entry->intf_link_addr));
  printf("intf_alias_num = %d\n", entry->intf_alias_num);
  for(unsigned int i=0; i<entry->intf_alias_num; i++)
    printf("intf_alias_addrs[%d] = %s\n", i, addr_ntoa(&entry->intf_alias_addrs[i]));
  return 0;
}


/* Get a list of interfaces using dnet and intf_loop. */
int print_interfaces_dnet() {
  intf_t *it;
  /* Initialize the interface array. */
  it = intf_open();
  if (!it)
    fatal("%s: intf_open() failed. NULL descriptor", __func__);
  if (intf_loop(it, print_dnet_interface, NULL) != 0)
    fatal("%s: intf_loop() failed", __func__);
  intf_close(it);	
  return 0;
}



/** @warning Returns pointer to an internal static buffer */
struct sockaddr_storage *getSrcSockAddrFromIPPacket(u8 *pkt, size_t pktLen){
  static struct sockaddr_storage ss;
  struct sockaddr_in *s_ip4=(struct sockaddr_in *)&ss;
  struct sockaddr_in6 *s_ip6=(struct sockaddr_in6 *)&ss;
  struct ip *i4=(struct ip*)pkt;
  memset(&ss, 0, sizeof(struct sockaddr_storage));

  if(pkt==NULL || pktLen < 20)
    return NULL;

  if( i4->ip_v == 4 ){
    s_ip4->sin_family=AF_INET;
    memcpy(&(s_ip4->sin_addr.s_addr), pkt+12, 4);
  }
  else if(i4->ip_v == 6 ){
    if(pktLen<40) /* Min length of an IPv6 header: 40 bytes*/
        return NULL;
    s_ip6->sin6_family=AF_INET6;
    memcpy(s_ip6->sin6_addr.s6_addr, pkt+8, 16);
  }
  else{
      return NULL;
  }
  return &ss;
} /* End of getSrcSockAddrFromPacket() */





u8 *getUDPheaderLocation(u8 *pkt, size_t pktLen){
  struct ip *i4=(struct ip*)pkt;
  if(pkt==NULL || pktLen < 40)
    return NULL;

  /* Packet is IPv4 */
  if( i4->ip_v == 4 ){
    if (i4->ip_p == IPPROTO_UDP) {
        if( pktLen >= ((size_t)(i4->ip_hl*4 + 8)) ) /* We have a full IP+UDP packet */
            return pkt+(i4->ip_hl*4);    
    }
    else
        return NULL;
  }
  /* Packet is IPv6 */
  else if(i4->ip_v == 6 ){
    if(pktLen<40 + 8 )
        return NULL;
    if( pkt[6] == IPPROTO_UDP ) /* Next Header is UDP? */
        return pkt+40;
    else /* Extension headers not supported, return NULL TODO: support it? */
        return NULL;
  }
  else{
      return NULL;
  }
  return NULL;
} /* End of getUDPheaderLocation */


u8 *getTCPheaderLocation(u8 *pkt, size_t pktLen){
  struct ip *i4=(struct ip*)pkt;
  if(pkt==NULL || pktLen < 40)
    return NULL;

  /* Packet is IPv4 */
  if( i4->ip_v == 4 ){
    if (i4->ip_p == IPPROTO_TCP) { /* Next proto is TCP? */
        if( pktLen >= ((size_t)(i4->ip_hl*4 + 20)) ) /* We have a full IP+TCP packet */
            return pkt+(i4->ip_hl*4);    
    }
    else
        return NULL;
  }
  /* Packet is IPv6 */
  else if(i4->ip_v == 6 ){
    if(pktLen<40 + 20 )
        return NULL;
    if( pkt[6] == IPPROTO_TCP ) /* Next Header is TCP? */
        return pkt+40;
    else /* Extension headers not supported, return NULL TODO: support it? */
        return NULL;
  }
  else{
      return NULL;
  }

  return NULL;

} /* End of getTCPHeaderLocation() */




/* Returns the IP protocol of the packet or -1 in case of failure */
u8 getProtoFromIPPacket(u8 *pkt, size_t pktLen){
  struct ip *i4=(struct ip*)pkt;
  static u8 proto;

  if(pkt==NULL || pktLen < 28)
    return -1;

  /* Packet is IPv4 */
  if( i4->ip_v == 4 ){
    proto = i4->ip_p;
    return proto;
  }

  /* Packet is IPv6 */
  else if(i4->ip_v == 6 ){
    proto = pkt[6];
    return proto;
  }
  return -1;
} /* End of getProtoFromIPPacket() */



/** @warning Returns pointer to an internal static buffer
 * @return pointer on success, NULL in case of failure */
u16 *getSrcPortFromIPPacket(u8 *pkt, size_t pktLen){
  static u16 port;
  u16 *pnt=NULL;
  u8 *header=NULL;

  if(pkt==NULL || pktLen < 28)
    return NULL;

  if((header=getTCPheaderLocation(pkt, pktLen))==NULL){
    if ((header=getUDPheaderLocation(pkt, pktLen))==NULL)
      return NULL;

  }
  pnt=(u16*)&(header[0]);
  port= ntohs(*pnt);
  return &port;
} /* End of getSrcPortFromIPPacket() */


/** @warning Returns pointer to an internal static buffer
 * @return pointer on success, NULL in case of failure */
u16 *getDstPortFromIPPacket(u8 *pkt, size_t pktLen){
  static u16 port;
  u16 *pnt=NULL;
  u8 *header=NULL;

  if(pkt==NULL || pktLen < 28)
    return NULL;

  if((header=getTCPheaderLocation(pkt, pktLen))==NULL){
    if ((header=getUDPheaderLocation(pkt, pktLen))==NULL)
      return NULL;
  }
  pnt=(u16*)&(header[2]);
  port= ntohs(*pnt);
  return &port;
} /* End of getDstPortFromIPPacket() */


/** @warning Returns pointer to an internal static buffer
 * @return pointer on success, NULL in case of failure */
u16 *getDstPortFromTCPHeader(u8 *pkt, size_t pktLen){
  static u16 port;
  u16 *pnt=NULL;

  if(pkt==NULL || pktLen < 20)
    return NULL;
  pnt=(u16*)&(pkt[2]);
  port= ntohs(*pnt);
  return &port;
} /* End of getDstPortFromTCPHeader() */


/** @warning Returns pointer to an internal static buffer
 * @return pointer on success, NULL in case of failure */
u16 *getDstPortFromUDPHeader(u8 *pkt, size_t pktLen){
  static u16 port;
  u16 *pnt=NULL;

  if(pkt==NULL || pktLen < 8)
    return NULL;
  pnt=(u16*)&(pkt[2]);
  port= ntohs(*pnt);
  return &port;
} /* End of getDstPortFromUDPHeader() */


int obtainRawSocket(){
  int rawipsd=0;
  int protocol=0;
  int one=1;

  if( o.ipv6() ){
    switch( o.getMode() ){

        case TCP:
            protocol = IPPROTO_TCP;
        break;

        case UDP:
            protocol = IPPROTO_UDP;
        break;

        case ICMP:
            protocol = IPPROTO_ICMPV6;
        break;

        case ARP:
            nping_warning(QT_2,"Warning: createRawSocket() should not be called in ARP mode.");
            return 0;
        break;

        default:
            nping_fatal(QT_3, "createRawSocket(): NpingOps::getMode() does not return a valid mode. Please report this bug.");
        break;

    }
    if ((rawipsd = socket(AF_INET6, SOCK_RAW, protocol)) < 0 )
        nping_fatal(QT_3,"Couldn't acquire IPv6 raw socket. Are you root?");

  }else{
    if ((rawipsd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0 )
        nping_fatal(QT_3,"Couldn't acquire IPv4 raw socket. Are you root?");
    /* Tell the kernel we are including our own IP Header (call to
     * setsockopt passing option IP_HDRINCL) */
    sethdrinclude(rawipsd);
  }

  /* Allow broadcast addresses */
  if (setsockopt(rawipsd, SOL_SOCKET, SO_BROADCAST, (const char *)&one, sizeof(int)) == -1)
      nping_warning(QT_2,"Failed to set SO_BROADCAST on raw socket.");

  return rawipsd;
} /* End of obtainRawSocket() */


/** This function parses Linux file /proc/net/if_inet6 and returns a list
    of network interfaces that are configured for IPv6.
    @param ifbuff should be a buffer big enough to hold info for max_ifaces
    interfaces. 

 Here is some info about the format of /proc/net/if_inet6, written by
 Peter Bieringer and taken from:
 http://tldp.org/HOWTO/Linux+IPv6-HOWTO/proc-net.html :

 # cat /proc/net/if_inet6
 00000000000000000000000000000001 01 80 10 80 lo
 +------------------------------+ ++ ++ ++ ++ ++
 |                                |  |  |  |  |
 1                                2  3  4  5  6

 1. IPv6 address displayed in 32 hexadecimal chars without colons as separator
 2. Netlink device number (interface index) in hexadecimal (see “ip addr” , too)
 3. Prefix length in hexadecimal
 4. Scope value (see kernel source “ include/net/ipv6.h” and “net/ipv6/addrconf.c” for more)
 5. Interface flags (see “include/linux/rtnetlink.h” and “net/ipv6/addrconf.c” for more)
 6. Device name


  @warning This function is NOT portable. It will only work on Linux systems
   and may not work in chroot-ed environments because it needs to be able
   to access  /proc/net/if_inet6.

 */
int getinterfaces_inet6_linux(if6_t *ifbuf, int max_ifaces){
  FILE *if6file=NULL;
  size_t i=0, j=0;
  int readlines=0;
  int parsed_ifs=0;
  bool badaddr=false;
  bool hasifname=false;
  char buffer[2048];
  char twobytes[3];
  memset(buffer, 0, sizeof(buffer));

  if(ifbuf==NULL || max_ifaces<=0)
    nping_fatal(QT_3,"getinterfaces_inet6_linux() NULL values supplied");

  /* TODO: Do we fatal() or should we just error and return OP_FAILURE? */
  if ( !file_is_readable(PATH_PROC_IFINET6) )
    nping_fatal(QT_3, "Couldn't get IPv6 interface information. File %s does not exist or you don't have read permissions.", PATH_PROC_IFINET6);
  if( (if6file=fopen(PATH_PROC_IFINET6, "r"))==NULL )
    nping_fatal(QT_3, "Failed to open %s.", PATH_PROC_IFINET6);

  while( fgets(buffer,sizeof(buffer), if6file) ){

      if(parsed_ifs>=max_ifaces)
        break;

    nping_print(DBG_4, "Read %s:%d: %s\n", PATH_PROC_IFINET6, ++readlines, buffer);

    /* Check the line has the expected format ********************************/
    /* Some versions of the kernel include colons in the IPv6 address, some
     * others don't. E.g:
     * fe80:0000:0000:0000:0333:a5ff:4444:9306 03 40 20 80 wlan0
     * fe800000000000000333a5ff44449306 03 40 20 80 wlan0
     * So what we do is to remove the colons so we can process the line
     * no matter the format of the IPv6 addresses.
     *
     * TODO: Can interfaces with format eth0:1 appear on /proc/net/if_inet6?
     * If they can, then we need to change the code to skip the last : */
    removecolon(buffer);

    /* 1. Check it has the correct length */
    if( strlen(buffer) < strlen("00000000000000000000000000000001 01 80 10 80       lo") ){
        continue;
    }
    /* 2. Check the inet6 address only contains hex digits */
    for(i=0; i<32; i++){
        if( !isxdigit(buffer[i]) ){
            badaddr=true;
            break;
        }
    }
    if(badaddr){
        badaddr=false;
        continue;
    }
    /* 2. Check spaces are in the appropriate place */
    if( buffer[32]!=' ' || buffer[35]!=' ' || buffer[38]!=' ' ||  buffer[41]!=' ' ||  buffer[44]!=' ' ){
        continue;
    }

    /* 3. Check we have numbers in the part where we are supposed to have them */
    if( !isxdigit( buffer[33] ) ||  !isxdigit( buffer[34] ) ||
        !isxdigit( buffer[36] ) ||  !isxdigit( buffer[37] ) ||
        !isxdigit( buffer[39] ) ||  !isxdigit( buffer[40] ) ||
        !isxdigit( buffer[42] ) ||  !isxdigit( buffer[43] ) ){
            continue;
    }

    /* 4. Check we actually have an interface name afterwards */
    for(i=44; i<strlen(buffer); i++){
        if( isalpha(buffer[i]) )
            hasifname=true;
    }
    if(!hasifname){
        hasifname=false;
        continue;
    }

    /* If we get here means the read line has the expected format so we
     * read the information and store it in a interface_info structure *
     */

    /* Store IPv6 address */
    u8 ipv6addr[16];
    for(i=0, j=0; j<16 && i<32; i+=2){
        twobytes[0]=buffer[i];
        twobytes[1]=buffer[i+1];
        twobytes[2]='\0';
        ipv6addr[j++]=(u8)strtol(twobytes, NULL, 16);
    }

    /* Store Netlink device number */
    u8 dev_no;
    twobytes[0]=buffer[33]; twobytes[1]=buffer[34]; twobytes[2]='\0';
    dev_no=(u8)strtol(twobytes, NULL, 16);

    /* Store prefix length */
    u8 prefix_len;
    twobytes[0]=buffer[36]; twobytes[1]=buffer[37]; twobytes[2]='\0';
    prefix_len=(u8)strtol(twobytes, NULL, 16);

    /* Store scope value */
    u8 scope_value;
    twobytes[0]=buffer[39]; twobytes[1]=buffer[40]; twobytes[2]='\0';
    scope_value=(u8)strtol(twobytes, NULL, 16);

    /* Store interface flags */
    u8 dev_flags;
    twobytes[0]=buffer[42]; twobytes[1]=buffer[43]; twobytes[2]='\0';
    dev_flags=(u8)strtol(twobytes, NULL, 16);

    /* Store interface name */
    char devname[DEVNAMELEN];
    memset(devname, 0, DEVNAMELEN);
    for(i=44, j=0; i<strlen(buffer) && j<DEVNAMELEN-1; i++){
        if( buffer[i]==' ' || buffer[i]=='\n')
            continue;
        else
            devname[j++]=buffer[i];            
    }
    devname[j]='\0';


    /* Once we have all the info, copy it to user supplied buffer */
    memset(&ifbuf[parsed_ifs], 0, sizeof(if6_t));
    memcpy( ifbuf[parsed_ifs].devname, devname, DEVNAMELEN);
    struct sockaddr_in6 *s6=(struct sockaddr_in6 *)&ifbuf[parsed_ifs].ss;
    s6->sin6_family=AF_INET6;
    memcpy(s6->sin6_addr.s6_addr, ipv6addr, 16);
    memcpy(ifbuf[parsed_ifs].addr, ipv6addr, 16);
    ifbuf[parsed_ifs].netmask_bits=prefix_len;
    ifbuf[parsed_ifs].dev_no=dev_no;
    ifbuf[parsed_ifs].scope=scope_value;
    ifbuf[parsed_ifs].flags=dev_flags;
    /*  ifbuf[parsed_ifs].mac = ???   (we don't know, we don't set it) */

   parsed_ifs++;

/* Debugging code: This should print the exact same lines that
 * /proc/net/if_inet6 contains. (well, unless that kernel includes colons
 * in the ipv6 address)
 * 
    for(i=0; i<16; i++)
        printf("%02x", ipv6addr[i]);
    printf(" %02x", dev_no);
    printf(" %02x", prefix_len);
    printf(" %02x", scope_value);
    printf(" %02x", dev_flags); 
    printf(" %8s\n", devname);        
 */

  } /* End of loop */

  /* Cleanup */
  if(if6file)
    fclose(if6file);
  return parsed_ifs;
} /* End of getinterfaces_inet6_linux() */


/** This function parses Linux file /proc/net/ipv6_route and returns a list
    of routes for IPv6 packets.
    @param ifbuff should be a buffer big enough to hold info for max_routes
    routes. 

 Here is some info about the format of /proc/net/if_inet6, written by
 Peter Bieringer and taken from:
 http://tldp.org/HOWTO/Linux+IPv6-HOWTO/proc-net.html :

 # cat /proc/net/ipv6_route
 00000000000000000000000000000000 00 00000000000000000000000000000000 00
 +------------------------------+ ++ +------------------------------+ ++
 |                                |  |                                |
 1                                2  3                                4 

 ¬ 00000000000000000000000000000000 ffffffff 00000001 00000001 00200200 lo
 ¬ +------------------------------+ +------+ +------+ +------+ +------+ ++
 ¬ |                                |        |        |        |        |
 ¬ 5                                6        7        8        9        10

 1. IPv6 destination network displayed in 32 hexadecimal chars without colons as separator
 2. IPv6 destination prefix length in hexadecimal
 3. IPv6 source network displayed in 32 hexadecimal chars without colons as separator
 4. IPv6 source prefix length in hexadecimal
 5. IPv6 next hop displayed in 32 hexadecimal chars without colons as separator
 6. Metric in hexadecimal
 7. Reference counter
 8. Use counter
 9. Flags
10. Device name

  @warning This function is NOT portable. It will only work on Linux systems
   and may not work in chroot-ed environments because it needs to be able
   to access /proc/net/ipv6_route.
 */
int getroutes_inet6_linux(route6_t *rtbuf, int max_routes){
  FILE *route6file=NULL;
  size_t i=0, j=0;
  int readlines=0;
  int parsed_routes=0;
  bool badchars=false;
  bool hasifname=false;
  char buffer[2048];
  char twobytes[3];
  memset(buffer, 0, sizeof(buffer));

  if(rtbuf==NULL || max_routes<=0)
    nping_fatal(QT_3,"getroutes_inet6_linux() NULL values supplied");

  /* TODO: Do we fatal() or should we just error and return OP_FAILURE? */
  if ( !file_is_readable(PATH_PROC_IPV6ROUTE) )
    nping_fatal(QT_3, "Couldn't get IPv6 route information. File %s does not exist or you don't have read permissions.", PATH_PROC_IPV6ROUTE);
  if( (route6file=fopen(PATH_PROC_IPV6ROUTE, "r"))==NULL )
    nping_fatal(QT_3, "Failed to open %s.", PATH_PROC_IPV6ROUTE);

  while( fgets(buffer,sizeof(buffer), route6file) ){

      if(parsed_routes>=max_routes)
        break;

    nping_print(DBG_4, "Read %s:%d: %s\n",PATH_PROC_IPV6ROUTE, ++readlines, buffer);

    /* Check the line has the expected format ********************************/
    /* Some versions of the kernel include colons in the IPv6 address, some
     * others don't. So what we do is to remove the colons so we can process
     * the line no matter the format of the IPv6 addresses.
     *
     * TODO: Can interfaces with format eth0:1 appear on /proc/net/ipv6_route?
     * If they can, then we need to change the code to skip the last : */
    removecolon(buffer);

    /* 1. Check it has the correct length.  */
    size_t min_len=0;
    min_len += 3*32; /* Three IPv6 addresses in hex */
    min_len += 2*2;  /* Two 8bit hex values (prefix lengths) */
    min_len += 4*8;  /* Four 32-bit hex values */
    min_len += 1;    /* I guess one char is the min for a device len */
    min_len += 9;    /* 9 spaces */
    if( strlen(buffer) < min_len ){
        continue;
    }
    /* 2. Check the first 140 characters only contain hex digits or spaces */
    for(i=0; i<140; i++){
        if( !isxdigit(buffer[i]) && buffer[i]!=' '){
            badchars=true;
            break;
        }
    }
    if(badchars){
        badchars=false;
        continue;
    }
    /* 2. Check spaces are in the appropriate place */
    if( buffer[32]!=' ' || buffer[71]!=' '  || buffer[122]!=' ' ||
        buffer[35]!=' ' || buffer[104]!=' ' || buffer[131]!=' ' ||
        buffer[68]!=' ' || buffer[113]!=' ' || buffer[140]!=' ' ){
        continue;
    }

    /* 4. Check we actually have an interface name afterwards */
    for(i=140; i<strlen(buffer); i++){
        if( isalpha(buffer[i]) )
            hasifname=true;
    }
    if(!hasifname){
        hasifname=false;
        continue;
    }

    /* If we get here means the read line has the expected format so we
     * read the information and store it in a interface_info structure *
     */

    /* Store destination network address */
    u8 dst_addr[16];
    for(i=0, j=0; j<16 && i<32; i+=2){
        twobytes[0]=buffer[i]; twobytes[1]=buffer[i+1]; twobytes[2]='\0';
        dst_addr[j++]=(u8)strtol(twobytes, NULL, 16);
    }    
    /* Store destination network prefix */
    u8 dst_prefix;
    twobytes[0]=buffer[33]; twobytes[1]=buffer[34]; twobytes[2]='\0';
    dst_prefix=(u8)strtol(twobytes, NULL, 16);

    /* Store source network address */
    u8 src_addr[16];
    for(i=36, j=0; j<16 && i<68; i+=2){
        twobytes[0]=buffer[i]; twobytes[1]=buffer[i+1]; twobytes[2]='\0';
        src_addr[j++]=(u8)strtol(twobytes, NULL, 16);
    }    
    /* Store source network prefix */
    u8 src_prefix;
    twobytes[0]=buffer[69]; twobytes[1]=buffer[70]; twobytes[2]='\0';
    src_prefix=(u8)strtol(twobytes, NULL, 16);

    /* Store next hop address */
    u8 nh_addr[16];
    for(i=72, j=0; j<16 && i<104; i+=2){
        twobytes[0]=buffer[i]; twobytes[1]=buffer[i+1]; twobytes[2]='\0';
        nh_addr[j++]=(u8)strtol(twobytes, NULL, 16);
    }

    /* Store metric */
    u8 metric[4];
    for(i=105, j=0; j<4 && i<113; i+=2){
        twobytes[0]=buffer[i]; twobytes[1]=buffer[i+1]; twobytes[2]='\0';
        metric[j++]=(u8)strtol(twobytes, NULL, 16);
    }

    /* Store reference counter */
    u8 ref_count[4];
    for(i=114, j=0; j<4 && i<122; i+=2){
        twobytes[0]=buffer[i]; twobytes[1]=buffer[i+1]; twobytes[2]='\0';
        ref_count[j++]=(u8)strtol(twobytes, NULL, 16);
    }

    /* Store use counter */
    u8 use_count[4];
    for(i=123, j=0; j<4 && i<131; i+=2){
        twobytes[0]=buffer[i]; twobytes[1]=buffer[i+1]; twobytes[2]='\0';
        use_count[j++]=(u8)strtol(twobytes, NULL, 16);
    }

    /* Store flags */
    u8 flags[4];
    for(i=132, j=0; j<4 && i<140; i+=2){
        twobytes[0]=buffer[i]; twobytes[1]=buffer[i+1]; twobytes[2]='\0';
        flags[j++]=(u8)strtol(twobytes, NULL, 16);
    }

    /* Store interface name */
    char devname[DEVNAMELEN];
    memset(devname, 0, DEVNAMELEN);
    for(i=140, j=0; i<strlen(buffer) && j<DEVNAMELEN-1; i++){
        if( buffer[i]==' ' || buffer[i]=='\n')
            continue;
        else
            devname[j++]=buffer[i];            
    }
    devname[j]='\0';

    /* Once we have all the info, copy it to user supplied buffer */
    memset(&rtbuf[parsed_routes], 0, sizeof(route6_t));
    memcpy(rtbuf[parsed_routes].dst_net.s6_addr, dst_addr, 16);
    rtbuf[parsed_routes].dst_prefix=dst_prefix;
    memcpy(rtbuf[parsed_routes].src_net.s6_addr, src_addr, 16);
    rtbuf[parsed_routes].src_prefix=src_prefix;
    memcpy(rtbuf[parsed_routes].next_hop.s6_addr, nh_addr, 16);

    /* TODO: Check the endianness stuff here is implemented right.
     * The thing is that the part of the linux kernel that prints the info
     * to /proc/net/ipv6_rout is the following:
     * [From  /net/ipv6/route.c ]
     * 2427         seq_printf(m, " %08x %08x %08x %08x %8s\n",
     * 2428                    rt->rt6i_metric, atomic_read(&rt->u.dst.__refcnt),
     * 2429                    rt->u.dst.__use, rt->rt6i_flags,
     * 2430                    rt->rt6i_dev ? rt->rt6i_dev->name : "");
     *
     * So as they are actually printing 32bit values with %08x, they are
     * getting printed out in network byte order (big endian) so we call
     * ntohl() for each of them so we actually convert them to the right
     * representation in the current machine. With 8-bit values we have no
     * problem because they are converted to binary using strtol() and it
     * handles endianness by itself. Am I doing anything wrong here?
     * */
    memcpy(&rtbuf[parsed_routes].metric, metric, 4);
    rtbuf[parsed_routes].metric=ntohl(rtbuf[parsed_routes].metric);
    memcpy(&rtbuf[parsed_routes].ref_count, ref_count, 4);
    rtbuf[parsed_routes].ref_count=ntohl(rtbuf[parsed_routes].ref_count);
    memcpy(&rtbuf[parsed_routes].use_count, use_count, 4);
    rtbuf[parsed_routes].use_count=ntohl(rtbuf[parsed_routes].use_count);
    memcpy(&rtbuf[parsed_routes].flags, flags, 4);
    rtbuf[parsed_routes].flags=ntohl(rtbuf[parsed_routes].flags);
    memcpy(rtbuf[parsed_routes].devname, devname, DEVNAMELEN);

/* Debugging code: This should print the exact same lines that
 * /proc/net/if_inet6 contains. (well, unless that kernel includes colons
 * in the ipv6 address)
 *
    for(i=0; i<16; i++)
        printf("%02x", rtbuf[parsed_routes].dst_net.s6_addr[i]);

    printf(" %02x ", rtbuf[parsed_routes].dst_prefix);

    for(i=0; i<16; i++)
        printf("%02x", rtbuf[parsed_routes].src_net.s6_addr[i]);

    printf(" %02x ", rtbuf[parsed_routes].src_prefix);

    for(i=0; i<16; i++)
        printf("%02x", rtbuf[parsed_routes].next_hop.s6_addr[i]);

    printf(" %08x", rtbuf[parsed_routes].metric);
    printf(" %08x", rtbuf[parsed_routes].ref_count);
    printf(" %08x", rtbuf[parsed_routes].use_count);
    printf(" %08x", rtbuf[parsed_routes].flags);
    printf(" %8s\n", rtbuf[parsed_routes].devname);        
*/
   parsed_routes++;

  } /* End of loop */

  /* Cleanup */
  if(route6file)
    fclose(route6file);
  return parsed_routes;
} /* End of getroutes_inet6_linux() */


/** This function takes a sockaddr_storage pointer that MUST contain a valid
  * IPv6 address (a sockaddr_in6 struct with sin6_family set to AF_INET6),
  * and returns the best route entry for the supplied destination.
  * The route entries are read from /proc/net/ipv6_route through function
  * getroutes_inet6_linux().
  * @warning This function is NOT portable. It will only work on Linux systems
  * and may not work in chroot-ed environments because it needs to be able
  * to access /proc/net/ipv6_route.
  * @warning It returns NULL in case of error. Check for it or you'll segfault.
  * @warning returned pointer points to a static buffer that subsequent calls
  * will overwrite.  */
route6_t *route_dst_ipv6_linux(const struct sockaddr_storage *const dst){
  struct sockaddr_in6 *dstsin6=NULL; /* Cast for supplied sockaddr_storage var */
  route6_t routes6[64];              /* Array of IPv6 routes                   */
  int total_routes6=0;               /* Number of returned routes              */
  static route6_t theone;            /* Stores the best route we find          */
  route6_t *def_gw=NULL;             /* Stores default gateway                 */
  int best_match=0;                  /* Max number of bits that we've matched  */
  int curr_match=0;                  /* Matching bits in current route         */
  u8 zero_addr[16];                  /* Just to compare route to addr "::"     */
  memset(zero_addr, 0, 16);
  dstsin6=(struct sockaddr_in6 *)dst;

  if(dst==NULL) return NULL;
  if(dstsin6->sin6_family!=AF_INET6) return NULL;

  /* Let's parse /proc/net/ipv6_route and get a list of routes */
  if ( (total_routes6=getroutes_inet6_linux(routes6, 64)) <= 0 )
    return NULL;

  /* Now we go over the whole route list and select the match that has the
   * largest prefix length */

  for(int i=0; i<total_routes6; i++){
    /* Check how many bits they have in common */
    curr_match=bitcmp(dstsin6->sin6_addr.s6_addr, routes6[i].dst_net.s6_addr, 16);

    /* Select only the best match (always taking into account that
     * our dst address needs to match at least dst_prefix bits. */
    if( curr_match > best_match && curr_match>=routes6[i].dst_prefix){
        best_match=curr_match;
        memcpy(&theone, &routes6[i], sizeof(route6_t));
    }
    /* There was no match, but we check if the route is actually "::"
     * (like 0.0.0.0 in IPv4). If it is, we store it, just in case we
     * end up without a better route. */
    else if ( !memcmp( routes6[i].dst_net.s6_addr, zero_addr, 16) ){
            if(def_gw==NULL){
                def_gw=&routes6[i];
            }
            else if( !strncmp("lo", def_gw->devname, 2) ){
                /* If the route we have is through the loopback interface,
                 * overwrite it, we prefer to choose any other device as
                 * the default gateway. We just compare the first two
                 * letters cause in Linux the interface is called "lo" but
                 * on BSD is usually called lo0.  */
                    def_gw=&routes6[i];
            }
    }
  }
  if( best_match==0 ){
    if(def_gw!=NULL)
        memcpy(&theone, def_gw, sizeof(route6_t));
    else return NULL;
  }
  return &theone;
} /* End of route_dst_ipv6() */
