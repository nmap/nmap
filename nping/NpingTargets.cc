
/***************************************************************************
 * NpingTargets.cc -- Class that handles target spec parsing and allows to *
 * obtain the different targets that need to be ping-ed.                   *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *
 * The Nmap Security Scanner is (C) 1996-2023 Nmap Software LLC ("The Nmap
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
 * Source code also allows you to port Nmap to new platforms, fix bugs, and add
 * new features. You are highly encouraged to submit your changes as a Github PR
 * or by email to the dev@nmap.org mailing list for possible incorporation into
 * the main distribution. Unless you specify otherwise, it is understood that
 * you are offering us very broad rights to use your submissions as described in
 * the Nmap Public Source License Contributor Agreement. This is important
 * because we fund the project by selling licenses with various terms, and also
 * because the inability to relicense code has caused devastating problems for
 * other Free Software projects (such as KDE and NASM).
 *
 * The free version of Nmap is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Warranties,
 * indemnification and commercial support are all available through the
 * Npcap OEM program--see https://nmap.org/oem/
 *
 ***************************************************************************/

#include "nping.h"
#include "NpingOps.h"
#include "global_structures.h"
#include "output.h"
#include "nbase.h"
#include "utils.h"
#include "NpingTargets.h"
#include "common.h"
#include "common_modified.h"

extern NpingOps o;
#ifdef WIN32
/* from libdnet's intf-win32.c */
extern "C" int g_has_npcap_loopback;
#endif

NpingTargets::NpingTargets(){
  memset(specs, 0, 1024*(sizeof(char *)) );
  memset(skipspec, 0, 1024*(sizeof(bool)) );
  speccount=0;
  current_spec=-1;
  finished=false;
  targets_fetched=0;
  current_target=0;
  ready=false;
} /* End of NpingTargets constructor */


NpingTargets::~NpingTargets(){
} /* End of NpingTargets destructor */


/** Adds a target specification to an internal array of specs */
int NpingTargets::addSpec(char *spec){
  if(spec==NULL)
    return OP_FAILURE;
  if( this->speccount >= 1024 )
    return OP_FAILURE;
  specs[ this->speccount ] = spec;
  this->speccount++;
  return OP_SUCCESS;
} /* End of NpingTargets */


/** Returns next target */
int NpingTargets::getNextTargetAddressAndName(struct sockaddr_storage *t, size_t *tlen, char *hname, size_t hlen){
  struct sockaddr_storage next;
  memset(&next, 0, sizeof(struct sockaddr_storage));
  size_t nextlen=0;
  int r=0;
  int family= (o.getIPVersion()==IP_VERSION_6) ? AF_INET6 : AF_INET;

  if( t==NULL || tlen==NULL )
    nping_fatal(QT_3,"getNextTarget(): NULL values supplied.");

  /* Return failure if there are no specs or we noticed that we were finished in
   * a previous call. */
  if ( this->speccount <= 0 || finished==true )
    return OP_FAILURE;

  /* If this is the first time we call to this method */
  if (this->current_spec == -1 ){

    current_spec=0;
    if ( !skipspec[ current_spec ] ){
     if ( current_group.parse_expr( specs[ current_spec ], family ) != 0 ){
        skipspec[ current_spec ]=true; /* Make sure we skip it next time */
        return OP_FAILURE;

        }
    }
    else{ /* We are skipping current target, return the next one */
        return  this->getNextTargetAddressAndName(t, tlen, hname, hlen);
    }
  }

  r=current_group.get_next_host(&next, &nextlen);

  if ( r!=0 ){ /* We exhausted current group */
    /* Is there any other group? */
     if (++current_spec == speccount){ /* No more specs to parse */
        finished=true;
        return OP_FAILURE;
     }
     /* Ok, there are more groups, so let's go with the next spec */
    if ( !skipspec[ current_spec ] ){
        if ( current_group.parse_expr( specs[ current_spec ], family ) != 0 ){
            skipspec[ current_spec ]=true;
            return this->getNextTargetAddressAndName(t, tlen, hname, hlen);

        }
    }
    else{ /* We are skipping current target, return the next one */
        return  this->getNextTargetAddressAndName(t, tlen, hname, hlen);
    }

    r=current_group.get_next_host(&next, &nextlen);

     if (r != 0)
        nping_fatal(QT_3,"BUG: TargetGroups are supposed to contain at least one IP! ");
  }
  memcpy( t, &next, sizeof( struct sockaddr_storage ) );
  /* If current spec is a named host (not a range), store name in supplied buff */
  if(current_group.get_namedhost()){
    if( hname!=NULL && hlen>0 )
        strncpy(hname, specs[ current_spec ], hlen);  
  }else{ /* If current spec is not a named host, insert NULL in the first position */
    if( hname!=NULL && hlen>0 )
        hname[0]='\0';
  } 
  *tlen=nextlen;
  targets_fetched++;
  return OP_SUCCESS;
 } /* End of getNextTarget() */


int NpingTargets::getNextIPv4Address(u32 *addr){
  struct sockaddr_storage t;
  size_t tlen;
  char buff[257];
  memset(buff, 0, 257);
  if( addr == NULL )
    nping_fatal(QT_3, "getNextIPv4Address(): NULL value supplied. ");
  if ( this->getNextTargetAddressAndName(&t, &tlen, buff, 256) != OP_SUCCESS )
    return OP_FAILURE;
  struct sockaddr_in *p=( struct sockaddr_in *)&t;
  if(p->sin_family!=AF_INET)
	nping_fatal(QT_3, "getNextIPv4Address(): Trying to obtain an IPv4 address from an IPv6 target.");
  *addr = p->sin_addr.s_addr;
  return OP_SUCCESS;
} /* End of getNextIPv4Address() */


int NpingTargets::rewindSpecs(){
  current_spec=-1;
  finished=false;
  targets_fetched=0;
  return OP_SUCCESS;
} /* End of rewind() */


unsigned long int NpingTargets::getTargetsFetched(){
  return this->Targets.size();
} /* getTargetsFetched() */


int NpingTargets::getTargetSpecCount(){
  return this->speccount;
} /* End of getTargetSpecCount() */


/** This method should be called when all the target specs have been entered
  * using addSpec(). What it does is to create a NpingTarget objects for
  * each IP address extracted from the specs. Objects are stored in an internal
  * vector. */
int NpingTargets::processSpecs(){
  char buff[MAX_NPING_HOSTNAME_LEN+1];
  struct sockaddr_storage ss;
  size_t slen=0;
  bool result=false;
  struct route_nfo rnfo;

  memset(&ss, 0, sizeof(struct sockaddr_storage));
  memset(buff, 0, MAX_NPING_HOSTNAME_LEN+1);

  /* Rewind spec index just in case someone has been playing around with it */
  o.targets.rewindSpecs();

  /* Get next host IP address and, if it is a named host, its hostname */
  while ( this->getNextTargetAddressAndName(&ss, &slen, buff, MAX_NPING_HOSTNAME_LEN) == OP_SUCCESS ){
      NpingTarget *mytarget = new NpingTarget();
      mytarget->setTargetSockAddr(&ss, slen);
      if( buff[0]=='\0')
        mytarget->setNamedHost(false);
      else{
        mytarget->setSuppliedHostName(buff);
        mytarget->setNamedHost(true);
      }

    /* For the moment, we only run this code if we are not dealing with IPv6 */
    if( !o.ipv6() ){

      /* Get all the information needed to send packets to this target.
	   * (Only in case we are not in unprivileged modes) */
		if(o.getMode()!=TCP_CONNECT && o.getMode()!=UDP_UNPRIV){
		  result=route_dst( &ss, &rnfo, o.getDevice(), NULL );
		  if(result==false){
			nping_warning(QT_2, "Failed to determine route to host %s. Skipping it...", mytarget->getTargetIPstr() );
			delete mytarget;
			continue;
		  }
#ifdef WIN32
		if (g_has_npcap_loopback == 0 && rnfo.ii.device_type == devt_loopback){
			nping_warning(QT_2, "Skipping %s because Windows does not allow localhost scans (try --unprivileged).", mytarget->getTargetIPstr() );
			delete mytarget;
			continue;
		}
#endif
		   /* Determine next hop */
		  if( rnfo.direct_connect ){
			mytarget->setDirectlyConnected(true);
			mytarget->setNextHop(&ss, slen);
		  }
		  else{
			mytarget->setDirectlyConnected(false);  
			mytarget->setNextHop(&rnfo.nexthop, sizeof(struct sockaddr_storage));
		  }
		  /* Source IP address that we should use when targeting this host */
		  mytarget->setSourceSockAddr(&rnfo.srcaddr, sizeof(struct sockaddr_storage));

		  /* If user requested to spoof IP source address, set it */
		  if( o.spoofSource() ){
			mytarget->setSpoofedSourceSockAddr( o.getSourceSockAddr(), sizeof(struct sockaddr_storage));
		  }

		  /* Network interface */  
		  mytarget->setDeviceNames( rnfo.ii.devname, rnfo.ii.devfullname );
		  mytarget->setDeviceType( rnfo.ii.device_type );

		  /* Set source MAC address */
		  mytarget->setSrcMACAddress( rnfo.ii.mac );

		  if( rnfo.ii.device_up == false )
			nping_warning(QT_2, "Device used for target host %s seems to be down.", mytarget->getTargetIPstr());

		  /* Determine next hop MAC address and target MAC address */
		  if( o.sendEth() ){
#ifdef WIN32
		    if (g_has_npcap_loopback == 1 && rnfo.ii.device_type == devt_loopback) {
		      mytarget->setNextHopMACAddress(mytarget->getSrcMACAddress());
		    }
		    else {
#endif
		      mytarget->determineNextHopMACAddress();
		      mytarget->determineTargetMACAddress(); /* Sets Target MAC only if is directly connected to us */
#ifdef WIN32
		    }
#endif
          }
		  /* If we are in debug mode print target details */
		  if(o.getDebugging() >= DBG_3)
			mytarget->printTargetDetails();
		}
    }else{
        struct sockaddr_storage ss;
        struct sockaddr_in6 *s6=(struct sockaddr_in6 *)&ss;
        memset(&ss, 0, sizeof(sockaddr_storage));
        s6->sin6_family=AF_INET6;        
        mytarget->setSourceSockAddr(&ss, sizeof(struct sockaddr_storage));
    }

      /* Insert current target into targets array */
      this->Targets.push_back(mytarget);
  }

  /* getNextTarget() checks this to ensure user has previously called processSpecs() */
  this->ready=true;
  o.targets.rewind();
  return OP_SUCCESS;
} /* End of getTargetSpecCount() */



NpingTarget *NpingTargets::getNextTarget(){
  /* When !ready it means that processSpecs() has not been called yet. This
   * happens when user hits CTRL-C early. */
  if( this->ready == false )
      return NULL;
  /* Did we reach the end of the vector in the last call? */
  if( this->current_target >= this->Targets.size() )
    return NULL;
  nping_print(DBG_4, "Next target returned by getNextTarget(): Targets[%lu/%lu] --> %s \n", this->current_target, (unsigned long) this->Targets.size(), this->Targets.at(this->current_target)->getTargetIPstr() );
  return this->Targets.at( this->current_target++ );
} /* End of getNextTarget() */


int NpingTargets::rewind(){
  current_target=0;
  return OP_SUCCESS;
} /* End of rewind() */

/* Frees all of the Targets. Returns the number of freed targets. The number 
 * return should match value returned by getTargetsFetched().  */
unsigned long int NpingTargets::freeTargets(){
  unsigned long int cnt=0;
  while(!this->Targets.empty()) {
    this->currenths = Targets.back();
    delete currenths;
    Targets.pop_back();
    cnt++;
  }
  return cnt;
} /* End of freeTargets() */


NpingTarget *NpingTargets::findTarget(struct sockaddr_storage *tt){
  size_t i=0;
  struct sockaddr_storage ss;
  size_t ss_len;
  struct sockaddr_in *s_ip4=(struct sockaddr_in *)&ss;
  struct sockaddr_in6 *s_ip6=(struct sockaddr_in6 *)&ss;
  struct sockaddr_in *t_ip4=(struct sockaddr_in *)tt;
  struct sockaddr_in6 *t_ip6=(struct sockaddr_in6 *)tt;

  if (tt==NULL)
    return NULL;

  for(i=0; i<this->Targets.size(); i++){
    this->Targets[i]->getTargetSockAddr(&ss, &ss_len);
    /* Are we are dealing with IPv4 addresses? */
    if( s_ip4->sin_family==AF_INET && t_ip4->sin_family==AF_INET){

        if( !memcmp(&(s_ip4->sin_addr), &(t_ip4->sin_addr), sizeof(struct in_addr)) )
            return this->Targets[i];
    }
    /* Are they IPv6 addresses? */
    else if( s_ip6->sin6_family==AF_INET6 && t_ip6->sin6_family==AF_INET6 ){
        if( !memcmp(&(s_ip6->sin6_addr), &(t_ip6->sin6_addr), sizeof(struct in6_addr)) )
            return this->Targets[i];
    }
    /* Unknown type of address, skipping... */
    else{
        continue;
    }
  }
  return NULL;
} /* End of findTarget() */
