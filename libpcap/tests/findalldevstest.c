#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <pcap.h>

static void ifprint(pcap_if_t *d);
static char *iptos(bpf_u_int32 in);

int main(int argc, char **argv)
{
  pcap_if_t *alldevs;
  pcap_if_t *d;
  char *s;
  bpf_u_int32 net, mask;
  
  char errbuf[PCAP_ERRBUF_SIZE+1];
  if (pcap_findalldevs(&alldevs, errbuf) == -1)
  {
    fprintf(stderr,"Error in pcap_findalldevs: %s\n",errbuf);
    exit(1);
  }
  for(d=alldevs;d;d=d->next)
  {
    ifprint(d);
  }

  if ( (s = pcap_lookupdev(errbuf)) == NULL)
  {
    fprintf(stderr,"Error in pcap_lookupdev: %s\n",errbuf);
  }
  else
  {
    printf("Preferred device name: %s\n",s);
  }

  if (pcap_lookupnet(s, &net, &mask, errbuf) < 0)
  {
    fprintf(stderr,"Error in pcap_lookupnet: %s\n",errbuf);
  }
  else
  {
    printf("Preferred device is on network: %s/%s\n",iptos(net), iptos(mask));
  }
  
  exit(0);
}

static void ifprint(pcap_if_t *d)
{
  pcap_addr_t *a;
#ifdef INET6
  char ntop_buf[INET6_ADDRSTRLEN];
#endif

  printf("%s\n",d->name);
  if (d->description)
    printf("\tDescription: %s\n",d->description);
  printf("\tLoopback: %s\n",(d->flags & PCAP_IF_LOOPBACK)?"yes":"no");

  for(a=d->addresses;a;a=a->next) {
    switch(a->addr->sa_family)
    {
      case AF_INET:
        printf("\tAddress Family: AF_INET\n");
        if (a->addr)
          printf("\t\tAddress: %s\n",
            inet_ntoa(((struct sockaddr_in *)(a->addr))->sin_addr));
        if (a->netmask)
          printf("\t\tNetmask: %s\n",
            inet_ntoa(((struct sockaddr_in *)(a->netmask))->sin_addr));
        if (a->broadaddr)
          printf("\t\tBroadcast Address: %s\n",
            inet_ntoa(((struct sockaddr_in *)(a->broadaddr))->sin_addr));
        if (a->dstaddr)
          printf("\t\tDestination Address: %s\n",
            inet_ntoa(((struct sockaddr_in *)(a->dstaddr))->sin_addr));
        break;
#ifdef INET6
      case AF_INET6:
        printf("\tAddress Family: AF_INET6\n");
        if (a->addr)
          printf("\t\tAddress: %s\n",
            inet_ntop(AF_INET6,
               ((struct sockaddr_in6 *)(a->addr))->sin6_addr.s6_addr,
               ntop_buf, sizeof ntop_buf));
        if (a->netmask)
          printf("\t\tNetmask: %s\n",
            inet_ntop(AF_INET6,
              ((struct sockaddr_in6 *)(a->netmask))->sin6_addr.s6_addr,
               ntop_buf, sizeof ntop_buf));
        if (a->broadaddr)
          printf("\t\tBroadcast Address: %s\n",
            inet_ntop(AF_INET6,
              ((struct sockaddr_in6 *)(a->broadaddr))->sin6_addr.s6_addr,
               ntop_buf, sizeof ntop_buf));
        if (a->dstaddr)
          printf("\t\tDestination Address: %s\n",
            inet_ntop(AF_INET6,
              ((struct sockaddr_in6 *)(a->dstaddr))->sin6_addr.s6_addr,
               ntop_buf, sizeof ntop_buf));
        break;
#endif
      default:
        printf("\tAddress Family: Unknown (%d)\n", a->addr->sa_family);
        break;
    }
  }
  printf("\n");
}

/* From tcptraceroute */
#define IPTOSBUFFERS	12
static char *iptos(bpf_u_int32 in)
{
	static char output[IPTOSBUFFERS][3*4+3+1];
	static short which;
	u_char *p;

	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}
