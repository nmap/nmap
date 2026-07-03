/***************************************************************************
 * nmap_dns.cc -- Handles parallel DNS resolution for target IPs           *
 *                                                                         *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *
 * The Nmap Security Scanner is (C) 1996-2026 Nmap Software LLC ("The Nmap
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

// mass_dns - Parallel Asynchronous DNS Resolution
//
// One of Nmap's features is to perform reverse DNS queries
// on large number of IP addresses. Nmap supports 2 different
// methods of accomplishing this:
//
// System Resolver (specified using --system-dns):
// Performs sequential getnameinfo() calls on all the IPs.
// As reliable as your system resolver, almost guaranteed
// to be portable, but intolerably slow for scans of hundreds
// or more because the result from each query needs to be
// received before the next one can be sent.
//
// Mass/Async DNS (default):
// Attempts to resolve host names in parallel using a set
// of DNS servers. DNS servers are found here:
//
//    --dns-servers <serv1[,serv2],...>   (all platforms - overrides everything else)
//
//    /etc/resolv.conf   (only on unix)
//
//    These registry keys:   (only on windows)
//
//      HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\NameServer
//      HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DhcpNameServer
//      HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\*\NameServer
//      HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\*\DhcpNameServer
//
//
// Also, most systems maintain a file "/etc/hosts" that contains
// IP to hostname mappings. We also try to consult these files. Here
// is where we look for the files:
//
// Unix: /etc/hosts
//
// Windows:
//   for 95/98/Me: WINDOWS_DIR\hosts
//   for NT/2000/XP Pro: WINDOWS_DIR\system32\drivers\etc\hosts
//   for XP Home: WINDOWS_DIR\system32\drivers\etc\hosts
//     --see http://accs-net.com/hosts/how_to_use_hosts.html
//
//
// Created by Doug Hoyte <doug at hcsw.org> http://www.hcsw.org
// DNS Caching and aging added by Eddie Bell ejlbell@gmail.com 2007
// IPv6 and improved DNS cache by Gioacchino Mazzurco <gmazzurco89@gmail.com> 2015


// TODO:
//
// * Tune performance parameters
//
// * Figure out best way to estimate completion time
//   and display it in a ScanProgressMeter
#ifdef WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#endif

#include <sstream>
#include <fstream>
#include <algorithm>
#include <map>
#include "massdns.h"
#include "netutil.h"
#include <limits.h>
#include <assert.h>


// From nmap.h
#ifndef MIN_RTT_TIMEOUT
#define MIN_RTT_TIMEOUT 100
#endif


//------------------- Performance Parameters ---------------------

// Algorithm:
//
// A batch of num_requests requests is passed to nmap_mass_dns():
//   void nmap_mass_dns(DNS::Request requests[], int num_requests);
//
// mass_dns sends out CAPACITY_MIN of these requests to the DNS
// servers detected, alternating in sequence.

// When a request is fulfilled (either a resolved domain, NXDomain,
// or confirmed ServFail) CAPACITY_UP_STEP is added to the current
// capacity of the server the request was found by.

// When a request times out and retries on the same server,
// the server's capacity is scaled by CAPACITY_MINOR_DOWN_STEP.

// When a request times out and moves to the next server in
// sequence, the server's capacity is scaled by CAPACITY_MAJOR_DOWN_STEP.

// mass_dns tries to maintain the current number of "outstanding
// queries" on each server to that of its current capacity. The
// packet is dropped if it cycles through all specified DNS
// servers.


// Since multiple DNS servers can be specified, different sequences
// of timers are maintained. These are the various retransmission
// intervals for each server before we move on to the next DNS server:

// In milliseconds
// Each row MUST be terminated with -1
#define MAX_DNS_TRIES 3
#define MIN_DNS_TIMEOUT (MIN_RTT_TIMEOUT * 5)
static int default_read_timeouts[][MAX_DNS_TRIES + 1] = {
  { 2 * MIN_DNS_TIMEOUT, 3 * MIN_DNS_TIMEOUT, 4 * MIN_DNS_TIMEOUT, -1 }, // 1 server
  { 2 * MIN_DNS_TIMEOUT, 2 * MIN_DNS_TIMEOUT,                   -1, -1 }, // 2 servers
  {     MIN_DNS_TIMEOUT, 2 * MIN_DNS_TIMEOUT,                   -1, -1 }, // 3+ servers
};

#define CAPACITY_MIN 10
#define CAPACITY_MAX 100
#define CAPACITY_UP_STEP 2
#define CAPACITY_MINOR_DOWN_SCALE 0.7
#define CAPACITY_MAJOR_DOWN_SCALE 0.4

// Each request will try to resolve on at most this many servers:
#define SERVERS_TO_TRY 3


//------------------- Other Parameters ---------------------

// How often to display a short debugging summary if debugging is
// specified. Lower numbers means it's displayed more often.
#define SUMMARY_DELAY 50

// Minimum debugging level to display packet trace
#define TRACE_DEBUG_LEVEL 4

// The amount of time we wait for nsock_write() to complete before
// retransmission. This should almost never happen. (in milliseconds)
#define WRITE_TIMEOUT 100

//------------------- Internal Structures ---------------------

struct request;

struct dns_server {
  enum status_t {
    DISCONNECTED,
    CONNECTING,
    CONNECTED
  };
  DNS::ResolverImpl *impl;
  std::string hostname;
  sockaddr_storage addr;
  size_t addr_len;
  nsock_iod nsd;
  status_t status;
  int reqs_on_wire;
  int capacity;
  int ssthresh;
  int write_busy;
  std::list<request *> to_process;
  std::list<request *> in_process;
  struct timeval last_increase;
  dns_server(DNS::ResolverImpl *i) : impl(i), hostname(), addr_len(0), nsd(NULL), status(DISCONNECTED), reqs_on_wire(0),
    capacity(CAPACITY_MIN), ssthresh((CAPACITY_MAX + CAPACITY_MIN)/2), write_busy(0), to_process(), in_process()
  {
    memset(&addr, 0, sizeof(addr));
    memset(&last_increase, 0, sizeof(last_increase));
  }
};

struct request {
  enum status_t {
    READY,
    WRITE_PENDING,
    DONE
  };
  DNS::ResolverImpl *impl;
  DNS::Request *targ;
  struct timeval sent;
  int tries;
  int servers_tried;
  dns_server *first_server;
  dns_server *curr_server;
  u16 id;
  status_t status;
  bool alt_req;
  request(DNS::ResolverImpl *i)
    : impl(i), targ(NULL), tries(0), servers_tried(0), first_server(NULL),
    curr_server(NULL), id(0), status(READY), alt_req(false)
  {
    memset(&sent, 0, sizeof(sent));
  }
  ~request() {
    if (alt_req && targ) {
      delete targ;
      targ = NULL;
    }
  }
};

/*keeps record of a request going through a particular DNS server
helps in attaining faster lookup based on ID */
struct info{
  dns_server *server;
  request *tpreq;
};

class HostElem
{
public:
  HostElem(const std::string & name_, const sockaddr_storage & ip) :
    name(name_), addr(ip), cache_hits(0) {}
  ~HostElem() {}

  /* Ages entries and return true with a cache hit of 0 (the least used) */
  static bool isTimeToClean(HostElem he)
  {
    if(he.cache_hits)
    {
      he.cache_hits >>= 1;
      return false;
    }

    return true;
  }

  const std::string name;
  const sockaddr_storage addr;
  u8 cache_hits;
};

class HostCacheLine : public std::list<HostElem>{};

class HostCache
{
public:
  //            TODO: avoid hardcode this constant
  HostCache() : lines_count(256), hash_mask(lines_count-1),
    hosts_storage(new HostCacheLine[lines_count]), elements_count(0)
  {}
  ~HostCache()
  {
    delete[] hosts_storage;
  }

  u32 hash(const sockaddr_storage &ip) const
  {
    u32 ret = 0;

    switch (ip.ss_family)
    {
      case AF_INET:
      {
        u8 * ipv4 = (u8 *) &((const struct sockaddr_in *) &ip)->sin_addr;
        // Shuffle bytes a little so we avoid awful performances in commons
        // usages patterns like 10.0.1-255.1 and lines_count 256
        ret = ipv4[0] + (ipv4[1]<<3) + (ipv4[2]<<5) + (ipv4[3]<<7);
        break;
      }
      case AF_INET6:
      {
        const struct sockaddr_in6 * sa6 = (const struct sockaddr_in6 *) &ip;
        u32 * ipv6 = (u32 *) sa6->sin6_addr.s6_addr;
        ret = ipv6[0] + ipv6[1] + ipv6[2] + ipv6[3];
        break;
      }
    }

    return ret & hash_mask;
  }

  /* Add to the dns cache. If there are too many entries
   * we age and remove the least frequently used ones to
   * make more space. */
  bool add( const sockaddr_storage & ip, const std::string & hname)
  {
    std::string discard;
    if(lookup(ip, discard)) return false;

    if(elements_count >= lines_count) prune();

    HostElem he(hname, ip);
    hosts_storage[hash(ip)].push_back(he);
    ++elements_count;
    return true;
  }

  u32 prune()
  {
    u32 original_count = elements_count;
    for(u32 i = 0; i < lines_count; ++i)
    {
      std::list<HostElem>::iterator it = find_if(hosts_storage[i].begin(),
                                                 hosts_storage[i].end(),
                                                 HostElem::isTimeToClean);
      while ( it != hosts_storage[i].end() )
      {
        it = hosts_storage[i].erase(it);
        assert(elements_count > 0);
        --elements_count;
      }
    }

    return original_count - elements_count;
  }

  /* Search for a hostname in the cache and increment
   * its cache hit counter if found */
  bool lookup(const sockaddr_storage & ip, std::string & name)
  {
    std::list<HostElem>::iterator hostI;
    u32 ip_hash = hash(ip);
    for( hostI = hosts_storage[ip_hash].begin();
         hostI != hosts_storage[ip_hash].end();
         ++hostI)
    {
      if (sockaddr_storage_equal(&hostI->addr, &ip))
      {
        if(hostI->cache_hits < UCHAR_MAX)
          hostI->cache_hits++;
        name = hostI->name;
        return true;
      }
    }
    return false;
  }

protected:
  const u32 lines_count;
  const u32 hash_mask;
  HostCacheLine * const hosts_storage;
  u32 elements_count;
};

static void null_status_cb(const DNS::Stats *stat) { (void) stat; }
static void null_log_func(int lvl, const char *s, ...) { (void) lvl; (void) s; }

namespace DNS {
class ResolverImpl
{
public:
  ResolverImpl(Resolver *r)
    : resolver(r), af(AF_INET), spoof(false), device(NULL), sslen1(0),
    sslen2(0), ipopts(NULL), ipoptslen(0), total_reqs(0), dnspool(NULL),
    proxy_chain(NULL), read_timeouts(NULL), status_cb(null_status_cb),
    log_func(null_log_func)
  {
    memset(&src1, 0, sizeof(src1));
    memset(&src2, 0, sizeof(src2));

    // If necessary, read /etc/hosts and put entries into the hashtable
    ResolverImpl::etchosts_init();
    init_host_cache();
  }
  /* Forward lookup table from /etc/hosts */
  typedef std::pair<std::string, RECORD_TYPE> NameRecord;
  static std::map<NameRecord, sockaddr_storage> etchosts;
  static std::list<std::pair<std::string, sockaddr_storage> > ptr_etchosts;
  static void etchosts_init();
  static void parse_etchosts(const char *fname);

  void reset() {
    stat.reset();
    stat.servers = servs.size();
    init_host_cache();
    new_reqs.clear();
    deferred_reqs.clear();
    records.clear();
    total_reqs = 0;
  }
  void add_dns_server(const std::string &hostname);
  void add_dns_server(
      const struct sockaddr_storage *addr, size_t addr_len, const char *hostname);
  void add_request(Request &reqt);
  bool resolve_nsock();
  bool resolve_system();

  /* Nsock event handlers */
  static void read_evt_handler(nsock_pool nsp, nsock_event evt, void *ctx) {
    dns_server *srv = static_cast<dns_server *>(ctx);
    srv->impl->handle_read(nsp, evt, srv);
  }
  static void write_evt_handler(nsock_pool nsp, nsock_event evt, void *ctx) {
    request *req = static_cast<request *>(ctx);
    req->impl->handle_write(nsp, evt, req);
  }
  static void connect_evt_handler(nsock_pool nsp, nsock_event evt, void *ctx) {
    dns_server *srv = static_cast<dns_server *>(ctx);
    srv->impl->handle_connect(nsp, evt, srv);
  }

private:
  Resolver *resolver;
  int af;
  bool spoof;
  const char *device;
  struct sockaddr_storage src1, src2;
  size_t sslen1, sslen2;
  const u8 *ipopts;
  size_t ipoptslen;
  std::list<dns_server> servs;
  std::list<request *> new_reqs;
  std::list<request *> deferred_reqs;
  std::map<u16, info> records;
  int total_reqs;
  nsock_pool dnspool;
  nsock_proxychain proxy_chain;

  /* The DNS cache, not just for entries from /etc/hosts. */
  HostCache host_cache;

  Stats stat;
  int *read_timeouts;
  void (*status_cb)(const Stats *);
  void (*log_func)(int lvl, const char *, ...);

  void init_host_cache();
  void platform_get_servers();
  void connect_dns_servers();
  void close_dns_servers();
  void check_capacities(dns_server *tpserv);
  void do_possible_writes();
  bool server_send(dns_server &serv);
  void put_dns_packet_on_wire(request *req);
  int deal_with_timedout_reads(bool adjust_timing);
  void process_request(int action, info &reqinfo);
  bool process_result(const std::string &name, const Record *rr,
      info &reqinfo, bool already_matched);
  bool system_resolve(DNS::Request &reqt);
  void output_summary(const Stats &stat);

  void handle_read(nsock_pool nsp, nsock_event evt, dns_server *srv);
  void handle_write(nsock_pool nsp, nsock_event evt, request *req);
  void handle_connect(nsock_pool nsp, nsock_event evt, dns_server *srv);

  friend class Resolver;
};
std::map<ResolverImpl::NameRecord, sockaddr_storage> ResolverImpl::etchosts;
std::list<std::pair<std::string, sockaddr_storage> > ResolverImpl::ptr_etchosts;
}

DNS::Resolver::Resolver()
{
  impl = new DNS::ResolverImpl(this);
}

bool DNS::Resolver::isMassDnsOK(const char **err) const
{
  if (impl->servs.empty()) {
    *err = "Unable to determine any DNS servers. ";
    return false;
  }
  return true;
}

bool DNS::Resolver::isSystemDnsOK(const char **err) const
{
  return true;
}

// Actual main loop
void DNS::Resolver::Init(DNS::Request *requests, int num_requests)
{
  if (impl->servs.empty())
    setServers(NULL);
  impl->reset();
  // Set up the request structure
  for (int i=0; i < num_requests; i++)
  {
    impl->add_request(requests[i]);
  }
}

void DNS::Resolver::Resolve(bool system)
{
  assert(impl != NULL);
  if (system)
    impl->resolve_system();
  else
    impl->resolve_nsock();
}


void DNS::Resolver::setAF(int af)
{
  impl->af = af;
}

void DNS::Resolver::setStatusCallback(void (*callback)(const DNS::Stats *))
{
  impl->status_cb = callback;
}

void DNS::Resolver::setLogFunc(void (*log_func)(int lvl, const char *, ...))
{
  impl->log_func = log_func;
}

void DNS::Resolver::setSource(const char *device, const struct sockaddr_storage *src, size_t srclen, bool spoof)
{
  impl->device = device;
  if (src) {
    impl->src1 = *src;
    impl->sslen1 = srclen;
    // Source addr can be set by -e, so unless user specifically asked to
    // spoof, also grab the source for the other address family.
    if (!spoof && (device && *device)) {
      int af = src->ss_family == AF_INET ? AF_INET6 : AF_INET;
      if (-1 != devname2ipaddr(device, af, &impl->src2)) {
        impl->sslen2 = sizeof(struct sockaddr_storage);
      }
    }
  }
}

void DNS::Resolver::setIpOptions(const u8 *opts, size_t optslen)
{
  impl->ipopts = opts;
  impl->ipoptslen = optslen;
}

void DNS::Resolver::setProxyChain(nsock_proxychain proxy_chain)
{
  impl->proxy_chain = proxy_chain;
}

/* If the --dns-servers option was given, use the listed servers; otherwise get
 * the list from resolv.conf or the Windows registry.
 */
// Adds DNS servers to the dns_server list. They can be separated by
// commas or spaces - NOTE this doesn't actually do any connecting!
void DNS::Resolver::setServers(const char *servers)
{
  if (servers) {
    const char *start = servers;

    start += strspn(start, " ,");
    while (*start) {
      start += strspn(start, " ,");
      size_t len = strcspn(start, " ,");
      std::string hostname(start, len);
      impl->add_dns_server(hostname);
      start += len;
      start += strspn(start, " ,");
    }
  }
  else {
    impl->platform_get_servers();
  }
}

// Returns a list of known DNS servers
std::list<std::string> DNS::Resolver::getServers() const
{
  std::list<dns_server>::iterator servI;
  std::list<std::string> serverList;
  for(servI = impl->servs.begin(); servI != impl->servs.end(); servI++) {
    serverList.push_back(inet_ntop_ez(&servI->addr, servI->addr_len));
  }
  return serverList;
}

DNS::Stats DNS::Resolver::getStats() const
{
  return impl->stat;
}

//------------------- Globals ---------------------

u16 DNS::Factory::progressiveId = get_random_u16();

//------------------- Prototypes and macros ---------------------

#define ACTION_FINISHED 0
#define ACTION_SYSTEM_RESOLVE 1
#define ACTION_TIMEOUT 2

#define DNS_CHECK_ACCUMLATE(accumulator, tmp, exp) \
  do { tmp = exp; if(tmp < 1) return 0 ; accumulator += tmp;} while(0)

#define DNS_CHECK_UPPER_BOUND(accumulator, max)\
  do { if(accumulator > max) return 0; } while(0)

#define DNS_HAS_FLAG(v,flag) ((v&flag)==flag)

#define DNS_HAS_ERR(v, err) ((v&DNS::ERR_ALL)==err)

//------------------- Misc code ---------------------

void DNS::ResolverImpl::add_request(DNS::Request &reqt)
{
  ++stat.names;
  // See if it's cached
  std::map<NameRecord, sockaddr_storage>::const_iterator it;
  switch (reqt.type) {
    case DNS::PTR:
      assert(reqt.ssv.size() > 0);
      if (host_cache.lookup(reqt.ssv.front(), reqt.name)) {
        return;
      }
      break;
    case DNS::ANY:
      it = etchosts.find(NameRecord(reqt.name, DNS::A));
      if (it != etchosts.end()) {
        reqt.ssv.push_back(it->second);
      }
      it = etchosts.find(NameRecord(reqt.name, DNS::AAAA));
      if (it != etchosts.end()) {
        reqt.ssv.push_back(it->second);
      }
      if (reqt.ssv.size() > 0) {
        return;
      }
      break;
    case DNS::A:
    case DNS::AAAA:
      it = etchosts.find(NameRecord(reqt.name, reqt.type));
      if (it != etchosts.end()) {
        reqt.ssv.push_back(it->second);
        return;
      }
      break;
    case DNS::NONE:
      // This is okay, just don't make a request.
      --stat.names;
      return;
      break;
    default:
      log_func(1, "%s: Unknown DNS request type %s\n", __func__, reqt.repr());
      return;
      break;
  }

  request *tpreq = new request(this);
  tpreq->targ = &reqt;
  tpreq->tries = 0;
  tpreq->servers_tried = 0;
  tpreq->alt_req = false;
  tpreq->id = DNS::Factory::progressiveId++;

  new_reqs.push_back(tpreq);
  stat.actual++;

  /* Because ANY queries have been used in DDoS attacks, they are heavily
   * restricted and can't be relied on. Instead, we interpret them as a request
   * for an A record, and we also create a duplicate request for a AAAA record.
   */
  if (reqt.type == DNS::ANY) {
    DNS::Request *req_aaaa = new DNS::Request;
    req_aaaa->type = DNS::AAAA;
    req_aaaa->name = reqt.name;
    req_aaaa->userdata = &reqt;
    request *tpreq_alt = new request(this);
    *tpreq_alt = *tpreq;
    tpreq_alt->targ = req_aaaa;
    tpreq_alt->alt_req = true;
    tpreq_alt->id = DNS::Factory::progressiveId++;
    new_reqs.push_back(tpreq_alt);
    stat.actual++;
  }
}

bool DNS::ResolverImpl::resolve_nsock()
{
  total_reqs = new_reqs.size();
  assert(total_reqs == stat.actual);
  if (total_reqs <= 0) {
    return true;
  }
  if ((dnspool = nsock_pool_new(this)) == NULL) {
    log_func(0, "Unable to create nsock pool in %s()", __func__);
    return false;
  }

  if (device)
    nsock_pool_set_device(dnspool, device);

  if (proxy_chain)
    nsock_pool_set_proxychain(dnspool, proxy_chain);

  connect_dns_servers();

  int read_timeout_index = MIN(sizeof(default_read_timeouts)/sizeof(default_read_timeouts[0]), servs.size()) - 1;
  read_timeouts = default_read_timeouts[read_timeout_index];

  int timeout = 0;
  int since_last = 0;
  nsock_loopstatus status = nsock_loop(dnspool, 0);
  while (status == NSOCK_LOOP_TIMEOUT && total_reqs > 0) {
    since_last += timeout;
    if (since_last > MIN_DNS_TIMEOUT) {
      since_last = 0;
      timeout = deal_with_timedout_reads(true);
    }
    else {
      timeout = deal_with_timedout_reads(false);
    }

    do_possible_writes();
    output_summary(stat);

    if (total_reqs <= 0) break;

    nsock_loop(dnspool, timeout);
  }
  assert(new_reqs.empty());

  close_dns_servers();

  nsock_pool_delete(dnspool);
  dnspool = NULL;

  if (deferred_reqs.size()) {
    log_func(1, "Performing system-dns for %lu domain names that were deferred\n", deferred_reqs.size());

    std::list<request *>::iterator reqI;
    for(reqI = deferred_reqs.begin(); reqI != deferred_reqs.end(); reqI++) {

      status_cb(&stat);
      output_summary(stat);

      request *tpreq = *reqI;
      if (system_resolve(*tpreq->targ)) {
        stat.ok++;
      }
      else {
        stat.nx++;
      }

      delete tpreq;
    }
    output_summary(stat);
  }

  deferred_reqs.clear();
  return true;
}

bool DNS::ResolverImpl::resolve_system()
{
  total_reqs = new_reqs.size();
  assert(total_reqs == stat.actual);
  while (total_reqs > 0) {
    request *tpreq = new_reqs.front();
    new_reqs.pop_front();
    total_reqs--;

    // System resolver can handle DNS::ANY as AF_UNSPEC, so no need for
    // alt_req's AAAA request.
    if (tpreq->alt_req) {
      delete tpreq;
      stat.actual--;
      continue;
    }
    stat.system++;

    status_cb(&stat);

    if (system_resolve(*tpreq->targ)) {
      stat.ok++;
    }
    else {
      stat.nx++;
    }
    delete tpreq;
  }
  assert(new_reqs.empty());
  return true;
}

void DNS::ResolverImpl::output_summary(const DNS::Stats &stat) {
  static int prev = 0;
  int tp = stat.ok + stat.nx + stat.sf + stat.dropped;
  if (prev > tp)
    prev = 0;

  if (tp - SUMMARY_DELAY >= prev || tp == stat.actual) {
    log_func(1, "mass_dns: %.2fs %d/%d [#: %lu, OK: %d, NX: %d, DR: %d, SF: %d, TR: %d, SY: %d]\n",
                    tp, stat.actual,
                    (unsigned long) servs.size(), stat.ok, stat.nx,
                    stat.dropped, stat.sf, stat.trans, stat.system);
    prev = tp;
  }
}

void DNS::ResolverImpl::check_capacities(dns_server *tpserv) {
  if (tpserv->capacity < CAPACITY_MIN) tpserv->capacity = CAPACITY_MIN;
  if (tpserv->capacity > CAPACITY_MAX) tpserv->capacity = CAPACITY_MAX;
  log_func(TRACE_DEBUG_LEVEL, "CAPACITY <%s> = %d\n", tpserv->hostname.c_str(), tpserv->capacity);
}

// Closes all nsis created in connect_dns_servers()
void DNS::ResolverImpl::close_dns_servers() {
  std::list<dns_server>::iterator serverI;

  for(serverI = servs.begin(); serverI != servs.end(); serverI++) {
    if (serverI->status != dns_server::DISCONNECTED) {
      nsock_iod_delete(serverI->nsd, NSOCK_PENDING_SILENT);
      serverI->status = dns_server::DISCONNECTED;
      serverI->to_process.clear();
      serverI->in_process.clear();
    }
  }
  nsock_loop_quit(dnspool);
}

// Attempts to send a request for this server
bool DNS::ResolverImpl::server_send(dns_server &serv) {
  if (serv.write_busy || serv.reqs_on_wire >= serv.capacity) {
    return false;
  }

  request *tpreq = NULL;
  if (!new_reqs.empty()) {
    tpreq = new_reqs.front();
    assert(tpreq != NULL);
    assert(tpreq->targ != NULL);
    tpreq->first_server = tpreq->curr_server = &serv;
    new_reqs.pop_front();
  } else if (!serv.to_process.empty()) {
    tpreq = serv.to_process.front();
    serv.to_process.pop_front();
  } else {
    return false;
  }

  assert(tpreq != NULL);
  assert(tpreq->targ != NULL);
  assert(tpreq->curr_server == &serv);
  log_func(TRACE_DEBUG_LEVEL,
    "mass_dns: TRANSMITTING for <%s> (server <%s>)\n", tpreq->targ->repr(), serv.hostname.c_str());
  stat.trans++;
  serv.write_busy = 1;
  put_dns_packet_on_wire(tpreq);
  serv.write_busy = 0;
  return true;
}

// Puts as many packets on the line as capacity will allow
void DNS::ResolverImpl::do_possible_writes() {
  std::list<dns_server>::iterator servI;
  bool all_servs_disconnected = true;

  for(servI = servs.begin(); servI != servs.end(); servI++) {
    switch (servI->status) {
      case dns_server::CONNECTED:
        all_servs_disconnected = false;
        break;
      case dns_server::CONNECTING:
        all_servs_disconnected = false;
      case dns_server::DISCONNECTED:
        continue;
        break;
    }
    for (int i=servI->capacity - servI->reqs_on_wire; i > 0; i--) {
      if (!server_send(*servI)) {
        break;
      }
    }
  }
  if (all_servs_disconnected) {
    nsock_loop_quit(dnspool);
  }
}

// nsock write handler
void DNS::ResolverImpl::handle_write(nsock_pool nsp, nsock_event evt, request *req) {
  assert(nse_type(evt) == NSE_TYPE_WRITE);

  if (nse_status(evt) == NSE_STATUS_SUCCESS) {
    server_send(*req->curr_server);
  }
  else {
      log_func(1, "mass_dns: WRITE error: %s", nse_status2str(nse_status(evt)));
    // We don't delete from records in case a response to an earlier probe comes in.
    req->curr_server->in_process.remove(req);
    req->curr_server->to_process.push_front(req);
  }

  if (req->status == request::DONE) {
    delete req;
  }
  else {
    assert(req->status == request::WRITE_PENDING);
    req->status = request::READY;
  }
}

static DNS::RECORD_TYPE wire_type(DNS::RECORD_TYPE t) {
  if (t == DNS::ANY) {
    return DNS::A;
  }
  return t;
}

// Takes a DNS request structure and actually puts it on the wire
// (calls nsock_write()). Does various other tasks like recording
// the time for the timeout.
void DNS::ResolverImpl::put_dns_packet_on_wire(request *req) {
  static const size_t maxlen = 512;
  u8 packet[maxlen];
  size_t plen=0;
  dns_server *srv = req->curr_server;
  info record;

  srv->reqs_on_wire++;
  DNS::Request &reqt = *req->targ;

  switch(reqt.type) {
    case DNS::ANY:
    case DNS::A:
    case DNS::AAAA:
      plen = DNS::Factory::buildSimpleRequest(req->id, reqt.name, wire_type(reqt.type), packet, maxlen);
      break;
    case DNS::PTR:
      assert(reqt.ssv.size() > 0);
      plen = DNS::Factory::buildReverseRequest(req->id, reqt.ssv.front(), packet, maxlen);
      break;
    default:
      // Unhandled type. Should have been dealt with earlier.
      assert(false);
      break;
  }

  srv->in_process.push_front(req);
  record.tpreq = req;
  record.server = srv;
  records[req->id] = record;
  memcpy(&req->sent, nsock_gettimeofday(), sizeof(struct timeval));

  req->status = request::WRITE_PENDING;
  nsock_write(dnspool, srv->nsd, &DNS::ResolverImpl::write_evt_handler, WRITE_TIMEOUT, req,
      reinterpret_cast<const char *>(packet), plen);
}

// Processes DNS packets that have timed out
// Returns time until next read timeout
int DNS::ResolverImpl::deal_with_timedout_reads(bool adjust_timing) {
  std::list<dns_server>::iterator servI;
  std::list<dns_server>::iterator servItemp;
  std::list<request *>::iterator reqI;
  std::list<request *>::iterator nextI;
  std::map<u16, info>::iterator infoI;
  request *tpreq;
  struct timeval now;
  int tp, min_timeout = INT_MAX;

  memcpy(&now, nsock_gettimeofday(), sizeof(struct timeval));

  status_cb(&stat);

  for(servI = servs.begin(); servI != servs.end(); servI++) {
    nextI = servI->in_process.begin();
    if (nextI == servI->in_process.end()) continue;

    struct timeval earliest_sent = now;
    bool adjusted = !adjust_timing;
    bool may_increase = adjust_timing;
    do {
      reqI = nextI++;
      tpreq = *reqI;

      int to = read_timeouts[tpreq->tries];

      int elapsed = TIMEVAL_MSEC_SUBTRACT(now, tpreq->sent);
      tp = to - elapsed;
      if (tp > 0) {
        // only bother checking this if we might increase the capacity
        if (may_increase && TIMEVAL_BEFORE(tpreq->sent, earliest_sent)) {
          earliest_sent = tpreq->sent;
        }
        if (tp < min_timeout) min_timeout = tp;
      }
      else {
        may_increase = false;
        tpreq->tries++;
        if (tpreq->tries > MAX_DNS_TRIES)
          tpreq->tries = MAX_DNS_TRIES;
        servI->in_process.erase(reqI);
        // We don't erase timed-out probes from records in case a late response comes in.
        servI->reqs_on_wire--;

        // If we've tried this server enough times, move to the next one
        if (read_timeouts[tpreq->tries] == -1) {
          if (!adjusted && tpreq->servers_tried == 0) {
            servI->ssthresh = MIN(servI->ssthresh, servI->capacity);
            servI->capacity = (int) (servI->capacity * CAPACITY_MAJOR_DOWN_SCALE);
            check_capacities(&*servI);
            adjusted = true;
          }

          servItemp = servI;
          servItemp++;

          if (servItemp == servs.end()) servItemp = servs.begin();

          tpreq->curr_server = &*servItemp;
          tpreq->tries = 0;
          tpreq->servers_tried++;

          if (tpreq->curr_server == tpreq->first_server || tpreq->servers_tried == SERVERS_TO_TRY) {
            // Either give up on the IP
            // or, for maximum reliability, put the server back into processing
            // Note it's possible that this will never terminate.
            // FIXME: Find a good compromise

            // **** We've already tried all servers... give up
            log_func(TRACE_DEBUG_LEVEL, "mass_dns: *DR*OPPING <%s>\n", tpreq->targ->repr());

            output_summary(stat);
            stat.dropped++;
            total_reqs--;
            records.erase(tpreq->id);
            if (tpreq->status != request::WRITE_PENDING) {
              delete tpreq;
            }
            else {
              tpreq->status = request::DONE;
            }
            tpreq = NULL;

            // **** OR We start at the back of this server's queue
            //servItemp->to_process.push_back(tpreq);
          } else {
            info record;
            record.tpreq = tpreq;
            record.server = &*servItemp;
            records[tpreq->id] = record;
            servItemp->to_process.push_back(tpreq);
          }
        } else {
          if (!adjusted && tpreq->servers_tried == 0 && tpreq->tries <= 1) {
            servI->ssthresh = MIN(servI->ssthresh, servI->capacity);
            servI->capacity = (int) (servI->capacity * CAPACITY_MINOR_DOWN_SCALE);
            check_capacities(&*servI);
            adjusted = true;
          }
          servI->to_process.push_back(tpreq);
        }

      }

    } while (nextI != servI->in_process.end());

    if (may_increase && TIMEVAL_MSEC_SUBTRACT(earliest_sent, servI->last_increase) > (MIN_DNS_TIMEOUT) && servI->reqs_on_wire > servI->capacity - 2*CAPACITY_UP_STEP) {
      servI->capacity += CAPACITY_UP_STEP;
      check_capacities(&*servI);
      servI->last_increase = now;
    }
  }

  if (min_timeout > 500) return 500;
  else return min_timeout;

}


void DNS::ResolverImpl::process_request(int action, info &reqinfo) {
  request *tpreq = reqinfo.tpreq;
  dns_server *server = reqinfo.server;

  switch (action) {
    case ACTION_SYSTEM_RESOLVE:
    case ACTION_FINISHED:
      if (server->reqs_on_wire == server->capacity && server->capacity < server->ssthresh) {
        server->capacity += CAPACITY_UP_STEP;
        check_capacities(server);
      }
      records.erase(tpreq->id);
      server->in_process.remove(tpreq);
      server->to_process.remove(tpreq);
      server->reqs_on_wire--;
      total_reqs--;
      if (action == ACTION_SYSTEM_RESOLVE) {
        // System resolver can handle DNS::ANY as AF_UNSPEC, so no need for
        // alt_req's AAAA request.
        if (!tpreq->alt_req) {
          deferred_reqs.push_back(tpreq);
          stat.system++;
          break;
        }
        stat.actual--;
      }
      if (tpreq->status != request::WRITE_PENDING) {
        delete tpreq;
      }
      else {
        tpreq->status = request::DONE;
      }
      tpreq = NULL;

      break;
    case ACTION_TIMEOUT:
      tpreq->tries = MAX_DNS_TRIES;
      deal_with_timedout_reads(false);
      break;
    default:
      assert(false);
      break;
  }
}

// After processing a DNS response, we search through the IPs we're
// looking for and update their results as necessary.
bool DNS::ResolverImpl::process_result(const std::string &name, const DNS::Record *rr,
    info &reqinfo, bool already_matched)
{
  DNS::Request *reqt = reqinfo.tpreq->targ;
  std::vector<struct sockaddr_storage> *ssv;
  if (reqinfo.tpreq->alt_req) {
    DNS::Request *alt_req = (DNS::Request *) reqinfo.tpreq->targ->userdata;
    ssv = &alt_req->ssv;
  }
  else {
    ssv = &reqt->ssv;
  }
  const struct sockaddr_storage *ss = NULL;
  const DNS::A_Record *a_rec = NULL;
  sockaddr_storage ip;
  ip.ss_family = AF_UNSPEC;
  switch (reqt->type) {
    case DNS::A:
    case DNS::AAAA:
    case DNS::ANY:
      if (!already_matched && name != reqt->name) {
        return false;
      }
      a_rec = static_cast<const DNS::A_Record *>(rr);
      ssv->push_back(a_rec->value);
      log_func(TRACE_DEBUG_LEVEL, "mass_dns: OK MATCHED <%s> to <%s>\n",
          reqt->name.c_str(),
          inet_ntop_ez(&a_rec->value, sizeof(struct sockaddr_storage)));
      break;
    case DNS::PTR:
      ss = &reqt->ssv.front();
      if (!already_matched) {
        if (!DNS::Factory::ptrToIp(name, ip) ||
            !sockaddr_storage_equal(&ip, ss)) {
          return false;
        }
      }
      reqt->name = static_cast<const DNS::PTR_Record *>(rr)->value;
      host_cache.add(*ss, reqt->name);
      log_func(TRACE_DEBUG_LEVEL, "mass_dns: OK MATCHED <%s> to <%s>\n",
          inet_ntop_ez(ss, sizeof(struct sockaddr_storage)),
          reqt->name.c_str());
      break;
    default:
      assert(false);
      break;
  }

  return true;
}

// Nsock read handler. One nsock read for each DNS server exists at each
// time. This function uses various helper functions as defined above.
void DNS::ResolverImpl::handle_read(nsock_pool nsp, nsock_event evt, dns_server *srv) {
  const u8 *buf;
  int buflen;
  assert(nse_type(evt) == NSE_TYPE_READ);

  // Only initiate another read if this one succeeded or timed out.
  if(nse_status(evt) == NSE_STATUS_SUCCESS ||
      nse_status(evt) == NSE_STATUS_TIMEOUT ) {
    if (total_reqs >= 1)
      nsock_read(nsp, nse_iod(evt), &DNS::ResolverImpl::read_evt_handler, -1, (void *)srv);
  }

  if (nse_status(evt) != NSE_STATUS_SUCCESS) {
    log_func(1, "mass_dns: warning: got a %s:%s in %s()\n",
        nse_type2str(nse_type(evt)),
        nse_status2str(nse_status(evt)), __func__);
    // We're not trying another read here, so disconnect the server.
    srv->status = dns_server::DISCONNECTED;
    nsock_iod_delete(srv->nsd, NSOCK_PENDING_SILENT);
    // Put all in-process and to-process requests back in the queue.
    new_reqs.splice(new_reqs.end(), srv->in_process);
    new_reqs.splice(new_reqs.end(), srv->to_process);
    return;
  }

  buf = (unsigned char *) nse_readbuf(evt, &buflen);

  DNS::Packet p;
  size_t readed_bytes = p.parseFromBuffer(buf, buflen);
  if(readed_bytes < DNS::DATA) return;

  // We should have 1+ queries:
  u16 &f = p.flags;
  if(p.queries.empty() || !DNS_HAS_FLAG(f, DNS::RESPONSE) ||
     !DNS_HAS_FLAG(f, DNS::OP_STANDARD_QUERY) ||
     (f & DNS::ZERO) || DNS_HAS_ERR(f, DNS::ERR_FORMAT) ||
     DNS_HAS_ERR(f, DNS::ERR_NOT_IMPLEMENTED) || DNS_HAS_ERR(f, DNS::ERR_REFUSED))
    return;

  // Check for matching request
  std::map<u16, info>::iterator infoI = records.find(p.id);
  if (infoI == records.end()) {
    return;
  }
  info &reqinfo = infoI->second;
  assert(p.id == reqinfo.tpreq->id);
  DNS::Request *reqt = reqinfo.tpreq->targ;
  assert(reqt != NULL);
  bool processing_successful = false;

  if (DNS_HAS_ERR(f, DNS::ERR_NAME) || p.answers.empty())
  {
    // Check if this was a nonstandard name;
    if (reqt->type != DNS::PTR) {
      for (std::string::const_iterator it=reqt->name.begin(); it < reqt->name.end(); it++) {
        if (*it < '0') { // signed char comparison; non-ascii are < 0
          // system resolver might be able to do better with things like AI_IDN
          process_request(ACTION_SYSTEM_RESOLVE, reqinfo);
          processing_successful = true;
          break;
        }
      }
      if (!processing_successful && reqt->name.find('.') == std::string::npos) {
        // Names without a dot: system resolver may do better.
          process_request(ACTION_SYSTEM_RESOLVE, reqinfo);
          processing_successful = true;
      }
    }

    if (!processing_successful) {
      process_request(ACTION_FINISHED, reqinfo);
      log_func(TRACE_DEBUG_LEVEL, "mass_dns: NXDOMAIN <id = %d>\n", p.id);
      stat.nx++;
    }

    output_summary(stat);
    return;
  }

  if (DNS_HAS_ERR(f, DNS::ERR_SERVFAIL))
  {
    process_request(ACTION_TIMEOUT, reqinfo);
    log_func(TRACE_DEBUG_LEVEL, "mass_dns: SERVFAIL <id = %d>\n", p.id);
    stat.sf++;

    return;
  }

  sockaddr_storage ip;
  ip.ss_family = AF_UNSPEC;
  std::string alias;

  for(std::list<DNS::Answer>::const_iterator it = p.answers.begin();
      it != p.answers.end(); ++it )
  {
    const DNS::Answer &a = *it;
    if(a.record_class == DNS::CLASS_IN)
    {
      if (wire_type(reqt->type) == a.record_type) {
        processing_successful = process_result(a.name, a.record, reqinfo, a.name == alias);
        if (!processing_successful) {
          log_func(1, "mass_dns: Mismatched record for request %s\n", reqt->repr());
        }
      }
      else if (a.record_type == DNS::CNAME) {
        const DNS::CNAME_Record *cname = static_cast<const DNS::CNAME_Record *>(a.record);
        if((reqt->type == DNS::PTR && DNS::Factory::ptrToIp(a.name, ip))
          || a.name == reqt->name || (!alias.empty() && a.name == alias))
        {
          alias = cname->value;
          log_func(TRACE_DEBUG_LEVEL, "mass_dns: CNAME found for <%s> to <%s>\n", a.name.c_str(), alias.c_str());
        }
      }
    }
  }

  if (!processing_successful) {
    if (DNS_HAS_FLAG(f, DNS::TRUNCATED)) {
      // TODO: TCP fallback, or only use system resolver if user didn't specify --dns-servers
      process_request(ACTION_SYSTEM_RESOLVE, reqinfo);
    }
    else if (!alias.empty()) {
      log_func(TRACE_DEBUG_LEVEL, "mass_dns: CNAME for <%s> not processed.\n", reqt->repr());
      // TODO: Send a PTR request for alias instead. Meanwhile, we'll just fall
      // back to using system resolver. Alternative: report the canonical name
      // (alias), but that's not very useful.
      process_request(ACTION_SYSTEM_RESOLVE, reqinfo);
    }
    else {
      log_func(TRACE_DEBUG_LEVEL, "mass_dns: Unable to process the response for %s\n", reqt->repr());
    }
  }
  else {
    output_summary(stat);
    stat.ok++;
    process_request(ACTION_FINISHED, reqinfo);
  }
  do_possible_writes();

  // Close DNS servers if we're all done so that we kill
  // all events and return from nsock_loop immediateley
  if (total_reqs == 0)
    close_dns_servers();
}


// nsock connect handler - Empty because it doesn't really need to do anything...
void DNS::ResolverImpl::handle_connect(nsock_pool nsp, nsock_event evt, dns_server *srv) {
  assert(nse_type(evt) == NSE_TYPE_CONNECT);
  if (nse_status(evt) != NSE_STATUS_SUCCESS) {
    log_func(1, "mass_dns: connection to %s failed: %s\n",
        srv->hostname.c_str(),
        nse_status2str(nse_status(evt)));
    srv->status = dns_server::DISCONNECTED;
    return;
  }
  nsock_read(nsp, srv->nsd, &DNS::ResolverImpl::read_evt_handler, -1, (void *)srv);
  srv->status = dns_server::CONNECTED;
}

void DNS::ResolverImpl::add_dns_server(
    const struct sockaddr_storage *addr, size_t addr_len, const char *hostname) {
  if (this->spoof && this->sslen1 && this->src1.ss_family != addr->ss_family) {
    // Can't connect to this address family using the specified source (-S)
    return;
  }

  std::list<dns_server>::iterator servI;
  for(servI = servs.begin(); servI != servs.end(); servI++) {
    // Already added!
    if (memcmp(addr, &servI->addr, addr_len) == 0) break;
  }

  // If it hasn't already been added, add it!
  if (servI == servs.end()) {
    dns_server tpserv(this);

    tpserv.hostname = hostname;
    memcpy(&tpserv.addr, addr, addr_len);
    tpserv.addr_len = addr_len;

    servs.push_front(tpserv);

    log_func(1, "mass_dns: Using DNS server %s\n", hostname);
  }
}

void DNS::ResolverImpl::add_dns_server(const std::string &hostname) {
  struct addrinfo *ai_result = resolve_all(hostname.c_str(),
      this->spoof ? this->af : PF_UNSPEC);
  for (struct addrinfo *ai = ai_result; ai != NULL; ai = ai->ai_next) {
    this->add_dns_server((struct sockaddr_storage *)ai->ai_addr,
        ai->ai_addrlen, hostname.c_str());
  }
  if (ai_result != NULL)
    freeaddrinfo(ai_result);
}

// Creates a new nsi for each DNS server
void DNS::ResolverImpl::connect_dns_servers() {
  std::list<dns_server>::iterator serverI;
  for(serverI = servs.begin(); serverI != servs.end(); serverI++) {
    serverI->nsd = nsock_iod_new(dnspool, NULL);
    if (sslen1 > 0 && src1.ss_family == serverI->addr.ss_family) {
      nsock_iod_set_localaddr(serverI->nsd, &src1, sslen1);
    }
    else if (sslen2 > 0 && src2.ss_family == serverI->addr.ss_family) {
      nsock_iod_set_localaddr(serverI->nsd, &src2, sslen2);
    }
    if (ipoptslen)
      nsock_iod_set_ipoptions(serverI->nsd, (const void *)ipopts, ipoptslen);

    serverI->status = dns_server::CONNECTING;
    nsock_connect_udp(dnspool, serverI->nsd, &DNS::ResolverImpl::connect_evt_handler, &*serverI, (struct sockaddr *) &serverI->addr, serverI->addr_len, 53);
  }
}


void DNS::ResolverImpl::platform_get_servers() {
#ifdef WIN32
  ULONG ret = ERROR_SUCCESS;
  std::vector<IP_ADAPTER_ADDRESSES> advec;
  ULONG len = 0;
  for (int i=0; i < 3; i++) {
    if (len == 0) {
      advec.resize(8);
    }
    else {
      size_t count = len / sizeof(IP_ADAPTER_ADDRESSES);
      advec.resize(count);
    }
    len = advec.size() * sizeof(IP_ADAPTER_ADDRESSES);
    ret = GetAdaptersAddresses(AF_UNSPEC, (
          GAA_FLAG_SKIP_UNICAST |
          GAA_FLAG_SKIP_ANYCAST |
          GAA_FLAG_SKIP_MULTICAST |
          GAA_FLAG_SKIP_FRIENDLY_NAME),
        NULL, &advec[0], &len);
    if (ret != ERROR_BUFFER_OVERFLOW) {
      break;
    }
  }
  if (ret != ERROR_SUCCESS) {
    log_func(1, "Unable to get DNS servers: %08x", ret);
    return;
  }

  char pcap_name[1024];
  const char *pcap_guid = NULL;
  if (device && DnetName2PcapName(device, pcap_name, sizeof(pcap_name))) {
    // pcap_guid is the AdapterName for the requested adapter.
    pcap_guid = strchr(pcap_name, '{');
  }
  for (IP_ADAPTER_ADDRESSES *a = &advec[0]; a != NULL; a = a->Next) {
    if (a->OperStatus != IfOperStatusUp)
      continue;
    // If user requested an interface with -e,
    // don't use DNS servers configured on other interfaces.
    if (pcap_guid && 0 != strcasecmp(a->AdapterName, pcap_guid))
      continue;
    for (IP_ADAPTER_DNS_SERVER_ADDRESS_XP *d = a->FirstDnsServerAddress;
        d != NULL; d = d->Next) {
        const sockaddr_storage* ss = (sockaddr_storage*)d->Address.lpSockaddr;
        size_t sslen = d->Address.iSockaddrLength;
        if (ss->ss_family == AF_INET) {
          if (!a->Ipv4Enabled) continue;
        }
        else if (ss->ss_family == AF_INET6) {
          if (!a->Ipv6Enabled) continue;
          /* Windows default site-local IPv6 DNS servers */
          if (0 == memcmp(&((sockaddr_in6*)ss)->sin6_addr,
              "\xfe\xc0\x00\x00\x00\x00\xff\xff", 8))
              continue;
        }
        else {
          continue;
        }
        add_dns_server(ss, sslen, inet_ntop_ez(ss, sslen));
    }
  }
#else // not WIN32
// Parses /etc/resolv.conf (unix) and adds all the nameservers found via the
// add_dns_server() function.
  FILE *fp;
  char buf[2048], *tp;
  char fmt[32];
  char ipaddr[INET6_ADDRSTRLEN+1];
  static bool firstrun = true;

  fp = fopen("/etc/resolv.conf", "r");
  if (fp == NULL) {
    if (firstrun) perror("mass_dns: warning: Unable to open /etc/resolv.conf. Try using --system-dns or specify valid servers with --dns-servers");
    firstrun = false;
    return;
  }

  Snprintf(fmt, sizeof(fmt), "nameserver %%%us", INET6_ADDRSTRLEN);

  while (fgets(buf, sizeof(buf), fp)) {
    tp = buf;

    // Clip off comments #, \r, \n
    while (*tp != '\r' && *tp != '\n' && *tp != '#' && *tp) tp++;
    *tp = '\0';

    tp = buf;
    // Skip any leading whitespace
    while (*tp == ' ' || *tp == '\t') tp++;

    if (sscanf(tp, fmt, ipaddr) == 1) this->add_dns_server(ipaddr);
  }

  fclose(fp);
#endif // WIN32
}

void DNS::ResolverImpl::parse_etchosts(const char *fname) {
  std::ifstream ifs(fname);
  std::string line;
  sockaddr_storage ia;
  size_t ialen;

  // First, load localhost names
  line = "localhost";
  if (0 == resolve_numeric("::1", 0, &ia, &ialen, AF_INET6)) {
    ptr_etchosts.push_back(std::make_pair(line, ia));
    etchosts[NameRecord(line, DNS::AAAA)] = ia;
  }
  if (0 == resolve_numeric("127.0.0.1", 0, &ia, &ialen, AF_INET)) {
    ptr_etchosts.push_back(std::make_pair(line, ia));
    etchosts[NameRecord(line, DNS::A)] = ia;
  }

  if (ifs.fail()) return; // silently is OK

  while (std::getline(ifs, line)) {
    std::istringstream iss(line);

      std::string addr, hname;
      if (!(iss >> addr >> hname)) {
        // We need more than 1 token per line
        continue;
      }

      // If hostname is a comment or address begins a comment, no good.
      if (hname[0] == '#' || addr.find('#') != std::string::npos) {
        continue;
      }

      if (0 == resolve_numeric(addr.c_str(), 0, &ia, &ialen, AF_UNSPEC)) {
        size_t commentpos = std::string::npos;
        bool first = true;
        do {
          // If there's a comment in the hostname, strip it.
          commentpos = hname.find('#');
          if (commentpos != std::string::npos) {
            hname.erase(commentpos);
          }
          if (!hname.empty()) {
            if (first) {
              ptr_etchosts.push_back(std::make_pair(hname, ia));
            }
            if (ia.ss_family == AF_INET) {
              etchosts[NameRecord(hname, DNS::A)] = ia;
            }
            else if (ia.ss_family == AF_INET6) {
              etchosts[NameRecord(hname, DNS::AAAA)] = ia;
            }
          }
          first = false;
          // Keep going until we find a comment or run out of tokens
        } while (commentpos == std::string::npos && (iss >> hname));
      }
      //else log_func(1, "Unable to parse /etc/hosts address: %s\n", addr.c_str());
  }
}

void DNS::ResolverImpl::etchosts_init(void) {
  static int initialized = 0;
  if (initialized) return;
  initialized = 1;

#ifdef WIN32
  char windows_dir[1024];
  char tpbuf[2048];
  int has_backslash;

  if (!GetWindowsDirectoryA(windows_dir, sizeof(windows_dir)))
    fprintf(stderr, "massdns: Failed to determine your windows directory\n");

  // If it has a backslash it's C:\, otherwise something like C:\WINNT
  has_backslash = (windows_dir[strlen(windows_dir)-1] == '\\');

  // Windows NT/2000/XP/2K3:
  Snprintf(tpbuf, sizeof(tpbuf), "%s%ssystem32\\drivers\\etc\\hosts", windows_dir, has_backslash ? "" : "\\");
  DNS::ResolverImpl::parse_etchosts(tpbuf);

#else
  DNS::ResolverImpl::parse_etchosts("/etc/hosts");
#endif // WIN32
}

void DNS::ResolverImpl::init_host_cache(void) {
  for(std::list<std::pair<std::string, sockaddr_storage> >::const_iterator it = DNS::ResolverImpl::ptr_etchosts.begin();
      it != ptr_etchosts.end(); ++it) {
    const std::string &hostname = it->first;
    const sockaddr_storage &ss = it->second;
    host_cache.add(ss, hostname);
  }
}

bool DNS::ResolverImpl::system_resolve(DNS::Request &reqt)
{
  char hostname[DNS_NAME_MAX_LENGTH] = "";
  int af = AF_INET;
  struct addrinfo *ai_result = NULL, *ai = NULL;

  if (reqt.type == DNS::PTR) {
    assert(reqt.ssv.size() > 0);
    if (getnameinfo((const struct sockaddr *) &reqt.ssv.front(),
          sizeof(sockaddr_storage), hostname,
          sizeof(hostname), NULL, 0, NI_NAMEREQD) == 0) {
      reqt.name = hostname;
    }
  }
  else {
    switch (reqt.type) {
      case DNS::A:
        af = AF_INET;
        break;
      case DNS::AAAA:
        af = AF_INET6;
        break;
      case DNS::ANY:
        af = AF_UNSPEC;
        break;
      default:
        log_func(0, "System DNS resolution of %s could not be performed.\n", reqt.repr());
        return false;
        break;
    }
    ai_result = resolve_all(reqt.name.c_str(), af);
    for (ai = ai_result; ai != NULL; ai = ai->ai_next) {
      if (ai->ai_addrlen <= sizeof(sockaddr_storage)) {
        sockaddr_storage ss = {};
        memcpy(&ss, ai->ai_addr, ai->ai_addrlen);
        reqt.ssv.push_back(ss);
      }
    }
    if (ai_result != NULL)
      freeaddrinfo(ai_result);
    else
      return false;
  }
  return true;
}

bool DNS::Factory::ipToPtr(const sockaddr_storage &ip, std::string &ptr)
{
  static const size_t maxlen = sizeof("0.0.1.1.2.2.3.3.4.4.5.5.6.6.7.7.8.8.9.9.a.a.b.b.c.c.d.d.e.e.f.f.ip6.arpa");
  ptr.reserve(maxlen);
  char tmp[INET_ADDRSTRLEN];
  switch (ip.ss_family) {
    case AF_INET:
    {
      const u32 ipv4_addr = ((const sockaddr_in *) &ip)->sin_addr.s_addr;
      const u8 *ipv4_c = (const u8 *)&ipv4_addr;
      sprintf(tmp, "%d.%d.%d.%d", ipv4_c[3], ipv4_c[2], ipv4_c[1], ipv4_c[0]);
      ptr = tmp;
      ptr += IPV4_PTR_DOMAIN;
      break;
    }
    case AF_INET6:
    {
      ptr.clear();
      const struct sockaddr_in6 &s6 = (const struct sockaddr_in6 &) ip;
      const u8 * ipv6 = s6.sin6_addr.s6_addr;
      for (short i=15; i>=0; --i)
      {
        sprintf(tmp, "%02x", ipv6[i]);
        ptr += '.';
        ptr += tmp[1];
        ptr += '.';
        ptr += tmp[0];
      }
      ptr.erase(ptr.begin());
      ptr += IPV6_PTR_DOMAIN;
      break;
    }
    default:
      return false;
  }
  return true;
}

bool DNS::Factory::ptrToIp(const std::string &ptr, sockaddr_storage &ip)
{
  const char *cptr = ptr.c_str();
  const char *p = NULL;

  memset(&ip, 0, sizeof(sockaddr_storage));

  // Check whether the name ends with the IPv4 PTR domain
  if (NULL != (p = strcasestr(cptr + ptr.length() + 1 - sizeof(C_IPV4_PTR_DOMAIN), C_IPV4_PTR_DOMAIN)))
  {
    struct sockaddr_in *ip4 = (struct sockaddr_in *)&ip;
    static const u8 place_value[] = {1, 10, 100};
    u8 *v = (u8 *) &(ip4->sin_addr.s_addr);
    size_t place = 0;
    size_t i = 0;

    p--;
    while (p >= cptr && i < sizeof(ip4->sin_addr.s_addr))
    {
      if (*p == '.')
      {
        place = 0;
        p--;
        i++;
      }
      if (p < cptr)
      {
        break;
      }
      u8 n = *p;
      if (n >= '0' && n <= '9') { // 0-9
        n -= 0x30;
      }
      else { // invalid
        return false;
      }
      v[i] += n * place_value[place];
      place++;
      p--;
    }
    ip.ss_family = AF_INET;
  }
  // If not, check IPv6
  else if (NULL != (p = strcasestr(cptr + ptr.length() + 1 - sizeof(C_IPV6_PTR_DOMAIN), C_IPV6_PTR_DOMAIN)))
  {
    struct sockaddr_in6 *ip6 = (struct sockaddr_in6 *)&ip;
    u8 alt = 0;
    size_t i=0;

    p--;
    while (p >= cptr && i < sizeof(ip6->sin6_addr.s6_addr))
    {
      if (*p == '.')
      {
        p--;
      }
      if (p < cptr)
      {
        break;
      }
      u8 n = *p;
      // First subtract base regardless of underflow:
      if (n < 0x3A) { // 0-9
        n -= 0x30;
      }
      else if (n < 0x47) { // A-F
        n -= 0x37;
      }
      else if (n < 0x67) { // a-f
        n -= 0x57;
      }
      else { // invalid
        return false;
      }
      // Now catch any of the underflow conditions above:
      if (n > 0xf) { // invalid
        return false;
      }
      if (alt == 0) { // high nibble
        ip6->sin6_addr.s6_addr[i] += n << 4;
        alt = 1;
      }
      else { // low nibble
        ip6->sin6_addr.s6_addr[i] += n;
        alt = 0;
        i++;
      }
      p--;
    }
    ip.ss_family = AF_INET6;
  }
  return true;
}

size_t DNS::Factory::buildSimpleRequest(u16 id, const std::string &name, RECORD_TYPE rt, u8 *buf, size_t maxlen)
{
  size_t ret=0 , tmp=0;
  DNS_CHECK_ACCUMLATE(ret, tmp, putUnsignedShort(id, buf, ID, maxlen));
  DNS_CHECK_ACCUMLATE(ret, tmp, putUnsignedShort(OP_STANDARD_QUERY | RECURSION_DESIRED, buf, FLAGS_OFFSET, maxlen));
  DNS_CHECK_ACCUMLATE(ret, tmp, putUnsignedShort(1, buf, QDCOUNT, maxlen));
  DNS_CHECK_ACCUMLATE(ret, tmp, putUnsignedShort(0, buf, ANCOUNT, maxlen));
  DNS_CHECK_ACCUMLATE(ret, tmp, putUnsignedShort(0, buf, NSCOUNT, maxlen));
  DNS_CHECK_ACCUMLATE(ret, tmp, putUnsignedShort(0, buf, ARCOUNT, maxlen));
  DNS_CHECK_ACCUMLATE(ret, tmp, putDomainName(name, buf, DATA, maxlen));
  DNS_CHECK_ACCUMLATE(ret, tmp, putUnsignedShort(rt, buf, ret, maxlen));
  DNS_CHECK_ACCUMLATE(ret, tmp, putUnsignedShort(CLASS_IN, buf, ret, maxlen));

  return ret;
}

size_t DNS::Factory::buildReverseRequest(u16 id, const sockaddr_storage &ip, u8 *buf, size_t maxlen)
{
  std::string name;
  if(ipToPtr(ip,name))
    return buildSimpleRequest(id, name, PTR, buf, maxlen);
  return 0;
}

size_t DNS::Factory::putUnsignedShort(u16 num, u8 *buf, size_t offset, size_t maxlen)
{
  size_t max_access = offset+1;
  if(buf && (maxlen > max_access))
  {
    buf[offset] = (num >> 8) & 0xFF;
    buf[max_access] = num & 0xFF;
    return 2;
  }

  return 0;
}

size_t DNS::Factory::putDomainName(const std::string &name, u8 *buf, size_t offset, size_t maxlen)
{
  size_t ret=0;
  if( !( buf && (maxlen > (offset + name.length() + 1))) ) return ret;

  std::string namew = name + ".";
  std::string accumulator;
  for (std::string::const_iterator c=namew.begin(); c != namew.end(); ++c)
  {
    if((*c)=='.')
    {
      u8 length = accumulator.length();
      *(buf+offset+ret) = length;
      ret += 1;

      memcpy(buf+offset+ret, accumulator.c_str(), length);
      ret += length;
      accumulator.clear();
    }
    else
      accumulator += (*c);
  }

  *(buf+offset+ret) = 0;
  ret += 1;

  return ret;
}

size_t DNS::Factory::parseUnsignedShort(u16 &num, const u8 *buf, size_t offset, size_t maxlen)
{
  size_t max_access = offset+1;
  if(buf && (maxlen > max_access))
  {
    const u8 * n = buf + offset;
    num = n[1] + (n[0]<<8);
    return 2;
  }

  return 0;
}

size_t DNS::Factory::parseUnsignedInt(u32 &num, const u8 *buf, size_t offset, size_t maxlen)
{
  size_t max_access = offset+3;
  if(buf && (maxlen > max_access))
  {
    const u8 * n = buf + offset;
    num = n[3] + (n[2]<<8) + (n[1]<<16) + (n[0]<<24);
    return 4;
  }

  return 0;
}

size_t DNS::Factory::parseIPv4(struct in_addr &addr, const u8 *buf, size_t offset, size_t maxlen)
{
  size_t max_access = offset+3;
  if(buf && (maxlen > max_access))
  {
    memcpy(&addr, buf + offset, 4);
    return 4;
  }

  return 0;
}

size_t DNS::Factory::parseIPv6(struct in6_addr &addr, const u8 *buf, size_t offset, size_t maxlen)
{
  size_t max_access = offset+15;
  if(buf && (maxlen > max_access))
  {
    memcpy(&addr, buf + offset, 16);
    return 16;
  }

  return 0;
}

size_t DNS::Factory::parseDomainName(std::string &name, const u8 *buf, size_t offset, size_t maxlen)
{
  size_t tmp = 0;
  size_t max_offset = offset;
  size_t curr_offset = offset;
  u8 label_length = 0;

  name.clear();
  while(curr_offset < maxlen && 0 != (label_length = buf[curr_offset]))
  {
    if((label_length & COMPRESSED_NAME) == COMPRESSED_NAME)
    {
      u16 real_offset;
      tmp = parseUnsignedShort(real_offset, buf, curr_offset, maxlen);
      if (tmp < 1) {
        return 0;
      }
      if (curr_offset >= max_offset) {
        max_offset = curr_offset + tmp;
      }
      real_offset -= COMPRESSED_NAME<<8;
      if(real_offset < curr_offset)
      {
        curr_offset = real_offset;
        continue;
      }
      else {
        //log_func(1, "DNS compression pointer is not backwards\n");
        return 0;
      }
    }

    if (label_length > DNS_LABEL_MAX_LENGTH) {
      //log_func(1, "DNS label exceeds max length\n");
      return 0;
    }

    curr_offset++;
    DNS_CHECK_UPPER_BOUND(curr_offset + label_length, maxlen);
    name.append(reinterpret_cast<const char *>(buf + curr_offset), label_length);
    curr_offset += label_length;
    if (curr_offset > max_offset) {
      max_offset = curr_offset;
    }
    name += '.';

    if (name.length() > DNS_NAME_MAX_LENGTH - 1) {
      //log_func(1, "DNS name exceeds max length\n");
      return 0;
    }
  }

  DNS_CHECK_UPPER_BOUND(curr_offset, maxlen - 1);
  if (max_offset == curr_offset && buf[curr_offset] == '\0') {
    max_offset++;
  }

  if (name.empty()) {
    name = ".";
  }
  else {
    std::string::iterator it = name.end()-1;
    if( *it == '.') name.erase(it);
  }

  return max_offset - offset;
}

size_t DNS::A_Record::parseFromBuffer(const u8 *buf, size_t offset, size_t maxlen, RECORD_TYPE rt)
{
  size_t tmp, ret = 0;
  struct sockaddr_in * ip4addr = (sockaddr_in *) &value;
  struct sockaddr_in6 * ip6addr = (sockaddr_in6 *) &value;

  memset(&value, 0, sizeof(value));
  switch (rt) {
    case DNS::A:
      DNS_CHECK_ACCUMLATE(ret, tmp, Factory::parseIPv4(ip4addr->sin_addr, buf, offset, maxlen));
      ip4addr->sin_family = AF_INET;
      break;
    case DNS::AAAA:
      DNS_CHECK_ACCUMLATE(ret, tmp, Factory::parseIPv6(ip6addr->sin6_addr, buf, offset, maxlen));
      ip6addr->sin6_family = AF_INET6;
      break;
    default:
      return 0;
      break;
  }

  return ret;
}

size_t DNS::Query::parseFromBuffer(const u8 *buf, size_t offset, size_t maxlen)
{
  size_t ret=0;

  if (buf && ((maxlen - offset) > 5))
  {
    size_t tmp=0;
    DNS_CHECK_ACCUMLATE(ret, tmp, Factory::parseDomainName(name, buf, offset+ret, maxlen));
    DNS_CHECK_ACCUMLATE(ret, tmp, Factory::parseUnsignedShort(record_type, buf, offset+ret, maxlen));
    DNS_CHECK_ACCUMLATE(ret, tmp, Factory::parseUnsignedShort(record_class, buf, offset+ret, maxlen));
  }

  return ret;
}

size_t DNS::Answer::parseFromBuffer(const u8 *buf, size_t offset, size_t maxlen)
{
  size_t ret=0;

  if (buf && ((maxlen - offset) > 7))
  {
    size_t tmp;
    DNS_CHECK_ACCUMLATE(ret, tmp, Factory::parseDomainName(name, buf, offset+ret, maxlen));
    DNS_CHECK_ACCUMLATE(ret, tmp, Factory::parseUnsignedShort(record_type, buf, offset+ret, maxlen));
    DNS_CHECK_ACCUMLATE(ret, tmp, Factory::parseUnsignedShort(record_class, buf, offset+ret, maxlen));
    DNS_CHECK_ACCUMLATE(ret, tmp, Factory::parseUnsignedInt(ttl, buf, offset+ret, maxlen));
    DNS_CHECK_ACCUMLATE(ret, tmp, Factory::parseUnsignedShort(length, buf, offset+ret, maxlen));

    DNS_CHECK_UPPER_BOUND(offset+ret+length, maxlen);

    switch(record_type)
    {
    case A:
    case AAAA:
    {
      record = new A_Record();
      break;
    }
    case CNAME:
    {
      record = new CNAME_Record();
      break;
    }
    case PTR:
    {
      record = new PTR_Record();
      break;
    }
    default:
      return 0;
    }

    DNS_CHECK_ACCUMLATE(ret, tmp, record->parseFromBuffer(buf, offset+ret, maxlen, (RECORD_TYPE) record_type));
  }

  return ret;
}

DNS::Answer& DNS::Answer::operator=(const Answer &r)
{
  name = r.name;
  record_type = r.record_type;
  record_class = r.record_class;
  ttl = r.ttl;
  length = r.length;
  record = r.record->clone();
  return *this;
}

size_t DNS::Packet::parseFromBuffer(const u8 *buf, size_t maxlen)
{
  if( !buf || maxlen < DATA) return 0;

  size_t tmp, ret = 0;
  DNS_CHECK_ACCUMLATE(ret, tmp, Factory::parseUnsignedShort(id, buf, ID, maxlen));
  DNS_CHECK_ACCUMLATE(ret, tmp, Factory::parseUnsignedShort(flags, buf, FLAGS_OFFSET, maxlen));

  u16 queries_counter, answers_counter, authorities_counter, additionals_counter;
  DNS_CHECK_ACCUMLATE(ret, tmp, Factory::parseUnsignedShort(queries_counter, buf, QDCOUNT, maxlen));
  DNS_CHECK_ACCUMLATE(ret, tmp, Factory::parseUnsignedShort(answers_counter, buf, ANCOUNT, maxlen));
  DNS_CHECK_ACCUMLATE(ret, tmp, Factory::parseUnsignedShort(authorities_counter, buf, NSCOUNT, maxlen));
  DNS_CHECK_ACCUMLATE(ret, tmp, Factory::parseUnsignedShort(additionals_counter, buf, ARCOUNT, maxlen));

  queries.clear();
  for(u16 i=0; i<queries_counter; ++i)
  {
    Query q;
    DNS_CHECK_ACCUMLATE(ret, tmp, q.parseFromBuffer(buf, ret, maxlen));
    queries.push_back(q);
  }

  answers.clear();
  for(u16 i=0; i<answers_counter; ++i)
  {
    Answer a;
    DNS_CHECK_ACCUMLATE(ret, tmp, a.parseFromBuffer(buf, ret, maxlen));
    answers.push_back(a);
  };

  return ret;
}

const char *DNS::Request::repr() const
{
#define REPR_BUFSIZE (DNS_NAME_MAX_LENGTH + 16)
  static char buf[REPR_BUFSIZE] = "\0";
  switch(type) {
    case DNS::NONE:
      return "Uninitialized request";
      break;
    case DNS::A:
    case DNS::AAAA:
    case DNS::ANY:
      Snprintf(buf, REPR_BUFSIZE, "%s/%d", name.c_str(), type);
      break;
    case DNS::PTR:
      if (ssv.size() > 0) {
        return inet_ntop_ez(&ssv.front(), sizeof(struct sockaddr_storage));
      }
      else {
        return "Uninitialized PTR request";
      }
      break;
    default:
      Snprintf(buf, REPR_BUFSIZE, "Invalid request: %d", type);
      break;
  }
  return buf;
}
