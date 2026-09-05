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

#include "NmapOps.h"
#include "nmap_dns.h"
#include "libnetutil/massdns.h"
#include "output.h"
#include "nmap_error.h"
#include "nmap_tty.h"
#include "timing.h"
#include "Target.h"

extern NmapOps o;

static ScanProgressMeter *SPM = NULL;

void nmap_massdns_log(int lvl, const char *fmt, ...)
{
  va_list ap;
  if (o.debugging >= lvl || o.verbose >= lvl + 2) {
    va_start(ap, fmt);
    log_vwrite(LOG_STDOUT, fmt, ap);
    va_end(ap);
  }
}

void nmap_massdns_status(const DNS::Stats *stat)
{
  if (keyWasPressed()) {
    assert(SPM != NULL);
    SPM->printStats(stat->statDone(), stat->actual, NULL);
    /* Because this can change with runtime interaction */
    nmap_adjust_loglevel(o.packetTrace());
  }
}

static DNS::Resolver *nmap_get_resolver() {
  static DNS::Resolver resolver;
  static DNS::Resolver *ptr = NULL;
  if (ptr == NULL) {
    resolver.setAF(o.af());
    resolver.setStatusCallback(nmap_massdns_status);
    resolver.setLogFunc(nmap_massdns_log);

    if (o.mass_dns) {
      struct sockaddr_storage ss;
      size_t sslen = 0;
      struct sockaddr_storage *src = NULL;
      if (0 == o.SourceSockAddr(&ss, &sslen)) {
        src = &ss;
      }
      if (*o.device || src) {
        resolver.setSource(o.device, &ss, sslen, o.spoofsource);
      }
      if (o.ipoptionslen) {
        resolver.setIpOptions(o.ipoptions, o.ipoptionslen);
      }
      if (o.proxy_chain) {
        resolver.setProxyChain(o.proxy_chain);
      }
      resolver.setServers(o.dns_servers);
    }
    ptr = &resolver;
  }
  return ptr;
}

// Publicly available function. Basically just a wrapper so we
// can record time information, restart statistics, etc.
void nmap_mass_dns(DNS::Request requests[], int num_requests) {
  DNS::Resolver *resolver = nmap_get_resolver();
  bool use_systemdns = !o.mass_dns;
  resolver->Init(requests, num_requests);

  if (o.mass_dns) {
    const char *errstr = NULL;
    if (!resolver->isMassDnsOK(&errstr)) {
      error("%s. Falling back to --system-dns. "
          "Specify valid servers with --dns-servers", errstr);
      use_systemdns = true;
    }
    else {
      nmap_set_nsock_logger();
      nmap_adjust_loglevel(o.packetTrace());
    }
  }

  DNS::Stats stat = resolver->getStats();
  char spmobuf[1024];
  Snprintf(spmobuf, sizeof(spmobuf), "%s DNS resolution of %d host%s.",
      use_systemdns ? "System" : "Parallel", stat.names, stat.names-1 ? "s" : "");
  assert(SPM == NULL);
  SPM = new ScanProgressMeter(spmobuf);

  resolver->Resolve(use_systemdns);

  SPM->endTask(NULL, NULL);
  delete SPM;
  SPM = NULL;
}


void nmap_mass_rdns(Target ** targets, int num_targets) {
  /* Second, make an array of pointer to DNS::Request to suit the interface of
     nmap_mass_rdns. */
  DNS::Request *requests = new DNS::Request[num_targets];
  for (int i = 0; i < num_targets; i++) {
    Target *target = targets[i];
    if (!(target->flags & HOST_UP) && !o.always_resolve) continue;

    DNS::Request &reqt = requests[i];
    reqt.ssv.push_back(*target->TargetSockAddr());
    reqt.type = DNS::PTR;
  }
  nmap_mass_dns(requests, num_targets);
  for (int i = 0; i < num_targets; i++) {
    std::string &name = requests[i].name;
    if (!name.empty()) {
      targets[i]->setHostName(name.c_str());
    }
  }
  delete[] requests;
}

std::list<std::string> get_dns_servers() {
  DNS::Resolver *resolver = nmap_get_resolver();
  return resolver->getServers();
}
