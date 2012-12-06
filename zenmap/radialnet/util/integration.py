# vim: set fileencoding=utf-8 :

# ***********************IMPORTANT NMAP LICENSE TERMS************************
# *                                                                         *
# * The Nmap Security Scanner is (C) 1996-2012 Insecure.Com LLC. Nmap is    *
# * also a registered trademark of Insecure.Com LLC.  This program is free  *
# * software; you may redistribute and/or modify it under the terms of the  *
# * GNU General Public License as published by the Free Software            *
# * Foundation; Version 2 with the clarifications and exceptions described  *
# * below.  This guarantees your right to use, modify, and redistribute     *
# * this software under certain conditions.  If you wish to embed Nmap      *
# * technology into proprietary software, we sell alternative licenses      *
# * (contact sales@insecure.com).  Dozens of software vendors already       *
# * license Nmap technology such as host discovery, port scanning, OS       *
# * detection, version detection, and the Nmap Scripting Engine.            *
# *                                                                         *
# * Note that the GPL places important restrictions on "derived works", yet *
# * it does not provide a detailed definition of that term.  To avoid       *
# * misunderstandings, we interpret that term as broadly as copyright law   *
# * allows.  For example, we consider an application to constitute a        *
# * "derivative work" for the purpose of this license if it does any of the *
# * following:                                                              *
# * o Integrates source code from Nmap                                      *
# * o Reads or includes Nmap copyrighted data files, such as                *
# *   nmap-os-db or nmap-service-probes.                                    *
# * o Executes Nmap and parses the results (as opposed to typical shell or  *
# *   execution-menu apps, which simply display raw Nmap output and so are  *
# *   not derivative works.)                                                *
# * o Integrates/includes/aggregates Nmap into a proprietary executable     *
# *   installer, such as those produced by InstallShield.                   *
# * o Links to a library or executes a program that does any of the above   *
# *                                                                         *
# * The term "Nmap" should be taken to also include any portions or derived *
# * works of Nmap, as well as other software we distribute under this       *
# * license such as Zenmap, Ncat, and Nping.  This list is not exclusive,   *
# * but is meant to clarify our interpretation of derived works with some   *
# * common examples.  Our interpretation applies only to Nmap--we don't     *
# * speak for other people's GPL works.                                     *
# *                                                                         *
# * If you have any questions about the GPL licensing restrictions on using *
# * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
# * we also offer alternative license to integrate Nmap into proprietary    *
# * applications and appliances.  These contracts have been sold to dozens  *
# * of software vendors, and generally include a perpetual license as well  *
# * as providing for priority support and updates.  They also fund the      *
# * continued development of Nmap.  Please email sales@insecure.com for     *
# * further information.                                                    *
# *                                                                         *
# * As a special exception to the GPL terms, Insecure.Com LLC grants        *
# * permission to link the code of this program with any version of the     *
# * OpenSSL library which is distributed under a license identical to that  *
# * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
# * linked combinations including the two. You must obey the GNU GPL in all *
# * respects for all of the code used other than OpenSSL.  If you modify    *
# * this file, you may extend this exception to your version of the file,   *
# * but you are not obligated to do so.                                     *
# *                                                                         *
# * If you received these files with a written license agreement or         *
# * contract stating terms other than the terms above, then that            *
# * alternative license agreement takes precedence over these comments.     *
# *                                                                         *
# * Source is provided to this software because we believe users have a     *
# * right to know exactly what a program is going to do before they run it. *
# * This also allows you to audit the software for security holes (none     *
# * have been found so far).                                                *
# *                                                                         *
# * Source code also allows you to port Nmap to new platforms, fix bugs,    *
# * and add new features.  You are highly encouraged to send your changes   *
# * to the dev@nmap.org mailing list for possible incorporation into the    *
# * main distribution.  By sending these changes to Fyodor or one of the    *
# * Insecure.Org development mailing lists, or checking them into the Nmap  *
# * source code repository, it is understood (unless you specify otherwise) *
# * that you are offering the Nmap Project (Insecure.Com LLC) the           *
# * unlimited, non-exclusive right to reuse, modify, and relicense the      *
# * code.  Nmap will always be available Open Source, but this is important *
# * because the inability to relicense code has caused devastating problems *
# * for other Free Software projects (such as KDE and NASM).  We also       *
# * occasionally relicense the code to third parties as discussed above.    *
# * If you wish to specify special license conditions of your               *
# * contributions, just say so when you send them.                          *
# *                                                                         *
# * This program is distributed in the hope that it will be useful, but     *
# * WITHOUT ANY WARRANTY; without even the implied warranty of              *
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the Nmap      *
# * license file for more details (it's in a COPYING file included with     *
# * Nmap, and also available from https://svn.nmap.org/nmap/COPYING         *
# *                                                                         *
# ***************************************************************************/

from radialnet.core.Graph import *
from radialnet.gui.RadialNet import NetNode
import zenmapCore.NmapParser

import math
import re


COLORS = [(0.0, 1.0, 0.0),
          (1.0, 1.0, 0.0),
          (1.0, 0.0, 0.0)]

BASE_RADIUS = 5.5
NONE_RADIUS = 4.5



def set_node_info(node, host):
    """
    """
    node.set_host(host)

    radius = BASE_RADIUS + 2 * math.log(node.get_info("number_of_open_ports") + 1)

    node.set_draw_info({"color":COLORS[node.get_info("vulnerability_score")],
                        "radius":radius})

class TracerouteHostInfo(object):
    """This is a minimal implementation of HostInfo, sufficient to
    represent the information in an intermediate traceroute hop."""
    def __init__(self):
        self.ip = None
        self.ipv6 = None
        self.mac = None
        self.hostname = None
        self.ports = []
        self.extraports = []
        self.osmatches = []

    def get_hostname(self):
        return self.hostname

    def get_best_osmatch(self):
        if not self.osmatches:
            return None
        def osmatch_key(osmatch):
            try:
                return -float(osmatch["accuracy"])
            except ValueError:
                return 0
        return sorted(self.osmatches, key = osmatch_key)[0]

    hostnames = property(lambda self: self.hostname and [self.hostname] or [])

def make_graph_from_hosts(hosts):
    #hosts = parser.get_root().search_children('host', deep=True)
    graph = Graph()
    nodes = list()
    node_cache = {}

    # Setting initial reference host
    main_node = NetNode()
    nodes.append(main_node)

    localhost = TracerouteHostInfo()
    localhost.ip = {"addr": "127.0.0.1/8", "type": "ipv4"}
    localhost.hostname = "localhost"
    main_node.set_host(localhost)
    main_node.set_draw_info({"valid": True, "color":(0,0,0), "radius":NONE_RADIUS})

    #Save endpoints for attaching scanned hosts to
    endpoints = {}
    # For each host in hosts just mount the graph
    for host in hosts:
        trace = host.trace
        endpoints[host] = nodes[0]
        hops = trace.get("hops")

        # If host has traceroute information mount graph
        if hops is not None and len(hops) > 0:
            prev_node = nodes[0]
            hops = trace.get("hops", [])
            ttls = [int(hop["ttl"]) for hop in hops]

            # Getting nodes of host by ttl
            for ttl in range(1, max(ttls) + 1):
                if ttl in ttls:
                    # Find a hop by ttl
                    hop = None
                    for h in hops:
                        if ttl == int(h["ttl"]):
                            hop = h
                            break

                    node = node_cache.get(hop["ipaddr"])
                    if node is None:
                        node = NetNode()
                        nodes.append(node)

                        hop_host = TracerouteHostInfo()
                        hop_host.ip = {"addr": hop["ipaddr"], "type": "", "vendor": ""}
                        node.set_draw_info({"valid":True})
                        node.set_draw_info({"color":(1,1,1),
                                            "radius":NONE_RADIUS})

                        if hop["host"] != "":
                            hop_host.hostname = hop["host"]

                        node.set_host(hop_host)

                        node_cache[node.get_info("ip")] = node

                    rtt = hop["rtt"]
                    if rtt != "--":
                        graph.set_connection(node, prev_node, float(rtt))
                    else:
                        graph.set_connection(node, prev_node)
                else:
                    node = NetNode()
                    nodes.append(node)

                    node.set_draw_info({"valid":False})
                    node.set_draw_info({"color":(1,1,1), "radius":NONE_RADIUS})

                    graph.set_connection(node, prev_node)

                prev_node = node
                endpoints[host] = node

    # For each fully scanned host
    for host in hosts:
        ip = host.ip
        if ip is None:
            ip = host.ipv6

        node = node_cache.get(ip["addr"])
        if node is None:
            node = NetNode()
            nodes.append(node)

            node.set_draw_info({"no_route":True})

            graph.set_connection(node, endpoints[host])

        node.set_draw_info({"valid":True})
        node.set_draw_info({"scanned":True})
        set_node_info(node, host)
        node_cache[node.get_info("ip")] = node

    graph.set_nodes(nodes)
    graph.set_main_node(main_node)

    return graph
