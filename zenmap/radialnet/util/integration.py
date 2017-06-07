# vim: set fileencoding=utf-8 :

# ***********************IMPORTANT NMAP LICENSE TERMS************************
# *                                                                         *
# * The Nmap Security Scanner is (C) 1996-2017 Insecure.Com LLC ("The Nmap  *
# * Project"). Nmap is also a registered trademark of the Nmap Project.     *
# * This program is free software; you may redistribute and/or modify it    *
# * under the terms of the GNU General Public License as published by the   *
# * Free Software Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE   *
# * CLARIFICATIONS AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your   *
# * right to use, modify, and redistribute this software under certain      *
# * conditions.  If you wish to embed Nmap technology into proprietary      *
# * software, we sell alternative licenses (contact sales@nmap.com).        *
# * Dozens of software vendors already license Nmap technology such as      *
# * host discovery, port scanning, OS detection, version detection, and     *
# * the Nmap Scripting Engine.                                              *
# *                                                                         *
# * Note that the GPL places important restrictions on "derivative works",  *
# * yet it does not provide a detailed definition of that term.  To avoid   *
# * misunderstandings, we interpret that term as broadly as copyright law   *
# * allows.  For example, we consider an application to constitute a        *
# * derivative work for the purpose of this license if it does any of the   *
# * following with any software or content covered by this license          *
# * ("Covered Software"):                                                   *
# *                                                                         *
# * o Integrates source code from Covered Software.                         *
# *                                                                         *
# * o Reads or includes copyrighted data files, such as Nmap's nmap-os-db   *
# * or nmap-service-probes.                                                 *
# *                                                                         *
# * o Is designed specifically to execute Covered Software and parse the    *
# * results (as opposed to typical shell or execution-menu apps, which will *
# * execute anything you tell them to).                                     *
# *                                                                         *
# * o Includes Covered Software in a proprietary executable installer.  The *
# * installers produced by InstallShield are an example of this.  Including *
# * Nmap with other software in compressed or archival form does not        *
# * trigger this provision, provided appropriate open source decompression  *
# * or de-archiving software is widely available for no charge.  For the    *
# * purposes of this license, an installer is considered to include Covered *
# * Software even if it actually retrieves a copy of Covered Software from  *
# * another source during runtime (such as by downloading it from the       *
# * Internet).                                                              *
# *                                                                         *
# * o Links (statically or dynamically) to a library which does any of the  *
# * above.                                                                  *
# *                                                                         *
# * o Executes a helper program, module, or script to do any of the above.  *
# *                                                                         *
# * This list is not exclusive, but is meant to clarify our interpretation  *
# * of derived works with some common examples.  Other people may interpret *
# * the plain GPL differently, so we consider this a special exception to   *
# * the GPL that we apply to Covered Software.  Works which meet any of     *
# * these conditions must conform to all of the terms of this license,      *
# * particularly including the GPL Section 3 requirements of providing      *
# * source code and allowing free redistribution of the work as a whole.    *
# *                                                                         *
# * As another special exception to the GPL terms, the Nmap Project grants  *
# * permission to link the code of this program with any version of the     *
# * OpenSSL library which is distributed under a license identical to that  *
# * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
# * linked combinations including the two.                                  *
# *                                                                         *
# * The Nmap Project has permission to redistribute Npcap, a packet         *
# * capturing driver and library for the Microsoft Windows platform.        *
# * Npcap is a separate work with it's own license rather than this Nmap    *
# * license.  Since the Npcap license does not permit redistribution        *
# * without special permission, our Nmap Windows binary packages which      *
# * contain Npcap may not be redistributed without special permission.      *
# *                                                                         *
# * Any redistribution of Covered Software, including any derived works,    *
# * must obey and carry forward all of the terms of this license, including *
# * obeying all GPL rules and restrictions.  For example, source code of    *
# * the whole work must be provided and free redistribution must be         *
# * allowed.  All GPL references to "this License", are to be treated as    *
# * including the terms and conditions of this license text as well.        *
# *                                                                         *
# * Because this license imposes special exceptions to the GPL, Covered     *
# * Work may not be combined (even as part of a larger work) with plain GPL *
# * software.  The terms, conditions, and exceptions of this license must   *
# * be included as well.  This license is incompatible with some other open *
# * source licenses as well.  In some cases we can relicense portions of    *
# * Nmap or grant special permissions to use it in other open source        *
# * software.  Please contact fyodor@nmap.org with any such requests.       *
# * Similarly, we don't incorporate incompatible open source software into  *
# * Covered Software without special permission from the copyright holders. *
# *                                                                         *
# * If you have any questions about the licensing restrictions on using     *
# * Nmap in other works, are happy to help.  As mentioned above, we also    *
# * offer alternative license to integrate Nmap into proprietary            *
# * applications and appliances.  These contracts have been sold to dozens  *
# * of software vendors, and generally include a perpetual license as well  *
# * as providing for priority support and updates.  They also fund the      *
# * continued development of Nmap.  Please email sales@nmap.com for further *
# * information.                                                            *
# *                                                                         *
# * If you have received a written license agreement or contract for        *
# * Covered Software stating terms other than these, you may choose to use  *
# * and redistribute Covered Software under those terms instead of these.   *
# *                                                                         *
# * Source is provided to this software because we believe users have a     *
# * right to know exactly what a program is going to do before they run it. *
# * This also allows you to audit the software for security holes.          *
# *                                                                         *
# * Source code also allows you to port Nmap to new platforms, fix bugs,    *
# * and add new features.  You are highly encouraged to send your changes   *
# * to the dev@nmap.org mailing list for possible incorporation into the    *
# * main distribution.  By sending these changes to Fyodor or one of the    *
# * Insecure.Org development mailing lists, or checking them into the Nmap  *
# * source code repository, it is understood (unless you specify            *
# * otherwise) that you are offering the Nmap Project the unlimited,        *
# * non-exclusive right to reuse, modify, and relicense the code.  Nmap     *
# * will always be available Open Source, but this is important because     *
# * the inability to relicense code has caused devastating problems for     *
# * other Free Software projects (such as KDE and NASM).  We also           *
# * occasionally relicense the code to third parties as discussed above.    *
# * If you wish to specify special license conditions of your               *
# * contributions, just say so when you send them.                          *
# *                                                                         *
# * This program is distributed in the hope that it will be useful, but     *
# * WITHOUT ANY WARRANTY; without even the implied warranty of              *
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the Nmap      *
# * license file for more details (it's in a COPYING file included with     *
# * Nmap, and also available from https://svn.nmap.org/nmap/COPYING)        *
# *                                                                         *
# ***************************************************************************/

from radialnet.core.Graph import *
from radialnet.gui.RadialNet import NetNode
import zenmapCore.NmapParser

import math


COLORS = [(0.0, 1.0, 0.0),
          (1.0, 1.0, 0.0),
          (1.0, 0.0, 0.0)]

BASE_RADIUS = 5.5
NONE_RADIUS = 4.5


def set_node_info(node, host):
    """
    """
    node.set_host(host)

    radius = BASE_RADIUS + 2 * math.log(
            node.get_info("number_of_open_ports") + 1)

    node.set_draw_info({"color": COLORS[node.get_info("vulnerability_score")],
                        "radius": radius})


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

        return sorted(self.osmatches, key=osmatch_key)[0]

    hostnames = property(lambda self: self.hostname and [self.hostname] or [])


def find_hop_by_ttl(hops, ttl):
    assert ttl >= 0, "ttl must be non-negative"
    if ttl == 0:  # Same machine (i.e. localhost)
        return {"ipaddr": "127.0.0.1/8"}
    for h in hops:
        if ttl == int(h["ttl"]):
            return h
    return None


def make_graph_from_hosts(hosts):
    #hosts = parser.get_root().search_children('host', deep=True)
    graph = Graph()
    nodes = list()
    node_cache = {}
    ancestor_node_cache = {}
    descendant_node_cache = {}

    # Setting initial reference host
    main_node = NetNode()
    nodes.append(main_node)

    localhost = TracerouteHostInfo()
    localhost.ip = {"addr": "127.0.0.1/8", "type": "ipv4"}
    localhost.hostname = "localhost"
    main_node.set_host(localhost)
    main_node.set_draw_info(
            {"valid": True, "color": (0, 0, 0), "radius": NONE_RADIUS})

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
                    hop = find_hop_by_ttl(hops, ttl)
                    node = node_cache.get(hop["ipaddr"])
                    if node is None:
                        node = NetNode()
                        nodes.append(node)

                        hop_host = TracerouteHostInfo()
                        hop_host.ip = {
                                "addr": hop["ipaddr"],
                                "type": "",
                                "vendor": ""
                                }
                        node.set_draw_info({"valid": True})
                        node.set_draw_info({"color": (1, 1, 1),
                                            "radius": NONE_RADIUS})

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
                    # Add an "anonymous" node only if there isn't already a
                    # node equivalent to it (i.e. at same distance from the
                    # previous "real" node)

                    pre_hop = None
                    pre_hop_distance = 0
                    for i in range(1, ttl + 1):
                        pre_hop = find_hop_by_ttl(hops, ttl - i)
                        if pre_hop is not None:
                            pre_hop_distance = i
                            break

                    post_hop = None
                    post_hop_distance = 0
                    for i in range(1, max(ttls) - ttl):
                        post_hop = find_hop_by_ttl(hops, ttl + i)
                        if post_hop is not None:
                            post_hop_distance = i
                            break

                    assert pre_hop is not None, \
                            "pre_hop should have become localhost if nothing else"  # noqa

                    ancestor_key = (pre_hop["ipaddr"], pre_hop_distance)
                    descendant_key = None
                    if post_hop is not None:
                        descendant_key = \
                                (post_hop["ipaddr"], post_hop_distance)

                    if ancestor_key in ancestor_node_cache:
                        node = ancestor_node_cache[ancestor_key]
                    elif (descendant_key is not None and
                            descendant_key in descendant_node_cache):
                        node = descendant_node_cache[descendant_key]
                        graph.set_connection(node, prev_node)
                    else:
                        node = NetNode()
                        nodes.append(node)

                        node.set_draw_info({"valid": False})
                        node.set_draw_info(
                                {"color": (1, 1, 1), "radius": NONE_RADIUS})

                        graph.set_connection(node, prev_node)

                        ancestor_node_cache[ancestor_key] = node
                        if descendant_key is not None:
                            descendant_node_cache[descendant_key] = node

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

            node.set_draw_info({"no_route": True})

            graph.set_connection(node, endpoints[host])

        node.set_draw_info({"valid": True})
        node.set_draw_info({"scanned": True})
        set_node_info(node, host)
        node_cache[node.get_info("ip")] = node

    graph.set_nodes(nodes)
    graph.set_main_node(main_node)

    return graph


def make_graph_from_nmap_parser(parser):
    return make_graph_from_hosts(
            parser.get_root().search_children('host', deep=True))
