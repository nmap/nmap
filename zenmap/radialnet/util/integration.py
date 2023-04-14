# vim: set fileencoding=utf-8 :

# ***********************IMPORTANT NMAP LICENSE TERMS************************
# *
# * The Nmap Security Scanner is (C) 1996-2023 Nmap Software LLC ("The Nmap
# * Project"). Nmap is also a registered trademark of the Nmap Project.
# *
# * This program is distributed under the terms of the Nmap Public Source
# * License (NPSL). The exact license text applying to a particular Nmap
# * release or source code control revision is contained in the LICENSE
# * file distributed with that version of Nmap or source code control
# * revision. More Nmap copyright/legal information is available from
# * https://nmap.org/book/man-legal.html, and further information on the
# * NPSL license itself can be found at https://nmap.org/npsl/ . This
# * header summarizes some key points from the Nmap license, but is no
# * substitute for the actual license text.
# *
# * Nmap is generally free for end users to download and use themselves,
# * including commercial use. It is available from https://nmap.org.
# *
# * The Nmap license generally prohibits companies from using and
# * redistributing Nmap in commercial products, but we sell a special Nmap
# * OEM Edition with a more permissive license and special features for
# * this purpose. See https://nmap.org/oem/
# *
# * If you have received a written Nmap license agreement or contract
# * stating terms other than these (such as an Nmap OEM license), you may
# * choose to use and redistribute Nmap under those terms instead.
# *
# * The official Nmap Windows builds include the Npcap software
# * (https://npcap.com) for packet capture and transmission. It is under
# * separate license terms which forbid redistribution without special
# * permission. So the official Nmap Windows builds may not be redistributed
# * without special permission (such as an Nmap OEM license).
# *
# * Source is provided to this software because we believe users have a
# * right to know exactly what a program is going to do before they run it.
# * This also allows you to audit the software for security holes.
# *
# * Source code also allows you to port Nmap to new platforms, fix bugs, and add
# * new features. You are highly encouraged to submit your changes as a Github PR
# * or by email to the dev@nmap.org mailing list for possible incorporation into
# * the main distribution. Unless you specify otherwise, it is understood that
# * you are offering us very broad rights to use your submissions as described in
# * the Nmap Public Source License Contributor Agreement. This is important
# * because we fund the project by selling licenses with various terms, and also
# * because the inability to relicense code has caused devastating problems for
# * other Free Software projects (such as KDE and NASM).
# *
# * The free version of Nmap is distributed in the hope that it will be
# * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Warranties,
# * indemnification and commercial support are all available through the
# * Npcap OEM program--see https://nmap.org/oem/
# *
# ***************************************************************************/

from radialnet.core.Graph import Graph
from radialnet.gui.RadialNet import NetNode

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
