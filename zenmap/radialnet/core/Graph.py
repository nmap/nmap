# vim: set fileencoding=utf-8 :

# ***********************IMPORTANT NMAP LICENSE TERMS************************
# *                                                                         *
# * The Nmap Security Scanner is (C) 1996-2011 Insecure.Com LLC. Nmap is    *
# * also a registered trademark of Insecure.Com LLC.  This program is free  *
# * software; you may redistribute and/or modify it under the terms of the  *
# * GNU General Public License as published by the Free Software            *
# * Foundation; Version 2 with the clarifications and exceptions described  *
# * below.  This guarantees your right to use, modify, and redistribute     *
# * this software under certain conditions.  If you wish to embed Nmap      *
# * technology into proprietary software, we sell alternative licenses      *
# * (contact sales@insecure.com).  Dozens of software vendors already       *
# * license Nmap technology such as host discovery, port scanning, OS       *
# * detection, and version detection.                                       *
# *                                                                         *
# * Note that the GPL places important restrictions on "derived works", yet *
# * it does not provide a detailed definition of that term.  To avoid       *
# * misunderstandings, we consider an application to constitute a           *
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
# * works of Nmap.  This list is not exclusive, but is meant to clarify our *
# * interpretation of derived works with some common examples.  Our         *
# * interpretation applies only to Nmap--we don't speak for other people's  *
# * GPL works.                                                              *
# *                                                                         *
# * If you have any questions about the GPL licensing restrictions on using *
# * Nmap in non-GPL works, we would be happy to help.  As mentioned above,  *
# * we also offer alternative license to integrate Nmap into proprietary    *
# * applications and appliances.  These contracts have been sold to dozens  *
# * of software vendors, and generally include a perpetual license as well  *
# * as providing for priority support and updates as well as helping to     *
# * fund the continued development of Nmap technology.  Please email        *
# * sales@insecure.com for further information.                             *
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
# * to nmap-dev@insecure.org for possible incorporation into the main       *
# * distribution.  By sending these changes to Fyodor or one of the         *
# * Insecure.Org development mailing lists, it is assumed that you are      *
# * offering the Nmap Project (Insecure.Com LLC) the unlimited,             *
# * non-exclusive right to reuse, modify, and relicense the code.  Nmap     *
# * will always be available Open Source, but this is important because the *
# * inability to relicense code has caused devastating problems for other   *
# * Free Software projects (such as KDE and NASM).  We also occasionally    *
# * relicense the code to third parties as discussed above.  If you wish to *
# * specify special license conditions of your contributions, just say so   *
# * when you send them.                                                     *
# *                                                                         *
# * This program is distributed in the hope that it will be useful, but     *
# * WITHOUT ANY WARRANTY; without even the implied warranty of              *
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU       *
# * General Public License v2.0 for more details at                         *
# * http://www.gnu.org/licenses/gpl-2.0.html , or in the COPYING file       *
# * included with Nmap.                                                     *
# *                                                                         *
# ***************************************************************************/


class Node(object):
    """
    Node class
    """
    def __init__(self):
        """
        Constructor method of Node class
        @type  : integer
        @param : Node identifier
        """
        self.__data = None
        """User-controlled data pointer"""
        self.__edges = []
        """List of edges to other nodes"""


    def get_data(self):
        return self.__data


    def set_data(self, data):
        self.__data = data


    def get_edge(self, dest):
        """
        Return the edge connecting to dest, or None if none
        """
        for edge in self.__edges:
            if dest in edge.get_nodes():
                return edge
        return None


    def get_edges(self):
        """
        Return the list of edges
        """
        return self.__edges


    def add_edge(self, edge):
        self.__edges.append(edge)



class Edge:
    """
    """
    def __init__(self, nodes):
        """
        """
        self.__weights = []
        self.__nodes = nodes
        self.__weights_mean = None


    def get_nodes(self):
        """
        """
        return self.__nodes


    def get_weights(self):
        """
        """
        return self.__weights


    def set_weights(self, weights):
        """
        """
        self.__weights = weights
        self.__weights_mean = sum(self.__weights) / len(self.__weights)


    def add_weight(self, weight):
        """
        """
        self.__weights.append(weight)
        self.__weights_mean = sum(self.__weights) / len(self.__weights)


    def get_weights_mean(self):
        """
        """
        return self.__weights_mean




class Graph:
    """
    Network Graph class
    """

    def __init__(self):
        """
        Constructor method of Graph class
        @type  : list
        @param : List of nodes
        """
        self.__main_node = None
        self.__nodes = []
        self.__max_edge_mean_value = None
        self.__min_edge_mean_value = None


    def set_nodes(self, nodes):
        """
        """
        self.__nodes = nodes


    def get_nodes(self):
        """
        """
        return self.__nodes


    def get_number_of_nodes(self):
        """
        Get the number of nodes in graph
        @rtype: number
        @return: The number of nodes in the graph
        """
        return len(self.__nodes)


    def set_main_node(self, node):
        """
        Set the main node
        @type  : number
        @param : The node
        """
        self.__main_node = node


    def get_main_node(self):
        """
        Get the main node
        @rtype: Node
        @return: The main node
        """
        return self.__main_node


    def set_connection(self, a, b, weight=None):
        """
        Set node connections
        @type  : list
        @param : List of connections
        """

        # if is a new connection make it
        edge = a.get_edge(b)
        if edge is None:
            edge = Edge((a, b))
            a.add_edge(edge)
            b.add_edge(edge)

        # then add new weight value
        if weight != None:

            edge.add_weight(weight)

            mean_weight = edge.get_weights_mean()
            if self.__min_edge_mean_value is None or mean_weight < self.__min_edge_mean_value:
                self.__min_edge_mean_value = mean_weight
            if self.__max_edge_mean_value is None or mean_weight > self.__max_edge_mean_value:
                self.__max_edge_mean_value = mean_weight


    def get_edges(self):
        """
        An iterator that yields all edges
        """
        for node in self.__nodes:
            for edge in node.get_edges():
                if edge.get_nodes()[0] == node:
                    yield edge


    def get_node_connections(self, node):
        """
        """
        connections = []

        for edge in node.get_edges():

            (a, b) = edge.get_nodes()

            if a == node:
                connections.append(b)
            if b == node:
                connections.append(a)

        return connections


    def get_max_edge_mean_weight(self):
        """
        """
        return self.__max_edge_mean_value


    def get_min_edge_mean_weight(self):
        """
        """
        return self.__min_edge_mean_value


