# vim: set fileencoding=utf-8 :

# ***********************IMPORTANT NMAP LICENSE TERMS************************
# *                                                                         *
# * The Nmap Security Scanner is (C) 1996-2016 Insecure.Com LLC. Nmap is    *
# * also a registered trademark of Insecure.Com LLC.  This program is free  *
# * software; you may redistribute and/or modify it under the terms of the  *
# * GNU General Public License as published by the Free Software            *
# * Foundation; Version 2 ("GPL"), BUT ONLY WITH ALL OF THE CLARIFICATIONS  *
# * AND EXCEPTIONS DESCRIBED HEREIN.  This guarantees your right to use,    *
# * modify, and redistribute this software under certain conditions.  If    *
# * you wish to embed Nmap technology into proprietary software, we sell    *
# * alternative licenses (contact sales@nmap.com).  Dozens of software      *
# * vendors already license Nmap technology such as host discovery, port    *
# * scanning, OS detection, version detection, and the Nmap Scripting       *
# * Engine.                                                                 *
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
# * As another special exception to the GPL terms, Insecure.Com LLC grants  *
# * permission to link the code of this program with any version of the     *
# * OpenSSL library which is distributed under a license identical to that  *
# * listed in the included docs/licenses/OpenSSL.txt file, and distribute   *
# * linked combinations including the two.                                  *
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
# * Nmap, and also available from https://svn.nmap.org/nmap/COPYING)        *
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
        if weight is not None:

            edge.add_weight(weight)

            mean_weight = edge.get_weights_mean()
            if (self.__min_edge_mean_value is None or
                    mean_weight < self.__min_edge_mean_value):
                self.__min_edge_mean_value = mean_weight
            if (self.__max_edge_mean_value is None or
                    mean_weight > self.__max_edge_mean_value):
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
