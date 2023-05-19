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
