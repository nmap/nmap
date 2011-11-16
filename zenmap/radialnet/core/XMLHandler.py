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

import xml.sax
import xml.sax.saxutils
from xml.sax.xmlreader import AttributesImpl as Attributes



def convert_to_utf8(text):
    """
    """
    return text.encode('utf8', 'replace')



class XMLNode:
    """
    """
    def __init__(self, name):
        """
        """
        self.__name = name
        self.__text = ""
        self.__attrs = dict()
        self.__children = []


    def set_text(self, text):
        """
        """
        self.__text = text


    def get_text(self):
        """
        """
        return self.__text


    def set_name(self, name):
        """
        """
        self.__name = name


    def get_name(self):
        """
        """
        return self.__name


    def add_attr(self, key, value):
        """
        """
        self.__attrs[key] = value


    def add_child(self, child):
        """
        """
        self.__children.append(child)


    def get_keys(self):
        """
        """
        return self.__attrs.keys()


    def get_attr(self, attr):
        """
        """
        if self.__attrs.has_key(attr):
            return self.__attrs[attr]

        return None


    def get_attrs(self):
        """
        """
        return self.__attrs


    def get_children(self):
        """
        """
        return self.__children


    def query_children(self, name, attr, value, first=False, deep=False):
        """
        """
        result = []

        for child in self.__children:

            if child.get_name() == name:

                if child.get_attrs().has_key(attr):

                    c_value = child.get_attr(attr)

                    if c_value == value or c_value == str(value):
                        result.append(child)

            if deep:

                c_result = child.query_children(name, attr, value, first, deep)

                if c_result != None:

                    if first:
                        return c_result

                    else:
                        result.extend(c_result)

        if first and len(result) > 0:
            return result[0]

        if first:
            return None

        return result


    def search_children(self, name, first=False, deep=False):
        """
        """
        result = []

        for child in self.__children:

            if child.get_name() == name:

                result.append(child)

                if first:
                    return result[0]

            if deep:

                c_result = child.search_children(name, first, deep)

                if c_result != None and c_result != []:

                    if first:
                        return c_result

                    else:
                        result.extend(c_result)

        if first:
            return None

        return result



class XMLWriter(xml.sax.saxutils.XMLGenerator):
    """
    """
    def __init__(self, file, root=None, encoding="utf-8"):
        """
        """
        xml.sax.saxutils.XMLGenerator.__init__(self, file, encoding)

        self.__root = root


    def set_root(self, root):
        """
        """
        self.__root = root


    def write(self):
        """
        """
        self.startDocument()
        self.write_xml_node([self.__root])
        self.endDocument()


    def write_xml_node(self, root):
        """
        """
        for child in root:

            self.startElement(child.get_name(), Attributes(child.get_attrs()))

            if child.get_text() != "":
                self.characters(child.get_text())

            self.write_xml_node(child.get_children())

            self.endElement(child.get_name())



class XMLReader(xml.sax.ContentHandler):
    """
    """
    def __init__(self, file=None):
        """
        """
        self.__text = ""
        self.__status = []

        self.__file = file
        self.__root = None

        self.__parser = xml.sax.make_parser();
        self.__parser.setContentHandler(self);


    def set_file(self, file, root):
        """
        """
        self.__file = file


    def get_file(self):
        """
        """
        return self.__file


    def get_root(self):
        """
        """
        return self.__root


    def parse(self):
        """
        """
        if self.__file != None:
            self.__parser.parse(self.__file)


    def startDocument(self):
        """
        """
        pass


    def startElement(self, name, attrs):
        """
        """
        # create new node
        node = XMLNode(name)

        # putting attributes and values in node
        for attr in attrs.getNames():
            node.add_attr(attr, convert_to_utf8(attrs.get(attr).strip()))

        # who is my father?
        if len(self.__status) > 0:
            self.__status[-1].add_child(node)

        if self.__root == None:
            self.__root = node

        self.__status.append(node)


    def endElement(self, name):
        """
        """
        self.__status[-1].set_text(convert_to_utf8(self.__text.strip()))

        self.__text = ""
        self.__status.pop()


    def endDocument(self):
        """
        """
        pass


    def characters(self, text):
        """
        """
        self.__text += text



if __name__ == "__main__":

    import sys

    reader = XMLReader(sys.argv[1])
    reader.parse()

    root = reader.get_root()

    writer = XMLWriter(open("test.xml", 'w'), root)
    writer.write()
