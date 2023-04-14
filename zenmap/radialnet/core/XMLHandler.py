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


# Prevent loading PyXML
import xml
xml.__path__ = [x for x in xml.__path__ if "_xmlplus" not in x]

import xml.sax
import xml.sax.saxutils
from xml.sax.xmlreader import AttributesImpl as Attributes


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
        return self.__attrs.get(attr)

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

                if attr in child.get_attrs():

                    c_value = child.get_attr(attr)

                    if c_value == value or c_value == str(value):
                        result.append(child)

            if deep:

                c_result = child.query_children(name, attr, value, first, deep)

                if c_result is not None:

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

                if c_result is not None and c_result != []:

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
        xml.sax.ContentHandler.__init__(self)
        self.__text = ""
        self.__status = []

        self.__file = file
        self.__root = None

        self.__parser = xml.sax.make_parser()
        self.__parser.setContentHandler(self)

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
        if self.__file is not None:
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
            node.add_attr(attr, attrs.get(attr).strip())

        # who is my father?
        if len(self.__status) > 0:
            self.__status[-1].add_child(node)

        if self.__root is None:
            self.__root = node

        self.__status.append(node)

    def endElement(self, name):
        """
        """
        self.__status[-1].set_text(self.__text.strip())

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
