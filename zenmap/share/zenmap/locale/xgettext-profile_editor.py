#!/usr/bin/env python

# This program acts like xgettext, specialized to extract strings from Zenmap's
# profile_editor.xml file.

import getopt
import os
import sys
import xml.sax

directory = None

def escape(s):
    return '"' + s.encode("UTF-8").replace('"', '\\"') + '"'

def output_msgid(msgid, locator):
    print
    print u"#: %s:%d" % (locator.getSystemId(), locator.getLineNumber())
    print u"msgid", escape(msgid)
    print u"msgstr", escape(u"")

class Handler (xml.sax.handler.ContentHandler):
    def setDocumentLocator(self, locator):
        self.locator = locator

    def startElement(self, name, attrs):
        if name == u"group":
            output_msgid(attrs[u"name"], self.locator)
        if attrs.get(u"short_desc"):
            output_msgid(attrs[u"short_desc"], self.locator)
        if attrs.get(u"label"):
            output_msgid(attrs[u"label"], self.locator)

opts, filenames = getopt.gnu_getopt(sys.argv[1:], "D:", ["directory="])
for o, a in opts:
    if o == "-D" or o == "--directory":
        directory = a

if directory is not None:
    os.chdir(directory)

for fn in filenames:
    f = open(fn, "r")
    try:
        parser = xml.sax.make_parser()
        parser.setContentHandler(Handler())
        parser.parse(f)
    finally:
        f.close()

if len(filenames) < 2:
    parser = xml.sax.make_parser()
    parser.setContentHandler(Handler())
    parser.parse
