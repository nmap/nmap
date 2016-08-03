#!/usr/bin/env python

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

# This module has two classes. ScriptDB is responsible for parsing the
# script.db file and fetching each script's name and categories.
# ScriptMetadata gets the description, categories, @usage, @output, and
# arguments from the script itself.

import re
import os
import sys

from zenmapCore.Paths import Path
from zenmapCore.UmitLogging import log


class ScriptDBSyntaxError(SyntaxError):
    """Exception raised when encountering a syntax error in the script.db"""
    pass


class ScriptDB (object):
    """Class responsible for parsing the script.db file, fetching script
    names and categories."""
    LUA_STRING_ESCAPES = {
        "a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r",
        "t": "\t", "v": "\v", "\\": "\\", "\"": "\"", "'": "'", "0": "\0"
    }

    def __init__(self, script_db_path=None):
        self.unget_buf = ""

        self.f = open(script_db_path, "r")
        self.lineno = 1
        self.line = ""
        try:
            self.entries_list = self.parse()
        finally:
            self.f.close()

    def syntax_error(self, message):
        e = ScriptDBSyntaxError(message)
        e.filename = self.f.name
        e.lineno = self.lineno
        e.offset = len(self.line)
        e.text = self.line
        return e

    def getchar(self):
        c = None
        if self.unget_buf:
            c = self.unget_buf[-1]
            self.unget_buf = self.unget_buf[:-1]
        else:
            c = self.f.read(1)
        if c == "\n":
            self.lineno += 1
            self.line = ""
        else:
            self.line += c
        return c

    def unget(self, data):
        if data:
            self.line = self.line[:-len(data)]
            self.unget_buf += data

    def parse(self):
        """Parses a script.db entry and returns it as a dictionary. An entry
        looks like this:
        Entry { filename = "afp-brute.nse", categories = \
                { "auth", "intrusive", } }
        """
        entries = []
        while True:
            entry = self.parse_entry()
            if not entry:
                break
            entries.append(entry)
        return entries

    def token(self):
        """Returns a tuple whose first element is a type ("string", "ident", or
        "delim") and whose second element is the token text."""
        c = self.getchar()
        while c.isspace():
            c = self.getchar()
        if not c:
            return None
        if c.isalpha() or c == "_":
            ident = []
            while c.isalpha() or c.isdigit() or c == "_":
                ident.append(c)
                c = self.getchar()
            self.unget(c)
            return ("ident", "".join(ident))
        elif c in "'\"":
            string = []
            begin_quote = c
            c = self.getchar()
            while c != begin_quote:
                if c == "\\":
                    repl = None
                    c = self.getchar()
                    if not c:
                        raise self.syntax_error("Unexpected EOF")
                    if c.isdigit():
                        d1 = c
                        d2 = self.getchar()
                        d3 = self.getchar()
                        if d1 and d2 and d3:
                            n = int(d1 + d2 + d3)
                            if n > 255:
                                raise self.syntax_error(
                                        "Character code >255")
                            repl = chr(n)
                        else:
                            self.unget(d3)
                            self.unget(d2)
                    if not repl:
                        repl = self.LUA_STRING_ESCAPES.get(c)
                    if not repl:
                        raise self.syntax_error("Unhandled string escape")
                    c = repl
                string.append(c)
                c = self.getchar()
            return ("string", "".join(string))
        elif c in "{},=":
            return ("delim", c)
        else:
            raise self.syntax_error("Unknown token")

    def expect(self, tokens):
        for token in tokens:
            t = self.token()
            if t != token:
                raise self.syntax_error(
                        "Unexpected token '%s', expected '%s'" % (
                            t[1], token[1]))

    def parse_entry(self):
        entry = {}
        token = self.token()
        if not token:
            return None
        self.expect((("delim", "{"), ("ident", "filename"), ("delim", "=")))
        token = self.token()
        if not token or token[0] != "string":
            raise self.syntax_error("Unexpected non-string token or EOF")
        entry["filename"] = token[1]
        self.expect((("delim", ","), ("ident", "categories"),
            ("delim", "="), ("delim", "{")))
        entry["categories"] = []
        token = self.token()
        if token and token[0] == "string":
            entry["categories"].append(token[1])
        token = self.token()
        while token == ("delim", ","):
            token = self.token()
            if token and token[0] == "string":
                entry["categories"].append(token[1])
            else:
                break
            token = self.token()
        if token != ("delim", "}"):
            raise self.syntax_error(
                    "Unexpected token '%s', expected '}'" % (token[1]))
        token = self.token()
        if token == ("delim", ","):
            token = self.token()
        if token != ("delim", "}"):
            raise self.syntax_error(
                    "Unexpected token '%s', expected '}'" % (token[1]))
        return entry

    def get_entries_list(self):
        return self.entries_list


def nsedoc_tags_iter(f):
    in_doc_comment = False
    tag_name = None
    tag_text = None
    for line in f:
        # New LuaDoc comment?
        if re.match(r'^\s*---', line):
            in_doc_comment = True
        if not in_doc_comment:
            continue
        # New LuaDoc tag?
        m = re.match(r'^\s*--+\s*@(\w+)\s*(.*)', line, re.S)
        if m:
            if tag_name:
                yield tag_name, tag_text
            tag_name = None
            tag_text = None
            tag_name = m.group(1)
            tag_text = m.group(2)
        else:
            # Still in comment?
            m = re.match(r'^\s*--+\s*(.*)', line)
            if m:
                # Add to text if we're in a tag.
                if tag_name:
                    tag_text += m.group(1) + "\n"
            else:
                in_doc_comment = False
                if tag_name:
                    yield tag_name, tag_text
                tag_name = None
                tag_text = None


class ScriptMetadata (object):
    """Class responsible for parsing all the script information."""

    class Entry (object):
        """An instance of this class is used to store all the information
        related to a particular script."""
        def __init__(self, filename):
            self.filename = filename
            self.categories = []
            self.arguments = []  # Arguments including library arguments.
            self.license = ""
            self.author = []
            self.description = ""
            self.output = ""
            self.usage = ""

        url = property(lambda self: "https://nmap.org/nsedoc/scripts/"
                "%s.html" % (os.path.splitext(self.filename)[0]))

    def __init__(self, scripts_dir, nselib_dir):
        self.scripts_dir = scripts_dir
        self.nselib_dir = nselib_dir
        self.library_arguments = {}
        self.library_requires = {}
        self.construct_library_arguments()

    def get_metadata(self, filename):
        entry = self.Entry(filename)
        entry.description = self.get_string_variable(filename, "description")
        entry.arguments = self.get_arguments(entry.filename)
        entry.license = self.get_string_variable(filename, "license")
        entry.author = self.get_list_variable(filename, "author") or [
                self.get_string_variable(filename, "author")]

        filepath = os.path.join(self.scripts_dir, filename)
        f = open(filepath, "r")
        try:
            for tag_name, tag_text in nsedoc_tags_iter(f):
                if tag_name == "output" and not entry.output:
                    entry.output = tag_text
                elif tag_name == "usage" and not entry.usage:
                    entry.usage = tag_text
        finally:
            f.close()

        return entry

    @staticmethod
    def get_file_contents(filename):
        f = open(filename, "r")
        try:
            contents = f.read()
        finally:
            f.close()
        return contents

    def get_string_variable(self, filename, varname):
        contents = ScriptMetadata.get_file_contents(
            os.path.join(self.scripts_dir, filename))
        # Short string?
        m = re.search(
            re.escape(varname) + r'\s*=\s*(["\'])(.*?[^\\])\1', contents)
        if m:
            return m.group(2)
        # Long string?
        m = re.search(
            re.escape(varname) + r'\s*=\s*\[(=*)\[(.*?)\]\1\]', contents, re.S)
        if m:
            return m.group(2)
        return None

    def get_list_variable(self, filename, varname):
        contents = ScriptMetadata.get_file_contents(
            os.path.join(self.scripts_dir, filename))
        m = re.search(
            re.escape(varname) + r'\s*=\s*\{(.*?)}', contents)
        if not m:
            return None
        strings = m.group(1)
        out = []
        for m in re.finditer(r'(["\'])(.*?[^\\])\1\s*,?', strings, re.S):
            out.append(m.group(2))
        return out

    @staticmethod
    def get_requires(filename):
        f = open(filename, "r")
        try:
            requires = ScriptMetadata.get_requires_from_file(f)
        finally:
            f.close()
        return requires

    @staticmethod
    def get_requires_from_file(f):
        require_expr = re.compile(r'.*\brequire\s*\(?([\'\"])([\w._-]+)\1\)?')
        requires = []
        for line in f.readlines():
            m = require_expr.match(line)
            if m:
                requires.append(m.group(2))
        return requires

    @staticmethod
    def get_script_args(filename):
        f = open(filename, "r")
        try:
            args = ScriptMetadata.get_script_args_from_file(f)
        finally:
            f.close()
        return args

    @staticmethod
    def get_script_args_from_file(f):
        """Extracts a list of script arguments from the file given. Results are
        returned as a list of (argname, description) tuples."""
        args = []
        for tag_name, tag_text in nsedoc_tags_iter(f):
            m = re.match(r'([\w._-]+)', tag_text)
            if (tag_name == "arg" or tag_name == "args") and m:
                args.append((m.group(1), re.sub(r'^[\w._-]+', '', tag_text)))
        return args

    def get_arguments(self, filename):
        """Returns list of arguments including library arguments on
        passing the file name."""
        filepath = os.path.join(self.scripts_dir, filename)
        script_args = self.get_script_args(filepath)

        # Recursively walk through the libraries required by the script (and
        # the libraries they require, etc.), adding all arguments.
        library_args = []
        seen = set()
        pool = set(self.get_requires(filepath))
        while pool:
            require = pool.pop()
            if require in seen:
                continue
            seen.add(require)
            sub_requires = self.library_requires.get(require)
            if sub_requires:
                pool.update(set(sub_requires))
            require_args = self.library_arguments.get(require)
            if require_args:
                library_args += require_args

        return script_args + library_args

    def construct_library_arguments(self):
        """Constructs a dictionary of library arguments using library
        names as keys and arguments as values. Each argument is really a
        (name, description) tuple."""
        for filename in os.listdir(self.nselib_dir):
            filepath = os.path.join(self.nselib_dir, filename)
            if not os.path.isfile(filepath):
                continue

            base, ext = os.path.splitext(filename)
            if ext == ".lua" or ext == ".luadoc":
                libname = base
            else:
                libname = filename

            self.library_arguments[libname] = self.get_script_args(filepath)
            self.library_requires[libname] = self.get_requires(filepath)


def get_script_entries(scripts_dir, nselib_dir):
    """Merge the information obtained so far into one single entry for
    each script and return it."""
    metadata = ScriptMetadata(scripts_dir, nselib_dir)
    try:
        scriptdb = ScriptDB(os.path.join(scripts_dir, "script.db"))
    except IOError:
        return []
    entries = []
    for dbentry in scriptdb.get_entries_list():
        entry = metadata.get_metadata(dbentry["filename"])
        # Categories is the only thing ScriptMetadata doesn't take care of.
        entry.categories = dbentry["categories"]
        entries.append(entry)
    return entries

if __name__ == '__main__':
    import sys
    for entry in get_script_entries(sys.argv[1], sys.argv[2]):
        print "*" * 75
        print "Filename:", entry.filename
        print "Categories:", entry.categories
        print "License:", entry.license
        print "Author:", entry.author
        print "URL:", entry.url
        print "Description:", entry.description
        print "Arguments:", [x[0] for x in entry.arguments]
        print "Output:"
        print entry.output
        print "Usage:"
        print entry.usage
        print "*" * 75
