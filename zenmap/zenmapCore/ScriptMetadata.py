#!/usr/bin/env python3

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

# This module has two classes. ScriptDB is responsible for parsing the
# script.db file and fetching each script's name and categories.
# ScriptMetadata gets the description, categories, @usage, @output, and
# arguments from the script itself.

import re
import os
import sys


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

        self.lineno = 1
        self.line = ""
        with open(script_db_path, "r") as self.f:
            self.entries_list = self.parse()

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
        try:
            entry.description = self.get_string_variable(filename, "description")
            entry.arguments = self.get_arguments(entry.filename)
            entry.license = self.get_string_variable(filename, "license")
            entry.author = self.get_list_variable(filename, "author") or [
                    self.get_string_variable(filename, "author")]

            filepath = os.path.join(self.scripts_dir, filename)
            with open(filepath, "r") as f:
                for tag_name, tag_text in nsedoc_tags_iter(f):
                    if tag_name == "output" and not entry.output:
                        entry.output = tag_text
                    elif tag_name == "usage" and not entry.usage:
                        entry.usage = tag_text
        except IOError as e:
            entry.description = "Error getting metadata: {}".format(e)

        return entry

    @staticmethod
    def get_file_contents(filename):
        with open(filename, "r") as f:
            contents = f.read()
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
        with open(filename, "r") as f:
            requires = ScriptMetadata.get_requires_from_file(f)
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
        with open(filename, "r") as f:
            args = ScriptMetadata.get_script_args_from_file(f)
        return args

    @staticmethod
    def get_script_args_from_file(f):
        """Extracts a list of script arguments from the file given. Results are
        returned as a list of (argname, description) tuples."""
        args = []
        for tag_name, tag_text in nsedoc_tags_iter(f):
            m = re.match(r'(\S+)\s+(.*?)', tag_text, re.DOTALL)
            if (tag_name == "arg" or tag_name == "args") and m:
                args.append((m.group(1), m.group(2)))
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
        print("*" * 75)
        print("Filename:", entry.filename)
        print("Categories:", entry.categories)
        print("License:", entry.license)
        print("Author:", entry.author)
        print("URL:", entry.url)
        print("Description:", entry.description)
        print("Arguments:", [x[0] for x in entry.arguments])
        print("Output:")
        print(entry.output)
        print("Usage:")
        print(entry.usage)
        print("*" * 75)
