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

# This module parses the --script-args and stores in the form of key/value
# pairs. The logic is same as in nse_main.lua, except that values are not
# returned as tables but as strings.

import re
# "^%s*([^'\"%s{},=][^{},=]-)%s*[},=]"
unquoted_re = re.compile(r'\s*([^\'"\s{},=][^{},=]*?)\s*([},=]|$)')
# "^%s*(['\"])(.-[^\\])%1%s*[},=]"
quoted_re = re.compile(r'\s*(([\'"])(.*?[^\\])\2)\s*([},=]|$)')
# "^%s*(['\"])%1%s*[},=]"
empty_re = re.compile(r'\s*(([\'"])\2)\s*([},=]|$)')


def parse_string(s, start):
    """Parses a single string that is quoted, unquoted or empty. It returns the
    found string along with the next starting position """
    for pattern in unquoted_re, quoted_re, empty_re:
        m = pattern.match(s, start) or quoted_re.match(s, start)
        if m:
            return m.group(1), m.end(1)
        raise ValueError("No string found at %s." % repr(s[start:]))


def next_char(s, start):
    """Returns the next character and position in the string."""
    while start < len(s) and s[start].isspace():
        start += 1
    if start < len(s):
        return s[start], start
    else:
        return None, start


def parse_value(s, start):
    """If the string starting from start is a name-value pair, returns a
    name-value tuple. Otherwise returns a plain string."""
    nc, j = next_char(s, start)
    if nc == "{":
        j = parse_table(s, j)
        return s[start:j], j
    else:
        tmp, j = parse_string(s, j)
        nc, j = next_char(s, j)
        if nc == "=":
            # Key/value?
            j += 1
            begin = j
            nc, j = next_char(s, j)
            if nc == "{":
                j = parse_table(s, j)
            else:
                dummy, j = parse_string(s, j)
            return (tmp, s[begin:j]), j
        else:
            return s[start:j], j


def parse_table(s, start):
    """This function is responsible for parsing a table; i.e, a string that
    starts with '{'. It returns the position where the balancing pair of braces
    gets closed."""
    nc, j = next_char(s, start)
    if not nc or nc != "{":
        raise ValueError("No '{' found at %s." % repr(s[start:]))
    j += 1
    while True:
        nc, j = next_char(s, j)
        if nc == "}":
            # End of table.
            return j + 1
        else:
            # Replace this with a call to parse_value.
            v, j = parse_value(s, j)
            nc, j = next_char(s, j)
            if nc == ",":
                j += 1


def parse_script_args(s):
    """Main function responsible for parsing the script args and storing the
    name-value pairs in a list. If an invalid argument is present it stores the
    value as None."""
    args = []
    nc, j = next_char(s, 0)
    try:
        while nc is not None:
            val, j = parse_value(s, j)
            if type(val) == str:
                raise ValueError(
                        "Only name-value pairs expected in parse_script_args.")
            else:
                args.append(val)
            nc, j = next_char(s, j)
            if nc == ",":
                j += 1
                nc, j = next_char(s, j)
    except ValueError:
        return None
    return args


def parse_script_args_dict(raw_argument):
    """Wrapper function that copies the name-value pairs from a list into a
    dictionary."""
    args_dict = {}
    args = parse_script_args(raw_argument)
    if args is None:
        return None
    for item in args:
        if(len(item) == 2):  # only key/value pairs are stored
            args_dict[item[0]] = item[1]
    return args_dict

if __name__ == '__main__':
    TESTS = (
            ('', []),
            ('a=b,c=d', [('a', 'b'), ('c', 'd')]),
            ('a="b=c"', [('a', '"b=c"')]),
            ('a="def\\"ghi"', [('a', '"def\\"ghi"')]),
            ('a={one,{two,{three}}}', [('a', '{one,{two,{three}}}')]),
            ('a={"quoted}quoted"}', [('a', '{"quoted}quoted"}')]),
            ('a="unterminated', None),
            ('user=foo,pass=",{}=bar",whois={whodb=nofollow+ripe},'
                'userdb=C:\\Some\\Path\\To\\File',
                [('user', 'foo'), ('pass', '",{}=bar"'),
                    ('whois', '{whodb=nofollow+ripe}'),
                    ('userdb', 'C:\\Some\\Path\\To\\File')]),
                )

    for test, expected in TESTS:
        args_dict = parse_script_args_dict(test)
        print(args_dict)
        args = parse_script_args(test)
        if args == expected:
            print("PASS", test)
            continue
        print("FAIL", test)
        if args is None:
            print("Parsing error")
        else:
            print("%d args" % len(args))
            for a, v in args:
                print(a, "=", v)
        if expected is None:
            print("Expected parsing error")
        else:
            print("Expected %d args" % len(expected))
            for a, v in expected:
                print(a, "=", v)
