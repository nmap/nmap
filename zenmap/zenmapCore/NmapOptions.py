#!/usr/bin/env python3

# This is an Nmap command line parser. It has two main parts:
#
#   getopt_long_only_extras, which is like getopt_long_only with robust
#   handling of unknown options.
#
#   NmapOptions, a class representing a set of Nmap options.
#
# NmapOptions is the class for external use. NmapOptions.parse parses a list of
# a command followed by command-line arguments. NmapOptions.render returns a
# list of of a command followed by arguments. NmapOptions.parse_string and
# NmapOptions.render_string first split strings into lists, following certain
# quoting rules.
#
# >>> ops = NmapOptions()
# >>> ops.parse(["nmap", "-v", "--script", "safe", "localhost"])
# >>> ops.executable
# 'nmap'
# >>> ops.target_specs
# ['localhost']
# >>> ops["-v"]
# 1
# >>> ops["--script"]
# 'safe'
#
# The command line may be modified by accessing member variables:
#
# >>> ops.executable = "C:\Program Files\Nmap\nmap.exe"
# >>> ops["-v"] = 2
# >>> ops["-oX"] = "output.xml"
# >>> ops.render()
# ['C:\\Program Files\\Nmap\\nmap.exe', '-v', '-v', '-oX', 'output.xml',
#  '--script', 'safe', 'localhost']
# >>> ops.render_string()
# '"C:\\Program Files\\Nmap\\nmap.exe" -v -v -oX output.xml\
#  --script safe localhost'
#
# A primary design consideration was robust handling of unknown options. That
# gives this code a degree of independence from Nmap's own list of options. If
# an option is added to Nmap but not added here, that option is treated as an
# "extra," an uninterpreted string that is inserted verbatim into the option
# list. Because the unknown option may or may not take an argument, pains are
# taken to avoid interpreting any option ambiguously.
#
# Consider the following case, where -x is an unknown option:
#   nmap -x -e eth0 scanme.nmap.org
# If -x, whatever it is, does not take an argument, it is equivalent to
#   nmap -e eth0 scanme.nmap.org -x
# that is, a scan of scanme.nmap.org over interface eth0. But if it does take
# an argument, its argument is "-e", and the command line is the same as
#   nmap eth0 scanme.nmap.org -x -e
# which is a scan of the two hosts eth0 and scanme.nmap.org, over the default
# interface. In either case scanme.nmap.org is a target but the other arguments
# are ambiguous. To resolve this, once an unknown option is found, all
# following arguments that can be interpreted ambiguously are removed with it
# and placed in the extras, with normal option processing resumed only when
# there is no more ambiguity. This ensures that such options maintain their
# relative order when rendered again to output. In this example "-x -e eth0"
# will always appear in that order, and the -e option will be uninterpreted.
#
# To add a new option, one should do the following:
# 1) Add a test case to the NmapOptionsTest::test_options() method for the new
#    option and make sure it initially fails.
# 2) Add the new option to NmapOptions.SHORT_OPTIONS and/or
#    NmapOptions.LONG_OPTIONS.
# 3) Add an appropriate case to NmapOptions::handle_result(). This should
#    include a line something like
#      self[opt] = True
#    or, if the option has an argument 'arg':
#      self[opt] = arg
# 4) Add an appropriate case to NmapOptions::render()
#    This should include a check to make sure the option was set in
#    handle_result:
#      if self[opt]:
#    or, if self[opt] contains arguments
#      if self[opt] is not None:
#    If the check passed, then opt should be added to opt_list.
# 5) Edit profile_editor.xml to display the new option in the GUI.
# 6) Depending on the option, one may need to edit
#    get_option_check_auxiliary_widget in OptionBuilder.py.
# 7) Make sure the test case works now.

from functools import reduce

from enum import Enum
from typing import Iterable


class ArgType(Enum):
    NO_ARGUMENT = 0
    REQUIRED_ARGUMENT = 1
    OPTIONAL_ARGUMENT = 2


class Option:
    """A single option, part of a pool of potential options. It's just a name
    and a flag saying if the option takes no argument, if an argument is
    optional, or if an argument is required."""

    def __init__(self, name: str, has_arg: ArgType, *aliases,
            convert=lambda x: x):
        self.name = name
        self.has_arg = has_arg
        self.aliases = aliases
        self.convert = convert
        if len(name) <= 2:
            self.prefix = "-"
        else:
            self.prefix = "--"

    def __repr__(self):
        return "{}('{}', {})".format(
                type(self).__name__, self.name, self.has_arg.name)

    def handle(self, arg, options_d: dict, extras: list):
        if arg is None:
            if self.has_arg == ArgType.REQUIRED_ARGUMENT:
                extras.append(self.optname())
                return
            else:
                arg = True
        if self not in options_d:
            try:
                options_d[self] = self.convert(arg)
                return
            except ValueError:
                pass
        if arg is True:
            extras.append(self.optname(arg))
        elif self.has_arg == ArgType.OPTIONAL_ARGUMENT:
            extras.append(self.optname(arg) + arg)
        else:
            extras.extend((self.optname(arg), arg))

    def get(self, arg, options_d: dict):
        return options_d.get(self, None)

    def optname(self, arg=None):
        return self.prefix + self.name

    def toargv(self, arg, options_d: dict):
        if self.has_arg == ArgType.NO_ARGUMENT:
            return (self.optname(),)
        else:
            oarg = self.get(arg, options_d)
            if oarg is None:
                oarg = arg
            if oarg is True:
                return (self.optname(),)
            elif self.has_arg == ArgType.OPTIONAL_ARGUMENT:
                return (self.optname(arg) + str(arg),)
            else:
                return (self.optname(), str(oarg))


class ScantypeOption(Option):
    def handle(self, arg, options_d: dict, extras: list):
        assert arg is not None
        scantypes = options_d.get(self, set())
        for scantype in arg:
            if scantype == 'P':
                scantype = 'n'
            if scantype in "ACFLMNORSTUVWXYZn":
                scantypes.add(scantype)
            else:
                extras.append(self.optname(arg))
        options_d[self] = scantypes

    def get(self, arg, options_d: dict):
        if not arg:
            return None
        try:
            scantypes = options_d[self]
        except KeyError:
            return None
        arg = arg.replace('P', 'n')
        return all(t in scantypes for t in arg)

    def optname(self, arg):
        return self.prefix + self.name + arg

    def toargv(self, arg, options_d: dict):
        argv = []
        for scantype in arg:
            argv.append(self.optname(scantype))
        return tuple(argv)


class PingtypeOption(Option):
    mapping = {
            '': 'E', 'I': 'E',
            '0': 'n', 'D': 'n', 'N': 'n',
            'T': 'A'
            }

    def pingtype(self, arg):
        pingtype = 'E'
        rest = True
        if arg is not None and len(arg) > 0:
            pingtype = PingtypeOption.mapping.get(arg[0], arg[0])
            rest = arg[1:]
        return pingtype, rest

    def handle(self, arg, options_d: dict, extras: list):
        pingtype, rest = self.pingtype(arg)
        pingtypes = options_d.get(self, {})
        if pingtype in "nEMPRSAUOBY":
            pingtypes[pingtype] = rest
        else:
            extras.append(self.optname(arg))
        options_d[self] = pingtypes

    def get(self, arg, options_d: dict):
        pingtype, rest = self.pingtype(arg)
        try:
            pingtypes = options_d[self]
            return pingtypes[pingtype]
        except KeyError:
            return None

    def optname(self, arg):
        pingtype, rest = self.pingtype(arg)
        return self.prefix + self.name + pingtype

    def toargv(self, arg, options_d: dict):
        ports = self.get(arg, options_d)
        if ports is None or ports is True:
            return (self.optname(arg),)
        else:
            return (self.optname(arg) + ports,)


class CounterOption(Option):
    def handle(self, arg, options_d: dict, extras: list):
        if arg is None:
            arg = ""
        try:
            value = int(arg)
            if value == 0:
                value = -1
        except ValueError:
            if reduce(lambda x, y: x and y,
                    [z == self.name for z in arg], True):
                value = options_d.get(self, 0)
                value += len(arg) + 1
            else:
                extras.append(self.prefix + self.name + arg)
                return
        options_d[self] = value

    def toargv(self, arg, options_d: dict):
        if self.has_arg == ArgType.NO_ARGUMENT:
            return (self.optname(),)
        else:
            oarg = self.get(arg, options_d)
            if oarg is None:
                try:
                    oarg = int(arg)
                except ValueError:
                    return (self.optname(),)
            return (self.prefix + (self.name * oarg),)


class TimingOption(Option):
    TIMING_PROFILE = {
        "paranoid": 0, "sneaky": 1, "polite": 2,
        "normal": 3, "aggressive": 4, "insane": 5
    }

    def handle(self, arg, options_d: dict, extras: list):
        assert arg is not None
        try:
            options_d[self] = int(arg)
        except ValueError:
            try:
                options_d[self] = TimingOption.TIMING_PROFILE[arg.lower()]
            except KeyError:
                extras.extend(("-T", arg))


def timespec(value: str):
    intval = -1
    try:
        if value.endswith("ms"):
            intval = int(value[:-2])
        elif value[-1] in "hms":
            intval = int(value[:-1])
        else:
            intval = int(value)
    except IndexError, ValueError:
        raise ValueError("not a timespec: {}".format(value))
    if intval < 0:
        raise ValueError("timespec cannot be negative: {}".format(value))
    return value


class PrefixStatus(Enum):
    NOT_A_PREFIX = "not_a_prefix"
    EXACT_MATCH = "exact_match"
    UNIQUE_PREFIX = "unique_prefix"
    MULTIPLE_PREFIXES = "multiple_prefixes"


class TrieNode:
    def __init__(self):
        self.children = {}
        self.value = None    # True if an entire string ends at this node
        self.word_count = 0  # Number of strings that pass through this node


class PrefixMatcher:
    def __init__(self, strings: Iterable[str] = None):
        self.root = TrieNode()
        if strings:
            for s in set(strings):  # Deduplicate input strings
                self._insert(s)

    def _insert(self, word: str, value=True):
        node = self.root
        node.word_count += 1
        for char in word:
            if char not in node.children:
                node.children[char] = TrieNode()
            node = node.children[char]
            node.word_count += 1
        if node.value is not None:
            raise ValueError("Duplicate PrefixMatcher entry: {}".format(word))
        node.value = value

    def add_string(self, word: str, value=True):
        """Dynamically add a new string to the matcher."""
        self._insert(word, value)

    def get_item(self, query: str):
        node = self.root
        for char in query:
            if char not in node.children:
                return PrefixStatus.NOT_A_PREFIX, None
            node = node.children[char]

        if node.value:
            return PrefixStatus.EXACT_MATCH, node.value

        if node.word_count == 1:
            while node.value is None:
                node, = node.children.values()
            return PrefixStatus.UNIQUE_PREFIX, node.value
        elif node.word_count > 1:
            return PrefixStatus.MULTIPLE_PREFIXES, None

        return PrefixStatus.NOT_A_PREFIX, None

    def get_status(self, query: str):
        return self.get_item(query)[0]


LONG_OPTIONS = (
        Option('6', ArgType.NO_ARGUMENT),
        Option('A', ArgType.NO_ARGUMENT),
        Option("allports", ArgType.NO_ARGUMENT),
        Option("append-output", ArgType.NO_ARGUMENT),
        Option('b', ArgType.REQUIRED_ARGUMENT),
        Option("badsum", ArgType.NO_ARGUMENT),
        Option('D', ArgType.REQUIRED_ARGUMENT),
        Option("data-length", ArgType.REQUIRED_ARGUMENT, convert=int),
        Option("datadir", ArgType.REQUIRED_ARGUMENT),
        CounterOption('d', ArgType.OPTIONAL_ARGUMENT, "debug"),
        Option("defeat-rst-ratelimit", ArgType.NO_ARGUMENT),
        Option("dns-servers", ArgType.REQUIRED_ARGUMENT),
        Option('e', ArgType.REQUIRED_ARGUMENT),
        Option("exclude", ArgType.REQUIRED_ARGUMENT),
        Option("excludefile", ArgType.REQUIRED_ARGUMENT),
        Option('F', ArgType.NO_ARGUMENT),
        CounterOption('f', ArgType.NO_ARGUMENT),
        Option("help", ArgType.NO_ARGUMENT, 'h'),
        Option("host-timeout", ArgType.REQUIRED_ARGUMENT, convert=timespec),
        Option("iL", ArgType.REQUIRED_ARGUMENT, 'i'),
        Option("iR", ArgType.REQUIRED_ARGUMENT, convert=int),
        Option("iflist", ArgType.NO_ARGUMENT),
        Option("initial-rtt-timeout", ArgType.REQUIRED_ARGUMENT,
            convert=timespec),
        Option("ip-options", ArgType.REQUIRED_ARGUMENT),
        Option("log-errors", ArgType.NO_ARGUMENT),
        Option("max-hostgroup", ArgType.REQUIRED_ARGUMENT, convert=int),
        Option("max-os-tries", ArgType.REQUIRED_ARGUMENT, convert=int),
        Option("max-parallelism", ArgType.REQUIRED_ARGUMENT, 'M', convert=int),
        Option("max-rate", ArgType.REQUIRED_ARGUMENT, convert=int),
        Option("max-retries", ArgType.REQUIRED_ARGUMENT, convert=int),
        Option("max-rtt-timeout", ArgType.REQUIRED_ARGUMENT, convert=timespec),
        Option("max-scan-delay", ArgType.REQUIRED_ARGUMENT, convert=timespec),
        Option("min-hostgroup", ArgType.REQUIRED_ARGUMENT, convert=int),
        Option("min-parallelism", ArgType.REQUIRED_ARGUMENT, convert=int),
        Option("min-rate", ArgType.REQUIRED_ARGUMENT, convert=int),
        Option("min-retries", ArgType.REQUIRED_ARGUMENT, convert=int),
        Option("min-rtt-timeout", ArgType.REQUIRED_ARGUMENT, convert=timespec),
        Option("mtu", ArgType.REQUIRED_ARGUMENT, convert=int),
        Option('n', ArgType.NO_ARGUMENT),
        Option("no-stylesheet", ArgType.NO_ARGUMENT),
        Option('O', ArgType.OPTIONAL_ARGUMENT),
        Option("oA", ArgType.REQUIRED_ARGUMENT),
        Option("oG", ArgType.REQUIRED_ARGUMENT, "oM", 'm'),
        Option("oN", ArgType.REQUIRED_ARGUMENT, 'o'),
        Option("oS", ArgType.REQUIRED_ARGUMENT),
        Option("oX", ArgType.REQUIRED_ARGUMENT),
        Option("open", ArgType.NO_ARGUMENT),
        Option("osscan-guess", ArgType.NO_ARGUMENT, "fuzzy"),
        Option("osscan-limit", ArgType.NO_ARGUMENT),
        Option('P', ArgType.OPTIONAL_ARGUMENT),
        Option('p', ArgType.REQUIRED_ARGUMENT),
        Option("packet-trace", ArgType.NO_ARGUMENT),
        Option("port-ratio", ArgType.REQUIRED_ARGUMENT, convert=float),
        Option("privileged", ArgType.NO_ARGUMENT),
        Option('R', ArgType.NO_ARGUMENT),
        Option('r', ArgType.NO_ARGUMENT),
        Option("randomize-hosts", ArgType.NO_ARGUMENT, "rH"),
        Option("reason", ArgType.NO_ARGUMENT),
        Option("release-memory", ArgType.NO_ARGUMENT),
        Option('S', ArgType.REQUIRED_ARGUMENT),
        ScantypeOption('s', ArgType.REQUIRED_ARGUMENT),
        Option("scanflags", ArgType.REQUIRED_ARGUMENT),
        Option("scan-delay", ArgType.REQUIRED_ARGUMENT, convert=timespec),
        Option("sI", ArgType.REQUIRED_ARGUMENT),
        Option("script", ArgType.REQUIRED_ARGUMENT),
        Option("script-args", ArgType.REQUIRED_ARGUMENT),
        Option("script-trace", ArgType.NO_ARGUMENT),
        Option("script-updatedb", ArgType.NO_ARGUMENT),
        Option("script-help", ArgType.REQUIRED_ARGUMENT),
        Option("send-eth", ArgType.NO_ARGUMENT),
        Option("send-ip", ArgType.NO_ARGUMENT),
        Option("servicedb", ArgType.REQUIRED_ARGUMENT),
        Option("source-port", ArgType.REQUIRED_ARGUMENT, 'g'),
        Option("spoof-mac", ArgType.REQUIRED_ARGUMENT),
        Option("stylesheet", ArgType.REQUIRED_ARGUMENT),
        Option("system-dns", ArgType.NO_ARGUMENT),
        TimingOption('T', ArgType.REQUIRED_ARGUMENT, "timing"),
        Option("top-ports", ArgType.REQUIRED_ARGUMENT, convert=int),
        Option("traceroute", ArgType.NO_ARGUMENT),
        Option("ttl", ArgType.REQUIRED_ARGUMENT, convert=int),
        Option("unprivileged", ArgType.NO_ARGUMENT),
        CounterOption('v', ArgType.OPTIONAL_ARGUMENT, "verbose"),
        Option("version", ArgType.NO_ARGUMENT, 'V'),
        Option("version-all", ArgType.NO_ARGUMENT),
        Option("version-intensity", ArgType.REQUIRED_ARGUMENT, convert=int),
        Option("version-light", ArgType.NO_ARGUMENT),
        Option("version-trace", ArgType.NO_ARGUMENT),
        Option("versiondb", ArgType.REQUIRED_ARGUMENT),
        Option("webxml", ArgType.NO_ARGUMENT))
options = PrefixMatcher()
for o in LONG_OPTIONS:
    options.add_string(o.name, o)
    for a in o.aliases:
        options.add_string(a, o)


def split_quoted(s):
    """Like str.split, except that no splits occur inside quoted strings, and
    quoted strings are unquoted."""
    r = []
    i = 0
    while i < len(s) and s[i].isspace():
        i += 1
    while i < len(s):
        part = []
        while i < len(s) and not s[i].isspace():
            c = s[i]
            if c == "\"" or c == "'":
                begin = c
                i += 1
                while i < len(s):
                    c = s[i]
                    if c == begin:
                        i += 1
                        break
                    elif c == "\\":
                        i += 1
                        if i < len(s):
                            c = s[i]
                        # Otherwise, ignore the error and leave the backslash
                        # at the end of the string.
                    part.append(c)
                    i += 1
            else:
                part.append(c)
                i += 1
        r.append("".join(part))
        while i < len(s) and s[i].isspace():
            i += 1

    return r


def maybe_quote(s):
    """Return s quoted if it needs to be, otherwise unchanged."""
    for c in s:
        if c == "\"" or c == "\\" or c == "'" or c.isspace():
            break
    else:
        return s

    r = []
    for c in s:
        if c == "\"":
            r.append("\\\"")
        elif c == "\\":
            r.append("\\\\")
        else:
            r.append(c)

    return "\"" + "".join(r) + "\""


def join_quoted(l):
    return " ".join([maybe_quote(x) for x in l])


def lookup_option(name, options):
    """Find an option with the given (possibly abbreviated) name. None is
    returned if no options match or if the name is ambiguous (more than one
    option matches with no exact match)."""

    status, match = options.get_item(name)
    return match


def split_option(cmd_arg, options):
    """Split an option into a name, argument (if any), and possible remainder.
    It is not an error if the option does not include an argument even though
    it is required; the caller must take the argument from the next
    command-line argument. The remainder is what's left over after stripping a
    single short option that doesn't take an argument. At most one of argument
    and remainder will be non-None.
    Examples:
    >>> split_option("-v", options)
    (CounterOption('v', OPTIONAL_ARGUMENT), None, None)
    >>> split_option("--min-rate", options)
    (Option('min-rate', REQUIRED_ARGUMENT), None, None)
    >>> split_option("--unknown", options)
    ('unknown', None, None)
    >>> split_option("--min-rate=100", options)
    (Option('min-rate', REQUIRED_ARGUMENT), '100', None)
    >>> split_option("-d9", options)
    (CounterOption('d', OPTIONAL_ARGUMENT), '9', None)
    >>> split_option("-AFn", options)
    (Option('A', NO_ARGUMENT), None, '-Fn')
    >>> split_option("-Amin-rate", options)
    (Option('A', NO_ARGUMENT), None, '-min-rate')
    """
    maybe_short = True
    if cmd_arg.startswith("--"):
        maybe_short = False
        name = cmd_arg[2:]
    elif cmd_arg.startswith("-"):
        name = cmd_arg[1:]
    else:
        raise RuntimeError(
                "split_option called with non-option '{}'".format(cmd_arg))
    # Check for a lone - or --.
    if name == "":
        return cmd_arg, None, None
    # First see if it's really a long option (or a single short option).
    index = name.find('=')
    if index < 0:
        arg = None
    else:
        name, arg = name[:index], name[index + 1:]
    option = lookup_option(name, options)
    if option is not None:
        return option, arg, None
    # No luck. Must be a short option.
    if not maybe_short:
        return name, arg, None
    name = cmd_arg[1]
    option = lookup_option(name, options)
    if option is None:
        # An unknown short option. Return the whole thing.
        return cmd_arg[1:], None, None
    rest = cmd_arg[2:]
    if rest == "":
        return option, None, None
    if option.has_arg == ArgType.NO_ARGUMENT:
        return option, None, "-" + rest
    else:
        return option, rest, None


def get_option(cmd_args, options):
    """Find and return the first option (plus a possible option argument) or
    positional argument from the command-line option list in cmd_args. The
    return value will have one of the following forms:
    * a string, representing a positional argument;
    * an (Option, argument) pair (argument may be None);
    * a (None, extra, ...) tuple, where extra, ... is a chain of an unknown
        option and its following arguments that cannot be interpreted
        unambiguously; or
    * None, at the end of the option list."""
    if len(cmd_args) == 0:
        return None
    cmd_arg = cmd_args.pop(0)
    if cmd_arg == "--":
        if len(cmd_args) == 0:
            return None
        # Grab the positional argument and replace the --.
        name = cmd_args[0]
        cmd_args[0] = "--"
        return name
    # A normal positional argument.
    if not cmd_arg.startswith("-"):
        return cmd_arg
    option, arg, remainder = split_option(cmd_arg, options)
    if remainder is not None:
        cmd_args.insert(0, remainder)
    if not isinstance(option, Option):
        # Unrecognized option.
        if arg is not None:
            return (None, cmd_arg)
        else:
            extras = [None, cmd_arg]
            # We found an unknown option but we have a problem--we don't know
            # if it takes an argument or not. So what we do is, we simulate
            # what would happen both if the option took and argument and if it
            # didn't. The sync function does that by calling this function in a
            # loop.
            rest = sync(cmd_args[1:], cmd_args[:], options)
            # rest is the part of the argument list that is the same whether or
            # not the unknown option takes an argument. Put everything up until
            # rest begins in the extras, then set cmd_args to rest.
            extras += cmd_args[0:len(cmd_args) - len(rest)]
            del cmd_args[0:len(cmd_args) - len(rest)]
            return tuple(extras)
    elif option.has_arg == ArgType.NO_ARGUMENT and arg is not None:
        # It has an arg but it shouldn't (like --send-ip=5). Treat it as
        # an extra.
        return (None, cmd_arg)
    elif option.has_arg == ArgType.REQUIRED_ARGUMENT and arg is None:
        # An argument is required but not yet read.
        if len(cmd_args) == 0:
            # No more args. Treat it as an extra.
            return (None, cmd_arg)
        else:
            arg = cmd_args.pop(0)
            return (option, arg)
    else:
        return (option, arg)


def sync(a, b, options):
    """Given two command-line argument lists, incrementally get an option from
    whichever is longer until both lists are equal. Return the resulting
    list."""
    while a != b:
        if len(a) > len(b):
            get_option(a, options)
        else:
            get_option(b, options)
    return a


def getopt_long_only_extras(cmd_args, options):
    """This is a generator version of getopt_long_only that additionally has
    robust handling of unknown options. Each of the items in the sequence it
    yields will be one of the following:
    * a string, representing a positional argument;
    * an (option, argument) pair (argument may be None);
    * a (None, extra, ...) tuple, where extra, ... is a chain of an unknown
        option and its following arguments that cannot be interpreted
        unambiguously; or
    * None, at the end of the option list."""
    # get_option modifies its list of arguments in place. Don't modify the
    # original list.
    cmd_args_copy = cmd_args[:]
    while True:
        result = get_option(cmd_args_copy, options)
        if result is None:
            break
        yield result


class NmapOptions(object):
    SHORT_OPTIONS = "6Ab:D:d::e:Ffg:hi:M:m:nO::o:P:p:RrS:s:T:v::V"

    # Sets of options that should be treated as equivalent from the point of
    # view of the external interface. For example, ops["--timing"] means the
    # same thing as ops["-T"].
    EQUIVALENT_OPTIONS = (
        ("debug", "d"),
        ("help", "h"),
        ("iL", "i"),
        ("max-parallelism", "M"),
        ("osscan-guess", "fuzzy"),
        ("oG", "oM", "m"),
        ("oN", "o"),
        ("sP", "sn"),
        ("P", "PE", "PI"),
        ("PA", "PT"),
        ("P0", "PD", "PN", "Pn"),
        ("rH", "randomize-hosts"),
        ("source-port", "g"),
        ("timing", "T"),
        ("verbose", "v"),
        ("version", "V"),
    )
    EQUIVALENCE_MAP = {}
    for set in EQUIVALENT_OPTIONS:
        base = set[0]
        aliases = set[1:]
        for alias in aliases:
            EQUIVALENCE_MAP[alias] = base

    def __init__(self):
        self.clear()

    def clear(self):
        self._executable = None
        self.target_specs = []
        self.extras = []

        # This is the internal mapping of option names to values.
        self.d = {}

    def _set_executable(self, executable):
        self._executable = executable

    executable = property(lambda self: self._executable or "nmap",
            _set_executable)

    def canonicalize_name(self, name):
        opt, arg, remainder = split_option(name, options)
        assert remainder is None
        if arg is None:
            if isinstance(opt, Option):
                option = opt.name
            else:
                option = opt
        else:
            option = name.lstrip("-")
        return option

    def __getitem__(self, key):
        option, arg, _ = split_option(key, options)
        if isinstance(option, Option):
            return option.get(arg, self.d)
        else:
            return None

    def __setitem__(self, key, value):
        result = get_option([key, value], options)
        self.handle_result(result)

    def setdefault(self, key, default):
        return self.d.setdefault(self.canonicalize_name(key), default)

    def handle_result(self, result):
        if isinstance(result, str):
            # A positional argument.
            self.target_specs.append(result)
            return
        elif result[0] is None:
            # An unknown option.
            self.extras.extend(result[1:])
            return

        # A normal option.
        option, arg = result
        option.handle(arg, self.d, self.extras)

    def parse(self, opt_list):
        self.clear()

        if len(opt_list) > 0:
            self.executable = opt_list[0]

        for result in getopt_long_only_extras(
                opt_list[1:], options):
            self.handle_result(result)

    def parse_string(self, opt_string):
        self.parse(split_quoted(opt_string))

    def render(self):
        opt_list = [self.executable]
        for option, v in self.d.items():
            opt_list.extend(str(a) for a in option.toargv(v, self.d))
        opt_list.extend(self.target_specs)

        opt_list.extend(self.extras)
        return opt_list

    def render_string(self):
        return join_quoted(self.render())

import doctest
import unittest


class NmapOptionsTest(unittest.TestCase):
    def test_clear(self):
        """Test that a new object starts without defining any options, that the
        clear method removes all options, and that parsing the empty string or
        an empty list removes all options."""
        TEST = "nmap -T4 -A -v localhost --webxml"
        ops = NmapOptions()
        self.assertTrue(len(ops.render()) == 1)
        ops.parse_string(TEST)
        self.assertFalse(len(ops.render()) == 1)
        ops.clear()
        self.assertTrue(len(ops.render()) == 1)
        ops.parse_string(TEST)
        ops.parse_string("")
        self.assertEqual(ops.render_string(), "nmap")
        ops.parse_string(TEST)
        ops.parse([])
        self.assertEqual(ops.render_string(), "nmap")

    def test_default_executable(self):
        """Test that there is a default executable member set."""
        ops = NmapOptions()
        self.assertNotNull(ops.executable)

    def test_default_executable(self):
        """Test that you can set the executable."""
        ops = NmapOptions()
        ops.executable = "foo"
        self.assertEqual(ops.executable, "foo")
        self.assertEqual(ops.render(), ["foo"])

    def test_render(self):
        """Test that the render method returns a list."""
        TEST = "nmap -T4 -A -v localhost --webxml"
        ops = NmapOptions()
        ops.parse_string(TEST)
        self.assertTrue(type(ops.render()) == list,
                "type == %s" % type(ops.render))

    def test_quoted(self):
        """Test that strings can be quoted."""
        ops = NmapOptions()

        ops.parse_string('nmap --script ""')
        self.assertEqual(ops["--script"], "")
        ops.parse_string("nmap --script ''")
        self.assertEqual(ops["--script"], "")

        ops.parse_string('nmap --script test one two three')
        self.assertEqual(ops["--script"], "test")
        self.assertEqual(ops.target_specs, ["one", "two", "three"])
        ops.parse_string('nmap --script "test" one two three')
        self.assertEqual(ops["--script"], "test")
        self.assertEqual(ops.target_specs, ["one", "two", "three"])
        ops.parse_string('nmap --script "test one" two three')
        self.assertEqual(ops["--script"], "test one")
        self.assertEqual(ops.target_specs, ["two", "three"])
        ops.parse_string('nmap --script test" one" two three')
        self.assertEqual(ops["--script"], "test one")
        self.assertEqual(ops.target_specs, ["two", "three"])
        ops.parse_string('nmap --script test" one"""" two" three')
        self.assertEqual(ops["--script"], "test one two")
        self.assertEqual(ops.target_specs, ["three"])

        ops.parse_string("nmap --script test one two three")
        self.assertEqual(ops["--script"], "test")
        self.assertEqual(ops.target_specs, ["one", "two", "three"])
        ops.parse_string("nmap --script 'test' one two three")
        self.assertEqual(ops["--script"], "test")
        self.assertEqual(ops.target_specs, ["one", "two", "three"])
        ops.parse_string("nmap --script 'test one' two three")
        self.assertEqual(ops["--script"], "test one")
        self.assertEqual(ops.target_specs, ["two", "three"])
        ops.parse_string("nmap --script test' one' two three")
        self.assertEqual(ops["--script"], "test one")
        self.assertEqual(ops.target_specs, ["two", "three"])
        ops.parse_string("nmap --script test' one'''' two' three")
        self.assertEqual(ops["--script"], "test one two")
        self.assertEqual(ops.target_specs, ["three"])

        ops.parse_string('nmap --script "ab\\\"cd"')
        self.assertEqual(ops["--script"], "ab\"cd")
        ops.parse_string('nmap --script "ab\\\\cd"')
        self.assertEqual(ops["--script"], "ab\\cd")
        ops.parse_string('nmap --script "ab\\\'cd"')
        self.assertEqual(ops["--script"], "ab'cd")
        ops.parse_string("nmap --script 'ab\\\"cd'")
        self.assertEqual(ops["--script"], 'ab"cd')

        ops.parse_string('nmap "--script" test')
        self.assertEqual(ops["--script"], "test")
        ops.parse_string("nmap '--script' test")
        self.assertEqual(ops["--script"], "test")

        ops.parse_string('"nmap foo" --script test')
        self.assertEqual(ops.executable, "nmap foo")
        ops.parse_string("'nmap foo' --script test")
        self.assertEqual(ops.executable, "nmap foo")

    def test_render_quoted(self):
        """Test that strings that need to be quoted are quoted."""
        ops = NmapOptions()
        ops.parse_string('"/path/ /nmap" --script "test one two three"')
        self.assertEqual(ops.executable, "/path/ /nmap")
        self.assertEqual(ops["--script"], "test one two three")
        self.assertEqual(ops.target_specs, [])
        s = ops.render_string()
        ops.parse_string(s)
        self.assertEqual(ops.executable, "/path/ /nmap")
        self.assertEqual(ops["--script"], "test one two three")
        self.assertEqual(ops.target_specs, [])

    def test_end(self):
        """Test that -- ends argument processing."""
        ops = NmapOptions()
        ops.parse_string("nmap -v -- -v")
        self.assertTrue(ops["-v"] == 1)
        self.assertTrue(ops.target_specs == ["-v"])

    def test_roundtrip(self):
        """Test that parsing and re-rendering a previous rendering gives the
        same thing as the previous rendering."""
        TESTS = (
            "nmap",
            "nmap -v",
            "nmap -vv",
            "nmap -d -v",
            "nmap -d -d",
            "nmap -d -v -d",
            "nmap localhost",
            "nmap -oX - 192.168.0.1 -PS10",
        )
        ops = NmapOptions()
        for test in TESTS:
            ops.parse_string(test)
            opt_string_1 = ops.render_string()
            ops.parse_string(opt_string_1)
            opt_string_2 = ops.render_string()
            self.assertEqual(opt_string_1, opt_string_2)

    def test_args(self):
        """Test potentially tricky argument scenarios."""
        ops = NmapOptions()
        ops.parse_string("nmap -d9")
        self.assertEqual(len(ops.target_specs), 0)
        self.assertEqual(ops["-d"], 9)
        ops.parse_string("nmap -d 9")
        self.assertEqual(ops.target_specs, ["9"])
        self.assertEqual(ops["-d"], 1)

    def test_repetition(self):
        """Test options that can be repeated to increase their effect."""
        ops = NmapOptions()
        ops.parse_string("nmap -vv")
        self.assertTrue(ops["-v"] == 2)
        ops.parse_string("nmap -v -v")
        self.assertTrue(ops["-v"] == 2)
        ops.parse_string("nmap -ff")
        self.assertTrue(ops["-f"] == 2)
        ops.parse_string("nmap -f -f")
        self.assertTrue(ops["-f"] == 2)
        # Note: unlike -d, -v doesn't take an optional numeric argument.
        ops.parse_string("nmap -d2 -d")
        self.assertTrue(ops["-d"] == 3)

    def test_scan_types(self):
        """Test that multiple scan types given to the -s option are all
        interpreted correctly."""
        ops = NmapOptions()
        ops.parse_string("nmap -s")
        self.assertTrue(ops.extras == ["-s"])
        ops.parse_string("nmap -sS")
        self.assertTrue(ops.extras == [])
        self.assertTrue(ops["-sS"])
        self.assertTrue(not ops["-sU"])
        ops.parse_string("nmap -sSU")
        self.assertTrue(ops["-sS"])
        self.assertTrue(ops["-sU"])

    def test_extras(self):
        """Test that unknown arguments are correctly recorded. A few subtleties
        are tested:
        1. Unknown options are not simply discarded.
        2. When an unknown option is found, any following arguments that could
           have a different meaning depending on whether the unknown option
           takes an argument are moved with the argument to the extras.
        3. Any arguments moved to the extras are not otherwise interpreted.
        4. Extra options so copied are copied in blocks, keeping their original
           ordering with each block."""
        ops = NmapOptions()

        ops.parse_string("nmap --fee")
        self.assertTrue(ops.extras == ["--fee"])
        self.assertTrue(ops.render_string() == "nmap --fee")

        # Note: -x is not a real Nmap option.

        ops.parse_string("nmap -x")
        self.assertTrue(ops.extras == ["-x"])
        self.assertTrue(ops.render_string() == "nmap -x")

        ops.parse_string("nmap -v --fie scanme.nmap.org -d")
        self.assertTrue(ops.extras == ["--fie", "scanme.nmap.org"])
        self.assertTrue(ops["-v"] == 1)
        self.assertTrue(ops["-d"] == 1)
        self.assertTrue(len(ops.target_specs) == 0)

        ops.parse_string("nmap -v --foe=5 scanme.nmap.org -d")
        self.assertTrue(ops.extras == ["--foe=5"])
        self.assertTrue(ops.target_specs == ["scanme.nmap.org"])

        ops.parse_string("nmap --fum -oX out.xml -v")
        self.assertTrue(ops.extras == ["--fum", "-oX", "out.xml"])
        self.assertTrue(ops["-v"] == 1)

        ops.parse_string("nmap -x -A localhost")
        self.assertTrue(ops.extras == ["-x", "-A"])

        ops.parse_string("nmap -x --fee -A localhost")
        self.assertTrue(ops.extras == ["-x", "--fee", "-A"])

        ops.parse_string("nmap -x -x --timing 3 localhost")
        self.assertTrue(ops.extras == ["-x", "-x", "--timing", "3"])
        self.assertTrue(ops.target_specs == ["localhost"])

        ops.parse_string("nmap -x -x --timing=3 localhost")
        self.assertTrue(ops.extras == ["-x", "-x", "--timing=3"])
        self.assertTrue(ops.target_specs == ["localhost"])

        ops.parse_string("nmap -x -Ad9")
        self.assertTrue(ops.extras == ["-x", "-Ad9"])

        ops.parse_string("nmap -xrest")
        self.assertTrue(ops.extras == ["-xrest"])

        # Options that can't be given more than once should end up in extras.
        ops.parse_string("nmap -p 53 -p 80 -O --mtu 50 --mtu 100 -O2")
        self.assertEqual(ops["-p"], "53")
        self.assertEqual(ops["--mtu"], 50)
        self.assertTrue(ops["-O"])
        self.assertEqual(ops.extras, ["-p", "80", "--mtu", "100", "-O2"])

    def test_quirks(self):
        """Test the handling of constructions whose interpretation isn't
        specified in documentation, but should match that of GNU getopt."""
        ops = NmapOptions()
        # Long options can be written with one dash.
        ops.parse_string("nmap -min-rate 100")
        self.assertEqual(ops["--min-rate"], 100)
        ops.parse_string("nmap -min-rate=200")
        self.assertEqual(ops["--min-rate"], 200)

        # Short options not taking an argument can be followed by a long
        # option.
        ops.parse_string("nmap -nFmin-rate 100")
        self.assertTrue(ops["-n"])
        self.assertTrue(ops["-F"])
        self.assertEqual(ops["--min-rate"], 100)

        # Short options taking an argument consume the rest of the argument.
        ops.parse_string("nmap -nFp1-100")
        self.assertTrue(ops["-n"])
        self.assertTrue(ops["-F"])
        self.assertEqual(ops["-p"], "1-100")

    def test_conversion(self):
        """Test that failed integer conversions cause the option to wind up in
        the extras."""
        ops = NmapOptions()
        ops.parse_string("nmap -d#")
        self.assertEqual(ops.extras, ["-d#"])
        ops.parse_string("nmap -T monkeys")
        self.assertTrue(ops["-T"] is None)
        self.assertTrue(ops.extras == ["-T", "monkeys"])
        ops.parse_string("nmap -iR monkeys")
        self.assertTrue(ops["-iR"] is None)
        self.assertEqual(ops.extras, ["-iR", "monkeys"])

    def test_read_unknown(self):
        """Test that getting the value of non-options returns None."""
        ops = NmapOptions()
        self.assertEqual(ops["-x"], None)
        self.assertEqual(ops["--nonoption"], None)

    def test_canonical_option_names(self):
        """Test that equivalent option names are properly canonicalized, so
        that ops["--timing"] and ops["-T"] mean the same thing, for example."""
        EQUIVS = (
            ("--debug", "-d"),
            ("--help", "-h"),
            ("-iL", "-i"),
            ("--max-parallelism", "-M"),
            ("--osscan-guess", "--fuzzy"),
            ("-oG", "-oM", "-m"),
            ("-oN", "-o"),
            ("-sP", "-sn"),
            ("-P", "-PE", "-PI"),
            ("-PA", "-PT"),
            ("-P0", "-PD", "-PN", "-Pn"),
            ("--source-port", "-g"),
            ("--timing", "-T"),
            ("--verbose", "-v"),
            ("--version", "-V"),
            ("--min-rate", "-min-rate")
        )
        ops = NmapOptions()
        for set in EQUIVS:
            for opt in set:
                ops.clear()
                ops[opt] = "test"
                for other in set:
                    self.assertTrue(ops[other] == ops[opt],
                        "%s and %s not the same" % (opt, other))

    def test_options(self):
        """Test that all options that are supposed to be supported are really
        supported. They must be parsed and not as extras, and must produce
        output on rendering that can be parsed again."""
        TESTS = ["-" + opt for opt in "6AFfhnRrVv"]
        TESTS += ["-b host", "-D 192.168.0.1,ME,RND", "-d", "-d -d", "-d2",
            "-e eth0", "-f -f", "-g 53", "-i input.txt", "-M 100",
            "-m output.gnmap", "-O", "-O2", "-o output.nmap", "-p 1-100",
            "-S 192.168.0.1", "-T0", "-v -v"]
        TESTS += ["-s" + opt for opt in "ACFLMNnOPRSTUVWXYZ"]
        TESTS += ["-P" + opt for opt in "IEMP0NnDRBSTAUOY"]
        TESTS += ["-P" + opt + "100" for opt in "STAUOY"]
        TESTS += [
            "--version",
            "--verbose",
            "--datadir=dir",
            "--datadir dir",
            "--servicedb=db",
            "--servicedb db",
            "--versiondb=db",
            "--versiondb db",
            "--debug",
            "--debug=3",
            "--debug 3",
            "--help",
            "--iflist",
            "--release-memory",
            "--max-os-tries=10",
            "--max-os-tries 10",
            "--max-parallelism=10",
            "--min-parallelism 10",
            "--timing=0",
            "--timing 0",
            "--max-rtt-timeout=10",
            "--max-rtt-timeout 10",
            "--min-rtt-timeout=10",
            "--min-rtt-timeout 10",
            "--initial-rtt-timeout=10",
            "--initial-rtt-timeout 10",
            "--excludefile=file",
            "--excludefile file",
            "--exclude=192.168.0.0",
            "--exclude 192.168.0.0",
            "--max-hostgroup=10",
            "--max-hostgroup 10",
            "--min-hostgroup=10",
            "--min-hostgroup 10",
            "--open",
            "--scanflags=RST,ACK",
            "--scanflags RST,ACK",
            "--defeat-rst-ratelimit",
            "--host-timeout=10",
            "--host-timeout 10",
            "--scan-delay=10",
            "--scan-delay 10",
            "--max-scan-delay=10",
            "--max-scan-delay 10",
            "--max-retries=10",
            "--max-retries 10",
            "--source-port=53",
            "--source-port 53",
            "--randomize-hosts",
            "--osscan-limit",
            "--osscan-guess",
            "--fuzzy",
            "--packet-trace",
            "--version-trace",
            "--data-length=10",
            "--data-length 10",
            "--send-eth",
            "--send-ip",
            "--stylesheet=style.xml",
            "--stylesheet style.xml",
            "--no-stylesheet",
            "--webxml",
            "--privileged",
            "--unprivileged",
            "--mtu=1500",
            "--mtu 1500",
            "--append-output",
            "--spoof-mac=00:00:00:00:00:00",
            "--spoof-mac 00:00:00:00:00:00",
            "--badsum",
            "--ttl=64",
            "--ttl 64",
            "--traceroute",
            "--reason",
            "--allports",
            "--version-intensity=5",
            "--version-intensity 5",
            "--version-light",
            "--version-all",
            "--system-dns",
            "--log-errors",
            "--dns-servers=localhost",
            "--dns-servers localhost",
            "--port-ratio=0.5",
            "--port-ratio 0.5",
            "--top-ports=1000",
            "--top-ports 1000",
            "--script=script.nse",
            "--script script.nse",
            "--script-trace",
            "--script-updatedb",
            "--script-args=none",
            "--script-args none",
            "--script-help=script.nse",
            "--script-help script.nse",
            "--ip-options=S",
            "--ip-options S",
            "--min-rate=10",
            "--min-rate 10",
            "--max-rate=10",
            "--max-rate 10",
            "-iL=input.txt",
            "-iL input.txt",
            "-iR=1000",
            "-iR 1000",
            "-oA=out",
            "-oA out",
            "-oG=out.gnmap",
            "-oG out.gnmap",
            "-oM=out.gnmap",
            "-oM out.gnmap",
            "-oN=out.nmap",
            "-oN out.nmap",
            "-oS=out.skid",
            "-oS out.skid",
            "-oX=out.xml",
            "-oX out.xml",
            "-sI=zombie.example.com",
            "-sI zombie.example.com",
            ]

        # The following options are present in the Nmap source but are not
        # tested for because they are deprecated or not documented or whatever.
        # "-I",
        # "--noninteractive",
        # "--thc",
        # "--nogcc",
        # "-rH",
        # "-ff",
        # "-vv",
        # "-oH",

        ops = NmapOptions()
        for test in TESTS:
            ops.parse_string("nmap " + test)
            opt_list_1 = ops.render()
            self.assertTrue(len(opt_list_1) > 1, "%s missing on render" % test)
            self.assertEqual(ops.extras, [],
                    "%s caused extras: %s" % (test, repr(ops.extras)))
            ops.parse(opt_list_1)
            opt_list_2 = ops.render()
            self.assertEqual(opt_list_1, opt_list_2,
                    "Result of parsing and rendering %s not parsable again" % (
                        test))
            self.assertEqual(ops.extras, [],
                    "Result of parsing and rendering %s left extras: %s" % (
                        test, ops.extras))


class SplitQuotedTest(unittest.TestCase):
    """A unittest class that tests the split_quoted function."""

    def test_split(self):
        self.assertEqual(split_quoted(''), [])
        self.assertEqual(split_quoted('a'), ['a'])
        self.assertEqual(split_quoted('a b c'), 'a b c'.split())

    def test_quotes(self):
        self.assertEqual(split_quoted('a "b" c'), ['a', 'b', 'c'])
        self.assertEqual(split_quoted('a "b c"'), ['a', 'b c'])
        self.assertEqual(split_quoted('a "b c""d e"'), ['a', 'b cd e'])
        self.assertEqual(split_quoted('a "b c"z"d e"'), ['a', 'b czd e'])

    def test_backslash(self):
        self.assertEqual(split_quoted('"\\""'), ['"'])
        self.assertEqual(split_quoted('\\"\\""'), ['\\"'])
        self.assertEqual(split_quoted('"\\"\\""'), ['""'])


class TestPrefixMatcher(unittest.TestCase):

    def setUp(self):
        """Initialize a standard PrefixMatcher with a known set of words."""
        self.words = ["cat", "caterpillar", "car", "dog"]
        self.matcher = PrefixMatcher(self.words)

    def test_not_a_prefix(self):
        """Test queries that are completely unrelated or extend past existing
        words."""
        self.assertEqual(self.matcher.get_status("bat"),
                PrefixStatus.NOT_A_PREFIX)
        self.assertEqual(self.matcher.get_status("doggy"),
                PrefixStatus.NOT_A_PREFIX)
        self.assertEqual(self.matcher.get_status("caterpillars"),
                PrefixStatus.NOT_A_PREFIX)

    def test_exact_match(self):
        """Test exact matches, ensuring they take precedence even if they are
        prefixes of others."""
        # 'cat' is an exact match in the set, despite 'caterpillar' existing
        self.assertEqual(self.matcher.get_status("cat"),
                PrefixStatus.EXACT_MATCH)
        self.assertEqual(self.matcher.get_status("car"),
                PrefixStatus.EXACT_MATCH)
        self.assertEqual(self.matcher.get_status("dog"),
                PrefixStatus.EXACT_MATCH)

    def test_unique_prefix(self):
        """Test strings that are a prefix of exactly one populated string."""
        # 'cater' is only a prefix of 'caterpillar'
        self.assertEqual(self.matcher.get_status("cater"),
                PrefixStatus.UNIQUE_PREFIX)
        # 'do' is only a prefix of 'dog'
        self.assertEqual(self.matcher.get_status("do"),
                PrefixStatus.UNIQUE_PREFIX)

    def test_multiple_prefixes(self):
        """Test strings that are a prefix of more than one populated string."""
        # 'ca' is a prefix of 'cat', 'caterpillar', and 'car'
        self.assertEqual(self.matcher.get_status("ca"),
                PrefixStatus.MULTIPLE_PREFIXES)
        # 'c' is also a prefix of multiple strings
        self.assertEqual(self.matcher.get_status("c"),
                PrefixStatus.MULTIPLE_PREFIXES)

    def test_dynamic_insertion(self):
        """Test adding strings dynamically and verifying status changes."""
        matcher = PrefixMatcher(["apple"])

        # Before adding 'applet'
        self.assertEqual(matcher.get_status("apple"), PrefixStatus.EXACT_MATCH)
        self.assertEqual(matcher.get_status("app"), PrefixStatus.UNIQUE_PREFIX)

        # Add a new word
        matcher.add_string("applet")

        # 'apple' is still an exact match (since it's in the set)
        self.assertEqual(matcher.get_status("apple"), PrefixStatus.EXACT_MATCH)
        # 'app' is now a prefix of multiple strings ('apple' and 'applet')
        self.assertEqual(matcher.get_status("app"),
                PrefixStatus.MULTIPLE_PREFIXES)

    def test_empty_matcher(self):
        """Test behavior when initialized with no strings or an empty
        collection."""
        empty_matcher = PrefixMatcher()
        self.assertEqual(empty_matcher.get_status("a"),
                PrefixStatus.NOT_A_PREFIX)

        empty_matcher_list = PrefixMatcher([])
        self.assertEqual(empty_matcher_list.get_status("test"),
                PrefixStatus.NOT_A_PREFIX)

    def test_duplicate_input_handling(self):
        """Test that duplicate strings passed during initialization do not
        break counts."""
        matcher = PrefixMatcher(["test", "test", "testing"])
        # 'test' is an exact match
        self.assertEqual(matcher.get_status("test"), PrefixStatus.EXACT_MATCH)
        self.assertEqual(matcher.get_status("tes"),
                PrefixStatus.MULTIPLE_PREFIXES)
        with self.assertRaises(ValueError):
            matcher.add_string("testing")

if __name__ == "__main__":
    doctest.testmod()
    unittest.main()
