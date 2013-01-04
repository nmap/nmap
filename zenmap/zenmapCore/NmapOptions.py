#!/usr/bin/env python

# This is an Nmap command line parser. It has two main parts:
#
#   getopt_long_only_extras, which is like getopt_long_only with robust handling
#   of unknown options.
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
# ['C:\\Program Files\\Nmap\\nmap.exe', '-v', '-v', '-oX', 'output.xml', '--script', 'safe', 'localhost']
# >>> ops.render_string()
# '"C:\\Program Files\\Nmap\\nmap.exe" -v -v -oX output.xml --script safe localhost'
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
# that is, a scan of scanme.nmap.org over interface eth0. But if it does take an
# argument, its argument is "-e", and the command line is the same as
#   nmap eth0 scanme.nmap.org -x -e
# which is a scan of the two hosts eth0 and scanme.nmap.org, over the default
# interface. In either case scanme.nmap.org is a target but the other arguments
# are ambiguous. To resolve this, once an unknown option is found, all following
# arguments that can be interpreted ambiguously are removed with it and placed
# in the extras, with normal option processing resumed only when there is no
# more ambiguity. This ensures that such options maintain their relative order
# when rendered again to output. In this example "-x -e eth0" will always appear
# in that order, and the -e option will be uninterpreted.
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

class option:
    """A single option, part of a pool of potential options. It's just a name
    and a flag saying if the option takes no argument, if an agument is
    optional, or if an argument is required."""
    NO_ARGUMENT = 0
    REQUIRED_ARGUMENT = 1
    OPTIONAL_ARGUMENT = 2

    def __init__(self, name, has_arg):
        self.name = name
        self.has_arg = has_arg

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
                        # Otherwise, ignore the error and leave the backslash at
                        # the end of the string.
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

def make_options(short_opts, long_opts):
    """Parse a short option specification string and long option tuples into a
    list of option objects."""
    options = []
    for name, has_arg in long_opts:
        options.append(option(name, has_arg))

    while len(short_opts) > 0:
        name = short_opts[0]
        short_opts = short_opts[1:]
        assert name != ":"
        num_colons = 0
        while len(short_opts) > 0 and short_opts[0] == ":":
            short_opts = short_opts[1:]
            num_colons += 1
        if num_colons == 0:
            has_arg = option.NO_ARGUMENT
        elif num_colons == 1:
            has_arg = option.REQUIRED_ARGUMENT
        else:
            has_arg = option.OPTIONAL_ARGUMENT
        options.append(option(name, has_arg))

    return options

lookup_option_cache = {}

def lookup_option(name, options):
    """Find an option with the given (possibly abbreviated) name. None is
    returned if no options match or if the name is ambiguous (more than one
    option matches with no exact match)."""

    # This function turns out to be a huge bottleneck. Therefore we memoize it.
    # We hash on the option name and the id of the options list, because lists
    # aren't hashable. This means that the options list can't change after the
    # first time you call this function, or you will get stale results. Turning
    # the list into a tuple and hashing that is too slow.
    cache_code = (name, id(options))
    try:
        return lookup_option_cache[cache_code]
    except KeyError:
        pass

    # Nmap treats '_' the same as '-' in long option names.
    def canonicalize_name(name):
        return name.replace("_", "-")

    name = canonicalize_name(name)
    matches = [o for o in options if canonicalize_name(o.name).startswith(name)]
    if len(matches) == 0:
        # No match.
        lookup_option_cache[cache_code] = None
    elif len(matches) == 1:
        # Only one match--not an ambiguous abbreviation.
        lookup_option_cache[cache_code] = matches[0]
    else:
        # More than one match--return only an exact match.
        for match in matches:
            if canonicalize_name(match.name) == name:
                lookup_option_cache[cache_code] = match
                break
        else:
            # No exact matches
            lookup_option_cache[cache_code] = None
    return lookup_option_cache[cache_code]

def split_option(cmd_arg, options):
    """Split an option into a name, argument (if any), and possible remainder.
    It is not an error if the option does not include an argument even though it
    is required; the caller must take the argument from the next command-line
    argument. The remainder is what's left over after stripping a single short
    option that doesn't take an argument. At most one of argument and remainder
    will be non-None.
    Examples:
    >>> split_option("-v", [option("v", option.NO_ARGUMENT)])
    ('v', None, None)
    >>> split_option("--min-rate", [option("min-rate", option.REQUIRED_ARGUMENT)])
    ('min-rate', None, None)
    >>> split_option("--min-rate=100", [option("min-rate", option.REQUIRED_ARGUMENT)])
    ('min-rate', '100', None)
    >>> split_option("-d9", [option("d", option.OPTIONAL_ARGUMENT)])
    ('d', '9', None)
    >>> split_option("-AFn", [option("A", option.NO_ARGUMENT)])
    ('A', None, '-Fn')
    >>> split_option("-Amin-rate", [option("A", option.NO_ARGUMENT)])
    ('A', None, '-min-rate')
    """
    if cmd_arg.startswith("--"):
        name = cmd_arg[2:]
        index = name.find('=')
        if index < 0:
            arg = None
        else:
            name, arg = name[:index], name[index + 1:]
        return name, arg, None
    elif cmd_arg.startswith("-"):
        name = cmd_arg[1:]
        # Check for a lone -.
        if name == "":
            return name, None, None
        # First see if it's really a long option (or a single short option).
        index = name.find('=')
        if index < 0:
            arg = None
        else:
            name, arg = name[:index], name[index + 1:]
        if lookup_option(name, options) is not None:
            return name, arg, None
        # No luck. Must be a short option.
        name = cmd_arg[1]
        option = lookup_option(name, options)
        if option is None:
            # An unknown short option. Return the whole thing.
            return cmd_arg[1:], None, None
        rest = cmd_arg[2:]
        if rest == "":
            return name, None, None
        if option.has_arg == option.NO_ARGUMENT:
            return name, None, "-" + rest
        else:
            return name, rest, None
    else:
        assert False, cmd_arg

def get_option(cmd_args, options):
    """Find and return the first option (plus a possible option argument) or
    positional argument from the command-line option list in cmd_args. The
    return value will have one of the following forms:
    a string, representing a positional argument;
    an (option, argument) pair (argument may be None);
    a (None, extra, ...) tuple, where extra, ... is a chain of an unknown option
        and its following arguments that cannot be interpreted unambiguously; or
    None, at the end of the option list."""
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
    name, arg, remainder = split_option(cmd_arg, options)
    if remainder is not None:
        cmd_args.insert(0, remainder)
    option = lookup_option(name, options)
    if option is None:
        # Unrecognized option.
        if arg is not None:
            return (None, cmd_arg)
        else:
            extras = [None, cmd_arg]
            # We found an unknown option but we have a problem--we don't know if
            # it takes an argument or not. So what we do is, we simulate what
            # would happen both if the option took and argument and if it
            # didn't. The sync function does that by calling this function in a
            # loop.
            rest = sync(cmd_args[1:], cmd_args[:], options)
            # rest is the part of the argument list that is the same whether or
            # not the unknown option takes an argument. Put everything up until
            # rest begins in the extras, then set cmd_args to rest.
            extras += cmd_args[0:len(cmd_args) - len(rest)]
            del cmd_args[0:len(cmd_args) - len(rest)]
            return tuple(extras)
    elif option.has_arg == option.NO_ARGUMENT and arg is not None:
        # It has an arg but it shouldn't (like --send-ip=5). Treat it as
        # an extra.
        return (None, cmd_arg)
    elif option.has_arg == option.REQUIRED_ARGUMENT and arg is None:
        # An argument is required but not yet read.
        if len(cmd_args) == 0:
            # No more args. Treat it as an extra.
            return (None, cmd_arg)
        else:
            arg = cmd_args.pop(0)
            return (option.name, arg)
    else:
        return (option.name, arg)

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

def getopt_long_only_extras(cmd_args, short_opts, long_opts):
    """This is a generator version of getopt_long_only that additionally has
    robust handling of unknown options. Each of the items in the sequence it
    yields will be one of the following:
    a string, representing a positional argument;
    an (option, argument) pair (argument may be None);
    a (None, extra, ...) tuple, where extra, ... is a chain of an unknown option
        and its following arguments that cannot be interpreted unambiguously; or
    None, at the end of the option list."""
    options = make_options(short_opts, long_opts)
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
    LONG_OPTIONS = (
        ("allports", option.NO_ARGUMENT),
        ("append-output", option.NO_ARGUMENT),
        ("badsum", option.NO_ARGUMENT),
        ("data-length", option.REQUIRED_ARGUMENT),
        ("datadir", option.REQUIRED_ARGUMENT),
        ("debug", option.OPTIONAL_ARGUMENT),
        ("defeat-rst-ratelimit", option.NO_ARGUMENT),
        ("dns-servers", option.REQUIRED_ARGUMENT),
        ("exclude", option.REQUIRED_ARGUMENT),
        ("excludefile", option.REQUIRED_ARGUMENT),
        ("fuzzy", option.NO_ARGUMENT),
        ("help", option.NO_ARGUMENT),
        ("host-timeout", option.REQUIRED_ARGUMENT),
        ("iL", option.REQUIRED_ARGUMENT),
        ("iR", option.REQUIRED_ARGUMENT),
        ("iflist", option.NO_ARGUMENT),
        ("initial-rtt-timeout", option.REQUIRED_ARGUMENT),
        ("ip-options", option.REQUIRED_ARGUMENT),
        ("log-errors", option.NO_ARGUMENT),
        ("max-hostgroup", option.REQUIRED_ARGUMENT),
        ("max-os-tries", option.REQUIRED_ARGUMENT),
        ("max-parallelism", option.REQUIRED_ARGUMENT),
        ("max-rate", option.REQUIRED_ARGUMENT),
        ("max-retries", option.REQUIRED_ARGUMENT),
        ("max-rtt-timeout", option.REQUIRED_ARGUMENT),
        ("max-scan-delay", option.REQUIRED_ARGUMENT),
        ("min-hostgroup", option.REQUIRED_ARGUMENT),
        ("min-parallelism", option.REQUIRED_ARGUMENT),
        ("min-rate", option.REQUIRED_ARGUMENT),
        ("min-retries", option.REQUIRED_ARGUMENT),
        ("min-rtt-timeout", option.REQUIRED_ARGUMENT),
        ("mtu", option.REQUIRED_ARGUMENT),
        ("no-stylesheet", option.NO_ARGUMENT),
        ("oA", option.REQUIRED_ARGUMENT),
        ("oG", option.REQUIRED_ARGUMENT),
        ("oM", option.REQUIRED_ARGUMENT),
        ("oN", option.REQUIRED_ARGUMENT),
        ("oS", option.REQUIRED_ARGUMENT),
        ("oX", option.REQUIRED_ARGUMENT),
        ("open", option.NO_ARGUMENT),
        ("osscan-guess", option.NO_ARGUMENT),
        ("osscan-limit", option.NO_ARGUMENT),
        ("packet-trace", option.NO_ARGUMENT),
        ("port-ratio", option.REQUIRED_ARGUMENT),
        ("privileged", option.NO_ARGUMENT),
        ("randomize-hosts", option.NO_ARGUMENT),
        ("reason", option.NO_ARGUMENT),
        ("release-memory", option.NO_ARGUMENT),
        ("scan-delay", option.REQUIRED_ARGUMENT),
        ("scanflags", option.REQUIRED_ARGUMENT),
        ("sI", option.REQUIRED_ARGUMENT),
        ("script", option.REQUIRED_ARGUMENT),
        ("script-args", option.REQUIRED_ARGUMENT),
        ("script-trace", option.NO_ARGUMENT),
        ("script-updatedb", option.NO_ARGUMENT),
        ("script-help", option.REQUIRED_ARGUMENT),
        ("send-eth", option.NO_ARGUMENT),
        ("send-ip", option.NO_ARGUMENT),
        ("servicedb", option.REQUIRED_ARGUMENT),
        ("source-port", option.REQUIRED_ARGUMENT),
        ("spoof-mac", option.REQUIRED_ARGUMENT),
        ("stylesheet", option.REQUIRED_ARGUMENT),
        ("system-dns", option.NO_ARGUMENT),
        ("timing", option.REQUIRED_ARGUMENT),
        ("top-ports", option.REQUIRED_ARGUMENT),
        ("traceroute", option.NO_ARGUMENT),
        ("ttl", option.REQUIRED_ARGUMENT),
        ("unprivileged", option.NO_ARGUMENT),
        ("verbose", option.OPTIONAL_ARGUMENT),
        ("version", option.NO_ARGUMENT),
        ("version-all", option.NO_ARGUMENT),
        ("version-intensity", option.REQUIRED_ARGUMENT),
        ("version-light", option.NO_ARGUMENT),
        ("version-trace", option.NO_ARGUMENT),
        ("versiondb", option.REQUIRED_ARGUMENT),
        ("webxml", option.NO_ARGUMENT),
    )

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

    TIMING_PROFILE_NAMES = {
        "paranoid": 0, "sneaky": 1, "polite": 2,
        "normal": 3, "aggressive": 4, "insane": 5
    }

    def __init__(self):
        self.options = make_options(self.SHORT_OPTIONS, self.LONG_OPTIONS)

        self.clear()

    def clear(self):
        self._executable = None
        self.target_specs = []
        self.extras = []

        # This is the internal mapping of option names to values.
        self.d = {}

    def _set_executable(self, executable):
        self._executable = executable

    executable = property(lambda self: self._executable or "nmap", _set_executable)

    def canonicalize_name(self, name):
        opt, arg, remainder = split_option(name, self.options)
        assert remainder == None
        if arg is None:
            option = lookup_option(opt, self.options)
            if option:
                option = option.name
            else:
                option = opt
        else:
            option = name.lstrip("-")
        option = NmapOptions.EQUIVALENCE_MAP.get(option, option)
        return option

    def __getitem__(self, key):
        return self.d.get(self.canonicalize_name(key))

    def __setitem__(self, key, value):
        self.d[self.canonicalize_name(key)] = value

    def setdefault(self, key, default):
        return self.d.setdefault(self.canonicalize_name(key), default)

    def handle_result(self, result):
        if isinstance(result, basestring):
            # A positional argument.
            self.target_specs.append(result)
            return
        elif result[0] == None:
            # An unknown option.
            self.extras.extend(result[1:])
            return

        # A normal option.
        opt, arg = result
        if opt in ("6", "A", "F", "h", "n", "R", "r", "V"):
            self["-" + opt] = True
        elif opt in (\
            "allports",
            "append-output",
            "badsum",
            "defeat-rst-ratelimit",
            "fuzzy",
            "help",
            "iflist",
            "log-errors",
            "no-stylesheet",
            "open",
            "osscan-guess",
            "osscan-limit",
            "packet-trace",
            "privileged",
            "randomize-hosts",
            "reason",
            "release-memory",
            "script-trace",
            "script-updatedb",
            "send-eth",
            "send-ip",
            "system-dns",
            "traceroute",
            "unprivileged",
            "version",
            "version-all",
            "version-light",
            "version-trace",
            "webxml",
            ):
            self["--" + opt] = True
        elif opt in ("b", "D", "e", "g", "i", "iL", "m", "M", "o", "oA", "oG", "oM", "oN", "oS", "oX", "p", "S", "sI"):
            assert arg is not None
            if self["-" + opt] is None:
                self["-" + opt] = arg
            else:
                self.extras.extend(("-" + opt, arg))
        elif opt in (\
            "datadir",
            "data-length",
            "dns-servers",
            "exclude",
            "excludefile",
            "host-timeout",
            "initial-rtt-timeout",
            "ip-options",
            "max-hostgroup",
            "max-os-tries",
            "max-parallelism",
            "max-rate",
            "max-retries",
            "max-rtt-timeout",
            "max-scan-delay",
            "min-hostgroup",
            "min-parallelism",
            "min-rate",
            "min-retries",
            "min-rtt-timeout",
            "mtu",
            "port-ratio",
            "scan-delay",
            "scanflags",
            "script",
            "script-args",
            "script-help",
            "servicedb",
            "source-port",
            "spoof-mac",
            "stylesheet",
            "top-ports",
            "ttl",
            "versiondb",
            "version-intensity",
            ):
            assert arg is not None
            if self["--" + opt] is None:
                self["--" + opt] = arg
            else:
                self.extras.extend(("--" + opt, arg))
        elif opt == "d" or opt == "debug":
            if arg is None:
                arg = ""
            try:
                self["-d"] = int(arg)
            except ValueError:
                if reduce(lambda x, y: x and y, map(lambda z: z == "d", arg), True):
                    self.setdefault("-d", 0)
                    self["-d"] += len(arg) + 1
                else:
                    self.extras.append("-d%s" % arg)
        elif opt == "f":
            self.setdefault("-f", 0)
            self["-f"] += 1
        elif opt == "iR":
            if self["-iR"] is None:
                try:
                    self["-iR"] = int(arg)
                except ValueError:
                    self.extras.extend(("-iR", arg))
            else:
                self.extras.extend(("-iR", arg))
        elif opt == "O":
            if arg is None:
                if self["-O"] is None:
                    self["-O"] = True
                else:
                    self.extras.append("-O")
            else:
                if self["-O"] is None:
                    self["-O"] = arg
                else:
                    self.extras.append("-O%s" % arg)
        elif opt == "P":
            type, ports = arg[:1], arg[1:]
            if type == "0" or type == "D" or type == "N" or type == "n" and ports == "":
                self["-Pn"] = True
            elif (type == "" or type == "I" or type == "E") and ports == "":
                self["-PE"] = True
            elif type == "M" and ports == "":
                self["-PM"] = True
            elif type == "P" and ports == "":
                self["-PP"] = True
            elif type == "R" and ports == "":
                self["-PR"] = True
            elif type == "S":
                self["-PS"] = ports
            elif type == "T" or type == "A":
                self["-PA"] = ports
            elif type == "U":
                self["-PU"] = ports
            elif type == "O":
                self["-PO"] = ports
            elif type == "B":
                self["-PB"] = ports
            elif type == "Y":
                self["-PY"] = ports
            else:
                self.extras.append("-P%s" % arg)
        elif opt == "s":
            for type in arg:
                if type in "ACFLMNOPRSTUVWXYZn":
                    self["-s%s" % type] = True
                else:
                    self.extras.append("-s%s" % type)
        elif opt == "T" or opt == "timing":
            if self["-T"] is None:
                try:
                    self["-T"] = int(arg)
                except ValueError:
                    try:
                        self["-T"] = self.TIMING_PROFILE_NAMES[arg.lower()]
                    except KeyError:
                        self.extras.extend(("-T", arg))
            else:
                self.extras.extend(("-T", arg))
        elif opt == "v" or opt == "verbose":
            if arg is None:
                arg = ""
            try:
                self["-v"] = int(arg)
            except ValueError:
                if reduce(lambda x, y: x and y, map(lambda z: z == "v", arg), True):
                    self.setdefault("-v", 0)
                    self["-v"] += len(arg) + 1
                else:
                    self.extras.append("-v%s" % arg)
        else:
            assert False, (opt, arg)

    def parse(self, opt_list):
        self.clear()

        if len(opt_list) > 0:
            self.executable = opt_list[0]

        for result in getopt_long_only_extras(opt_list[1:], self.SHORT_OPTIONS, self.LONG_OPTIONS):
            self.handle_result(result)

    def parse_string(self, opt_string):
        self.parse(split_quoted(opt_string))

    def render(self):
        opt_list = []

        for opt in ("-sA", "-sC", "-sF", "-sL", "-sM", "-sN", "-sO", "-sn", "-sR", "-sS", "-sT", "-sU", "-sV", "-sW", "-sX", "-sY", "-sZ"):
            if self[opt]:
                opt_list.append(opt)

        if self["-sI"] is not None:
            opt_list.extend(("-sI", self["-sI"]))

        for opt in ("-6",):
            if self[opt]:
                opt_list.append(opt)

        if self["-p"] is not None:
            opt_list.extend(("-p", self["-p"]))

        if self["-T"] is not None:
            opt_list.append("-T%s" % str(self["-T"]))

        if self["-O"] is not None:
            if isinstance(self["-O"], basestring):
                opt_list.append("-O%s" % self["-O"])
            elif self["-O"]:
                opt_list.append("-O")

        if self["-A"]:
            opt_list.append("-A")

        if self["-d"]:
            if self["-d"] == 1:
                opt_list.append("-d")
            elif self["-d"] > 1:
                opt_list.append("-d%s" % self["-d"])

        if self["-f"]:
            opt_list.extend(["-f"] * self["-f"])
        if self["-v"]:
            opt_list.extend(["-v"] * self["-v"])

        if self["-F"]:
            opt_list.append("-F")
        if self["-n"]:
            opt_list.append("-n")

        if self["-iL"] is not None:
            opt_list.extend(("-iL", self["-iL"]))
        if self["-iR"] is not None:
            opt_list.extend(("-iR", str(self["-iR"])))

        for opt in ("-oA", "-oG", "-oN", "-oS", "-oX"):
            if self[opt] is not None:
                opt_list.extend((opt, self[opt]))

        for opt in ("--min-hostgroup", "--max-hostgroup",
            "--min-parallelism", "--max-parallelism",
            "--min-rtt-timeout", "--max-rtt-timeout", "--initial-rtt-timeout",
            "--scan-delay", "--max-scan-delay",
            "--min-rate", "--max-rate",
            "--max-retries", "--max-os-tries", "--host-timeout"):
            if self[opt] is not None:
                opt_list.extend((opt, self[opt]))

        for ping_option in ("-Pn", "-PE", "-PM", "-PP", "-PR"):
            if self[ping_option]:
                opt_list.append(ping_option)
        for ping_option in ("-PS", "-PA", "-PU", "-PO", "-PY"):
            if self[ping_option] is not None:
                opt_list.append(ping_option + self[ping_option])
        if self["-PB"] is not None:
            if isinstance(self["-PB"], basestring):
                opt_list.append("-PB" + self["-PB"])
            elif self["-PB"]:
                opt_list.append("-PB")

        for opt in (\
            "--allports",
            "--append-output",
            "--badsum",
            "--defeat-rst-ratelimit",
            "--fuzzy",
            "--help",
            "--iflist",
            "--log-errors",
            "--no-stylesheet",
            "--open",
            "--osscan-guess",
            "--osscan-limit",
            "--packet-trace",
            "--privileged",
            "-r",
            "-R",
            "--randomize-hosts",
            "--reason",
            "--release-memory",
            "--script-trace",
            "--script-updatedb",
            "--send-eth",
            "--send-ip",
            "--system-dns",
            "--traceroute",
            "--unprivileged",
            "--version",
            "--version-all",
            "--version-light",
            "--version-trace",
            "--webxml",
            ):
            if self[opt]:
                opt_list.append(opt)

        for opt in (\
            "-b",
            "-D",
            "--datadir",
            "--data-length",
            "--dns-servers",
            "-e",
            "--exclude",
            "--excludefile",
            "-g",
            "--ip-options",
            "--mtu",
            "--port-ratio",
            "-S",
            "--scanflags",
            "--script",
            "--script-args",
            "--script-help",
            "--servicedb",
            "--spoof-mac",
            "--stylesheet",
            "--top-ports",
            "--ttl",
            "--versiondb",
            "--version-intensity",
            ):
            if self[opt] is not None:
                opt_list.extend((opt, self[opt]))

        opt_list.extend(self.target_specs)

        opt_list.extend(self.extras)

        return [self.executable] + opt_list

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
        self.assertTrue(type(ops.render()) == list, "type == %s" % type(ops.render))

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

    def test_underscores(self):
        """Test that underscores in option names are treated the same as
        dashes (and are canonicalized to dashes)."""
        ops = NmapOptions()
        ops.parse_string("nmap --osscan_guess")
        self.assertTrue("--osscan-guess" in ops.render_string())

    def test_args(self):
        """Test potentially tricky argument scenarios."""
        ops = NmapOptions()
        ops.parse_string("nmap -d9")
        self.assertTrue(len(ops.target_specs) == 0)
        self.assertTrue(ops["-d"] == 9, ops["-d"])
        ops.parse_string("nmap -d 9")
        self.assertTrue(ops.target_specs == ["9"])
        self.assertTrue(ops["-d"] == 1)

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
        self.assertTrue(ops["-p"] == "53")
        self.assertTrue(ops["--mtu"] == "50")
        self.assertTrue(ops["-O"])
        self.assertTrue(ops.extras == ["-p", "80", "--mtu", "100", "-O2"])

    def test_quirks(self):
        """Test the handling of constructions whose interpretation isn't
        specified in documentation, but should match that of GNU getopt."""
        ops = NmapOptions()
        # Long options can be written with one dash.
        ops.parse_string("nmap -min-rate 100")
        self.assertTrue(ops["--min-rate"] == "100")
        ops.parse_string("nmap -min-rate=100")
        self.assertTrue(ops["--min-rate"] == "100")

        # Short options not taking an argument can be followed by a long option.
        ops.parse_string("nmap -nFmin-rate 100")
        self.assertTrue(ops["-n"])
        self.assertTrue(ops["-F"])
        self.assertTrue(ops["--min-rate"] == "100")

        # Short options taking an argument consume the rest of the argument.
        ops.parse_string("nmap -nFp1-100")
        self.assertTrue(ops["-n"])
        self.assertTrue(ops["-F"])
        self.assertTrue(ops["-p"] == "1-100")

    def test_conversion(self):
        """Test that failed integer conversions cause the option to wind up in
        the extras."""
        ops = NmapOptions()
        ops.parse_string("nmap -d#")
        self.assertTrue(ops.extras == ["-d#"])
        ops.parse_string("nmap -T monkeys")
        self.assertTrue(ops["-T"] == None)
        self.assertTrue(ops.extras == ["-T", "monkeys"])
        ops.parse_string("nmap -iR monkeys")
        self.assertTrue(ops["-iR"] == None)
        self.assertTrue(ops.extras == ["-iR", "monkeys"])

    def test_read_unknown(self):
        """Test that getting the value of non-options returns None."""
        ops = NmapOptions()
        self.assertEqual(ops["-x"], None)
        self.assertEqual(ops["--nonoption"], None)

    def test_canonical_option_names(self):
        """Test that equivalent option names are properly canonicalized, so that
        ops["--timing"] and ops["-T"] mean the same thing, for example."""
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
            ("--min-rate", "-min-rate", "--min_rate", "-min_rate")
        )
        ops = NmapOptions()
        for set in EQUIVS:
            for opt in set:
                ops.clear()
                ops[opt] = "test"
                for other in set:
                    self.assertTrue(ops[other] == "test",
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
            self.assertTrue(len(ops.extras) == 0, "%s caused extras: %s" % (test, repr(ops.extras)))
            ops.parse(opt_list_1)
            opt_list_2 = ops.render()
            self.assertTrue(opt_list_1 == opt_list_2, "Result of parsing and rendering %s not parsable again" % test)
            self.assertTrue(len(ops.extras) == 0, "Result of parsing and rendering %s left extras: %s" % (test, ops.extras))

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

if __name__ == "__main__":
    doctest.testmod()
    unittest.main()
