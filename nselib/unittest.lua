---
-- Unit testing support for NSE libraries.
--
-- This library will import all NSE libraries looking for a global variable
-- <code>test_suite</code>. This must be a callable that returns true or false
-- and the number of tests that failed. For convenience, the
-- <code>unittest.TestSuite</code> class has this property, and tests can be
-- added with <code>add_test</code>. Example:
--
-- <code>
-- local data = {"foo", "bar", "baz"}
-- test_suite = unittest.TestSuite:new()
-- test_suite:add_test(equal(data[2], "bar"), "data[2] should equal 'bar'")
-- </code>
--
-- The library is driven by the unittest NSE script.
--
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html

local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local nmap = require "nmap"
local nsedebug = require "nsedebug"
local listop = require "listop"
_ENV = stdnse.module("unittest", stdnse.seeall)

local libs = {
"afp",
"ajp",
"amqp",
"anyconnect",
"asn1",
"base32",
"base64",
"bitcoin",
"bits",
"bittorrent",
"bjnp",
"brute",
"cassandra",
"citrixxml",
"coap",
"comm",
"creds",
"cvs",
"datafiles",
"datetime",
"dhcp",
"dhcp6",
"dns",
"dnsbl",
"dnssd",
"drda",
"eap",
"eigrp",
"formulas",
"ftp",
"geoip",
"giop",
"gps",
"http",
"httpspider",
"iax2",
"idna",
"ike",
"imap",
"informix",
"ipOps",
"ipmi",
"ipp",
"irc",
"iscsi",
"isns",
"jdwp",
"json",
"knx",
"ldap",
"lfs",
"libssh2",
"libssh2-utility",
"listop",
"lpeg",
"lpeg-utility",
"ls",
"match",
"membase",
"mobileme",
"mongodb",
"mqtt",
"msrpc",
"msrpcperformance",
"msrpctypes",
"mssql",
"multicast",
"mysql",
"natpmp",
"nbd",
"ncp",
"ndmp",
"netbios",
"nmap",
"nrpc",
"nsedebug",
"omp2",
"openssl",
"ospf",
"outlib",
"packet",
"pcre",
"pgsql",
"pop3",
"pppoe",
"proxy",
"punycode",
"rand",
"rdp",
"re",
"redis",
"rmi",
"rpc",
"rpcap",
"rsync",
"rtsp",
"sasl",
"shortport",
"sip",
"slaxml",
"smb",
"smb2",
"smbauth",
"smtp",
"snmp",
"socks",
"srvloc",
"ssh1",
"ssh2",
"sslcert",
"sslv2",
"stdnse",
"strbuf",
--"strict", -- behaves oddly
"stringaux",
"stun",
"tab",
"tableaux",
"target",
"tftp",
"tls",
"tn3270",
"tns",
"unicode",
"unittest",
"unpwdb",
"upnp",
"url",
"versant",
"vnc",
"vulns",
"vuzedht",
"wsdd",
"xdmcp",
"xmpp",
"zlib",
}

-- This script-arg is documented in the unittest script to avoid cluttering
-- NSEdoc of all the libraries which include this one.
local am_testing = stdnse.get_script_args('unittest.run')
---Check whether tests are being run
--
-- Libraries can use this function to avoid the overhead of creating tests if
-- the user hasn't chosen to run them. Unittesting is turned on with the
-- <code>unittest.run</code> script-arg.
-- @return true if unittests are being run, false otherwise.
function testing()
  return am_testing
end

---
-- Run tests provided by NSE libraries
-- @param to_test A list (table) of libraries to test. If none is provided, all
--                libraries are tested.
run_tests = function(to_test)
  am_testing = true
  if to_test == nil then
    to_test = libs
  end
  local fails = stdnse.output_table()
  for _,lib in ipairs(to_test) do
    stdnse.debug1("Testing %s", lib)
    local status, thelib = pcall(require, lib)
    if not status then
      fails[lib] = ("Failed to load: %s"):format(thelib)
    else
      local failed = 0
      if rawget(thelib,"test_suite") ~= nil then
        failed = thelib.test_suite()
      end
      if failed ~= 0 then
        fails[lib] = failed
      end
    end
  end
  return fails
end

--- The TestSuite class
--
-- Holds and runs tests.
TestSuite = {

  --- Creates a new TestSuite object
  --
  -- @name TestSuite.new
  -- @return TestSuite object
  new = function(self)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.tests = {}
    return o
  end,

  --- Set up test environment. Override this.
  -- @name TestSuite.setup
  setup = function(self)
    return true
  end,
  --- Tear down test environment. Override this.
  -- @name TestSuite.teardown
  teardown = function(self)
    return true
  end,
  --- Add a test.
  -- @name TestSuite.add_test
  -- @param test Function that will be called with the TestSuite object as its only parameter.
  -- @param description A description of the test being run
  add_test = function(self, test, description)
    self.tests[#self.tests+1] = {test, description}
  end,

  --- Run tests.
  -- Runs all tests in the TestSuite, and returns the number of failures.
  -- @name TestSuite.__call
  -- @return failures The number of tests that failed
  -- @return tests The number of tests run
  __call = function(self)
    local failures = 0
    local passes = 0
    self:setup()
    for _,test in ipairs(self.tests) do
      stdnse.debug2("| Test: %s...", test[2])
      local status, note = test[1](self)
      local result
      local lvl = 2
      if status then
        result = "Pass"
        passes = passes + 1
      else
        result = "Fail"
        lvl = 1
        if nmap.debugging() < 2 then
          stdnse.debug1("| Test: %s...", test[2])
        end
        failures = failures + 1
      end
      if note then
        stdnse.debug(lvl, "| \\_result: %s (%s)", result, note)
      else
        stdnse.debug(lvl, "| \\_result: %s", result)
      end
    end
    stdnse.debug1("|_%d of %d tests passed", passes, #self.tests)
    self:teardown()
    return failures, #self.tests
  end,
}

--- Test creation helper function.
--  Turns a simple function into a test factory.
--  @param test A function that returns true or false depending on test
--  @param fmt A format string describing the failure condition using the
--             arguments to the test function
--  @return function that generates tests suitable for use in add_test
make_test = function(test, fmt)
  return function(...)
    local args={...}
    local nargs = select("#", ...)
    return function(suite)
      if not test(table.unpack(args,1,nargs)) then
        return false, string.format(fmt, table.unpack(listop.map(nsedebug.tostr, args),1,nargs))
      end
      return true
    end
  end
end

--- Test for nil
-- @param value The value to test
-- @return bool True if the value is nil, false otherwise.
is_nil = function(value)
  return value == nil
end
is_nil = make_test(is_nil, "Expected nil, got %s")

--- Test for not nil
-- @param value The value to test
-- @return bool True if the value is not nil, false otherwise.
not_nil = function(value)
  return value ~= nil
end
not_nil = make_test(not_nil, "Expected not nil, got %s")

--- Test for Lua type
-- @param typ The type that value should be
-- @param value The value to test
-- @return bool True if type(value) == typ
type_is = function (typ, value)
  return type(value) == typ
end
type_is = make_test(type_is, "Value is not a '%s': %s")

--- Test tables for equality, 1 level deep
-- @param a The first table to test
-- @param b The second table to test
-- @return bool True if #a == #b and a[i] == b[i] for every i<#a, false otherwise.
table_equal = function(a, b)
  return function (suite)
    if #a ~= #b then
      return false, "Length not equal"
    end
    for i, v in ipairs(a) do
      if b[i] ~= v then
        return false, string.format("%s ~= %s at position %d", v, b[i], i)
      end
    end
    return true
  end
end

--- Test associative tables for equality, 1 level deep
-- @param a The first table to test
-- @param b The second table to test
-- @return bool True if a[k] == b[k] for all k in a and b
keys_equal = function(a, b)
  return function (suite)
    local seen = {}
    for k, v in pairs(a) do
      if b[k] ~= v then
        return false, ("%s ~= %s at key %s"):format(v, b[k], k)
      end
      seen[k] = true
    end
    for k, v in pairs(b) do
      if not seen[k] then
        return false, ("Key %s not present in table a"):format(k)
      end
    end
    return true
  end
end

--- Test two values for equality, recursively if necessary.
--
-- This function checks that both values are indistinguishable in all
-- but memory location.
--
-- @param a The first value to test.
-- @param b The second value to test
-- @return bool True if values are indistinguishable, false otherwise.
-- @return note Nil if values are indistinguishable, description of
--         distinguishability otherwise.
identical = function(a, b)
  return function(suite)
    local function _identical(val1, val2, path)
      local table_size = function(tbl)
        local count = 0
        for k in pairs(tbl) do
          count = count + 1
        end
        return count
      end

      -- Both values must be of the same type
      local t1, t2 = type(val1), type(val2)
      if t1 ~= t2 then
        return false, string.format("Types of %s are not equal: %s ~= %s", path, t1, t2)
      end

      -- For non-tables, we can make a direct comparison.
      if t1 ~= "table" then
        if val1 ~= val2 then
          return false, string.format("Values of %s are not equal: %s ~= %s", path, val1, val2)
        end
        return true
      end

      -- For tables, we must first check that they are of equal size.
      local len1, len2 = table_size(val1), table_size(val2)
      if len1 ~= len2 then
        return false, string.format("Sizes of %s are not equal: %s ~= %s", path, len1, len2)
      end

      -- Finally, we must recursively check all of the values in the tables.
      for k,v in pairs(val1) do
        -- Check that the key's value is identical in both tables, passing
        -- along the path of keys we have taken to get here.
        local status, note = _identical(val1[k], val2[k], string.format('%s["%s"]', path, k))
        if not status then
          return false, note
        end
      end

      return true
    end

    return _identical(a, b, "<top>")
  end
end

--- Test for equality
-- @param a The first value to test
-- @param b The second value to test
-- @return bool True if a == b, false otherwise.
equal = function(a, b)
  return a == b
end
equal = make_test(equal, "%s not equal to %s")

--- Test for inequality
-- @param a The first value to test
-- @param b The second value to test
-- @return bool True if a != b, false otherwise.
not_equal = function(a, b)
  return a ~= b
end
not_equal = make_test(not_equal, "%s unexpectedly equal to %s")

--- Test for truth
-- @param value The value to test
-- @return bool True if value is a boolean and true
is_true = function(value)
  return value == true
end
is_true = make_test(is_true, "Expected true, got %s")

--- Test for falsehood
-- @param value The value to test
-- @return bool True if value is a boolean and false
is_false = function(value)
  return value == false
end
is_false = make_test(is_false, "Expected false, got %s")

--- Test less than
-- @param a The first value to test
-- @param b The second value to test
-- @return bool True if a < b, false otherwise.
lt = function(a, b)
  return a < b
end
lt = make_test(lt, "%s not less than %s")

--- Test less than or equal to
-- @param a The first value to test
-- @param b The second value to test
-- @return bool True if a <= b, false otherwise.
lte = function(a, b)
  return a <= b
end
lte = make_test(lte, "%s not less than %s")

--- Test length
-- @param t The table to test
-- @param l The length to test
-- @return bool True if the length of t is l
length_is = function(t, l)
  return #t == l
end
length_is = make_test(length_is, "Length of %s is not %s")

--- Expected failure test
-- @param test The test to run
-- @return function A test for expected failure of the test
expected_failure = function(test)
  return function(suite)
    if test(suite) then
      return false, "Test unexpectedly passed"
    end

    return true, "Test failed as expected"
  end
end


if not testing() then
  return _ENV
end

-- Self test
test_suite = TestSuite:new()

test_suite:add_test(is_nil(test_suite["asdfdoesnotexist"]), "Nonexistent key does not exist")
test_suite:add_test(equal(1+1336, 7 * 191), "Arithmetically equal expressions are equal")
test_suite:add_test(not_equal( true, "true" ), "Boolean true not equal to string \"true\"")
test_suite:add_test(is_true("test" == "test"), "Boolean expression evaluates to true")
test_suite:add_test(is_false(1.9999 == 2.0), "Boolean expression evaluates to false")
test_suite:add_test(lt(1, 999), "1 < 999")
test_suite:add_test(lte(8, 8), "8 <= 8")
test_suite:add_test(expected_failure(not_nil(nil)), "Test expected to fail fails")
test_suite:add_test(expected_failure(expected_failure(is_nil(nil))), "Test expected to succeed does not fail")
test_suite:add_test(keys_equal({one=1,two=2,[3]="three"},{[3]="three",one=1,two=2}), "identical tables are identical")
test_suite:add_test(expected_failure(keys_equal({one=1,two=2},{[3]="three",one=1,two=2}), "dissimilar tables are dissimilar"))
test_suite:add_test(identical(0, 0), "integer === integer")
test_suite:add_test(identical(nil, nil), "nil === nil")
test_suite:add_test(identical({}, {}), "{} === {}")
test_suite:add_test(type_is("table", {}), "{} is a table")
test_suite:add_test(length_is(test_suite.tests, 16), "Number of tests is 16")

return _ENV;
