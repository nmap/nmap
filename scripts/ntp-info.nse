local bin = require "bin"
local comm = require "comm"
local datetime = require "datetime"
local os = require "os"
local math = require "math"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local lpeg = require "lpeg"
local U = require "lpeg-utility"

description = [[
Gets the time and configuration variables from an NTP server. We send two
requests: a time request and a "read variables" (opcode 2) control message.
Without verbosity, the script shows the time and the value of the
<code>version</code>, <code>processor</code>, <code>system</code>,
<code>refid</code>, and <code>stratum</code> variables. With verbosity, all
variables are shown.

See RFC 1035 and the Network Time Protocol Version 4 Reference and
Implementation Guide
(http://www.eecis.udel.edu/~mills/database/reports/ntp4/ntp4.pdf) for
documentation of the protocol.
]]

---
-- @usage
-- nmap -sU -p 123 --script ntp-info <target>
-- @output
-- PORT    STATE SERVICE VERSION
-- 123/udp open  ntp     NTP v4.2.4p4@1.1520-o
-- | ntp-info:
-- |   receive time stamp: Sat Dec 12 16:22:41 2009
-- |   version: ntpd 4.2.4p4@1.1520-o Wed May 13 21:06:31 UTC 2009 (1)
-- |   processor: x86_64
-- |   system: Linux/2.6.24-24-server
-- |   stratum: 2
-- |_  refid: 195.145.119.188
--
-- @xmloutput
-- <elem key="receive time stamp">2013-10-18T18:03:05</elem>
-- <elem key="version">ntpd 4.2.6p3@1.2290-o Tue Jun  5 20:12:11 UTC 2012 (1)</elem>
-- <elem key="processor">i686</elem>
-- <elem key="system">Linux/3.9.3-24</elem>
-- <elem key="leap">3</elem>
-- <elem key="stratum">16</elem>
-- <elem key="precision">-20</elem>
-- <elem key="rootdelay">0.000</elem>
-- <elem key="rootdisp">2502.720</elem>
-- <elem key="refid">INIT</elem>
-- <elem key="reftime">0x00000000.00000000</elem>
-- <elem key="clock">0xd60bf655.4cc0ba51</elem>
-- <elem key="peer">0</elem>
-- <elem key="tc">3</elem>
-- <elem key="mintc">3</elem>
-- <elem key="offset">0.000</elem>
-- <elem key="frequency">-46.015</elem>
-- <elem key="jitter">0.001</elem>
-- <elem key="wander">0.000</elem>

author = "Richard Sammet"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}



portrule = shortport.port_or_service(123, "ntp", {"udp", "tcp"})

-- This script run against open|filtered ports, so don't wait too long if
-- there's no response.
local TIMEOUT = 5000

-- Only these fields from the response are displayed with default verbosity.
local DEFAULT_FIELDS = {"version", "processor", "system", "refid", "stratum"}

-- comma-space-separated key=value pairs with optional quotes
local kvmatch = U.localize( {
    lpeg.V "space"^0 * lpeg.V "kv" * lpeg.P ","^-1,
    kv = lpeg.V "key" * lpeg.P "="^-1 * lpeg.V "value",
    key = lpeg.C( (lpeg.V "alnum" + lpeg.S "_-.")^1 ),
    value = U.escaped_quote() + lpeg.C((lpeg.P(1) - ",")^0),
  } )

action = function(host, port)
  local status
  local buftres, bufrlres
  local output = stdnse.output_table()

  -- This is a ntp v2 mode3 (client) date/time request.
  local treq = string.char(0xd3, 0x00, 0x04, 0xfa, 0x00, 0x01, 0x00, 0x00,
                           0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00)

  -- This is a ntp v2 mode6 (control) rl (readlist/READVAR(2)) request. See
  -- appendix B of RFC 1305.
  local rlreq = string.char(0x16, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00)

  status, buftres = comm.exchange(host, port, treq, {timeout=TIMEOUT})
  if status then
    local recvtime = os.time()

    local _, sec, frac = bin.unpack(">II", buftres, 33)
    -- The NTP epoch is 1900-01-01, so subtract 70 years to bring the date into
    -- the range Lua expects. The number of seconds at 1970-01-01 is taken from
    -- the NTP4 reference above.
    local tstamp = sec - 2208988800 + frac / 0x10000000

    datetime.record_skew(host, tstamp, recvtime)

    output["receive time stamp"] = stdnse.format_timestamp(tstamp)
  end

  status, bufrlres = comm.exchange(host, port, rlreq, {timeout=TIMEOUT})

  if status then
    -- This only looks at the first fragment of what can possibly be several
    -- fragments in the response.
    local _, data, k, q, v

    -- Skip the first 10 bytes of the header, then get the data which is
    -- preceded by a 2-byte length.
    _, data = bin.unpack(">P", bufrlres, 11)

    -- loop over capture pairs which represent (key, value)
    local function accumulate_output (...)
      local k, v = ...
      if k == nil then return end
      output[k] = v
      return accumulate_output(select(3, ...))
    end

    -- do the match and accumulate the captures
    local list = kvmatch^0 / accumulate_output
    list:match(data)
  end

  if(#output > 0) then
    stdnse.debug1("Test len: %d", #output)
    nmap.set_port_state(host, port, "open")
    if output['version'] then
      -- Look for the version string from the official ntpd and format it
      -- in a manner similar to the output of the standard Nmap version detection
      local version_num = string.match(output['version'],"^ntpd ([^ ]+)")
      if version_num then
        port.version.version = "v" .. version_num
        nmap.set_port_version(host, port, "hardmatched")
      end
    end
    if output['system'] then
      port.version.ostype = output['system']
      nmap.set_port_version(host, port, "hardmatched")
    end
    if nmap.verbosity() < 1 then
      local mt = getmetatable(output)
      mt["__tostring"] = function(t)
        local out = {}
        for _,k in ipairs(DEFAULT_FIELDS) do
          if output[k] ~= nil then
            table.insert(out, ("%s: %s"):format(k, output[k]))
          end
        end
        return "\n  " .. table.concat(out, "\n  ")
      end
    end
    return output
  else
    return nil
  end
end
