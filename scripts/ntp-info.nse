local bin = require "bin"
local comm = require "comm"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

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
-- @output
-- PORT    STATE SERVICE VERSION
-- 123/udp open  ntp     NTP v4
-- | ntp-info:  
-- |   receive time stamp: Sat Dec 12 16:22:41 2009
-- |   version: ntpd 4.2.4p4@1.1520-o Wed May 13 21:06:31 UTC 2009 (1)
-- |   processor: x86_64
-- |   system: Linux/2.6.24-24-server
-- |   stratum: 2
-- |_  refid: 195.145.119.188


author = "Richard Sammet"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}



portrule = shortport.port_or_service(123, "ntp", {"udp", "tcp"})

-- This script run against open|filtered ports, so don't wait too long if
-- there's no response.
local TIMEOUT = 5000

-- Transform an array into a table where the array's values all map to true.
local function make_set(a)
  local i, v, result
  result = {}
  for i, v in ipairs(a) do
    result[v] = true
  end
  return result
end

-- Only these fields from the response are displayed with default verbosity.
local DEFAULT_FIELDS = make_set({"version", "processor", "system", "refid", "stratum"})

action = function(host, port)
  local status
  local buftres, bufrlres
  local output = {}

  -- This is a ntp v4 mode3 (client) date/time request.
  local treq = string.char(0xe3, 0x00, 0x04, 0xfa, 0x00, 0x01, 0x00, 0x00, 
                           0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                           0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00)

  -- This is a ntp v2 mode6 (control) rl (readlist/READVAR(2)) request. See
  -- appendix B of RFC 1305.
  local rlreq = string.char(0x16, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00)

  status, buftres = comm.exchange(host, port, treq, {proto=port.protocol, timeout=TIMEOUT})
  if not status then
    -- Don't try the second probe if this one didn't work.
    return nil
  else
    local _, sec, frac, tstamp

    _, sec, frac = bin.unpack(">II", buftres, 33)
    -- The NTP epoch is 1900-01-01, so subtract 70 years to bring the date into
    -- the range Lua expects. The number of seconds at 1970-01-01 is taken from
    -- the NTP4 reference above.
    tstamp = sec - 2208988800 + frac / 0x10000000

    table.insert(output, string.format("receive time stamp: %s", stdnse.format_timestamp(tstamp)))
  end

  status, bufrlres = comm.exchange(host, port, rlreq, {proto=port.protocol, timeout=TIMEOUT})

  if status then
    -- This only looks at the first fragment of what can possibly be several
    -- fragments in the response.
    local _, data, k, q, v

    -- Skip the first 10 bytes of the header, then get the data which is
    -- preceded by a 2-byte length.
    _, data = bin.unpack(">P", bufrlres, 11)

    -- This parsing is not quite right with respect to quoted strings.
    -- Backslash escapes should be interpreted inside strings and commas should
    -- be allowed inside them.
    for k, q, v in string.gmatch(data, "%s*(%w+)=(\"?)([^,\"]*)%2,?") do
      if DEFAULT_FIELDS[k] or nmap.verbosity() then
        table.insert(output, string.format("%s: %s", k, v))
      end
    end
  end

  if(#output > 0) then
    nmap.set_port_state(host, port, "open")
    return stdnse.format_output(true, output)
  else
    return nil
  end
end
