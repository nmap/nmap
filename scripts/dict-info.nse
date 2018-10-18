local nmap = require "nmap"
local match = require "match"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Connects to a dictionary server using the DICT protocol, runs the SHOW
SERVER command, and displays the result. The DICT protocol is defined in RFC
2229 and is a protocol which allows a client to query a dictionary server for
definitions from a set of natural language dictionary databases.

The SHOW server command must be implemented and depending on access will show
server information and accessible databases. If authentication is required, the
list of databases will not be shown.
]]

---
-- @usage
-- nmap -p 2628 <ip> --script dict-info
--
-- @output
-- PORT     STATE SERVICE
-- 2628/tcp open  dict
-- | dict-info:
-- |   dictd 1.12.0/rf on Linux 3.0.0-12-generic
-- |   On ubu1110: up 15.000, 4 forks (960.0/hour)
-- |
-- |   Database      Headwords         Index          Data  Uncompressed
-- |   bouvier          6797        128 kB       2338 kB       6185 kB
-- |_  fd-eng-swe       5489         76 kB         77 kB        204 kB
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}


portrule = shortport.port_or_service(2628, "dict", "tcp")

local function fail(err) return stdnse.format_output(false, err) end

action = function(host, port)
  local socket = nmap.new_socket()
  if ( not(socket:connect(host, port)) ) then
    return fail("Failed to connect to dictd server")
  end

  local probes = {
    'client "dict 1.12.0/rf on Linux 3.0.0-12-generic"',
    'show server',
    'quit',
  }

  if ( not(socket:send(table.concat(probes, "\r\n") .. "\r\n")) ) then
    return fail("Failed to send request to server")
  end

  local srvinfo

  repeat
    local status, data = socket:receive_buf(match.pattern_limit("\r\n", 2048), false)
    if ( not(status) ) then
      return fail("Failed to read response from server")
    elseif ( data:match("^5") ) then
      return fail(data)
    elseif ( data:match("^114") ) then
      srvinfo = {}
    elseif ( srvinfo and not(data:match("^%.$")) ) then
      table.insert(srvinfo, data)
    end
  until(not(status) or data:match("^221") or data:match("^%.$"))
  socket:close()

  -- if last item is an empty string remove it, to avoid trailing line feed
  srvinfo[#srvinfo] = ( srvinfo[#srvinfo] ~= "" and srvinfo[#srvinfo] or nil )

  return stdnse.format_output(true, srvinfo)
end
