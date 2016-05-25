local os = require "os"
local stdnse = require "stdnse"
local table = require "table"
local xdmcp = require "xdmcp"

description = [[
Discovers servers running the X Display Manager Control Protocol (XDMCP) by
sending a XDMCP broadcast request to the LAN. Display managers allowing access
are marked using the keyword Willing in the result.
]]

---
-- @usage
-- nmap --script broadcast-xdmcp-discover
--
-- @output
-- Pre-scan script results:
-- | broadcast-xdmcp-discover:
-- |_  192.168.2.162 - Willing
--
-- @args broadcast-xdmcp-discover.timeout socket timeout (default: 5s)

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"broadcast", "safe"}


prerule = function() return true end

local arg_timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME .. ".timeout"))

action = function()

  local host, port = { ip = "255.255.255.255" }, { number = 177, protocol = "udp" }
  local options = { timeout = 1 }
  local helper = xdmcp.Helper:new(host, port, options)
  local status = helper:connect()

  local req = xdmcp.Packet[xdmcp.OpCode.BCAST_QUERY]:new(nil)
  local status, err = helper:send(req)
  if ( not(status) ) then
    return false, err
  end

  local timeout = arg_timeout or 5
  local start = os.time()
  local result = {}
  repeat

    local status, response = helper:recv()
    if ( not(status) and response ~= "TIMEOUT" ) then
      break
    elseif ( status ) then
      local status, _, _, rhost = helper.socket:get_info()
      if ( response.header.opcode == xdmcp.OpCode.WILLING ) then
        result[rhost] = true
      else
        result[rhost] = false
      end
    end

  until( os.time() - start > timeout )

  local output = {}
  for ip, res in pairs(result) do
    if ( res ) then
      table.insert(output, ("%s - Willing"):format(ip))
    else
      table.insert(output, ("%s - Unwilling"):format(ip))
    end
  end
  return stdnse.format_output(true, output)
end
