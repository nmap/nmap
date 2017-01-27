local bin = require "bin"
local ipOps = require "ipOps"
local nmap = require "nmap"
local stdnse = require "stdnse"
local tab = require "tab"
local table = require "table"

description=[[
Discovers hosts and routing information from devices running RIPv2 on the
LAN. It does so by sending a RIPv2 Request command and collects the responses
from all devices responding to the request.
]]

---
-- @usage
-- nmap --script broadcast-rip-discover
--
-- @output
-- Pre-scan script results:
-- | broadcast-rip-discover:
-- | Discovered RIPv2 devices
-- |   10.0.200.107
-- |     ip           netmask        nexthop       metric
-- |     10.46.100.0  255.255.255.0  0.0.0.0       1
-- |     10.46.110.0  255.255.255.0  0.0.0.0       1
-- |     10.46.120.0  255.255.255.0  0.0.0.0       1
-- |     10.46.123.0  255.255.255.0  10.0.200.123  1
-- |     10.46.124.0  255.255.255.0  10.0.200.124  1
-- |     10.46.125.0  255.255.255.0  10.0.200.125  1
-- |   10.0.200.101
-- |     ip       netmask  nexthop     metric
-- |_    0.0.0.0  0.0.0.0  10.0.200.1  1
--
-- @args broadcast-rip-discover.timeout timespec defining how long to wait for
--       a response. (default 5s)

--
-- Version 0.1
-- Created 29/10/2011 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"broadcast", "safe"}


prerule = function() return not( nmap.address_family() == "inet6") end

RIPv2 = {

  Command = {
    Request = 1,
    Response = 2,
  },

  AddressFamily = {
    IP = 2,
  },

  -- The Request class contains functions to build a RIPv2 Request
  Request = {

    -- Creates a new Request instance
    --
    -- @param command number containing the RIPv2 Command to use
    -- @return o instance of request
    new = function(self, command)
      local o = {
        version = 2,
        command = command,
        domain = 0,
        family = 0,
        tag =  0,
        address = 0,
        subnet = 0,
        nexthop = 0,
        metric = 16
      }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    -- Converts the whole request to a string
    __tostring = function(self)
      assert(self.command, "No command was supplied")
      assert(self.metric, "No metric was supplied")
      assert(self.address, "No address was supplied")
      local RESERVED = 0
      -- RIPv2 stuff, should be 0 for RIPv1
      local tag, subnet, nexthop = 0, 0, 0

      local data = bin.pack(">CCSSSIIII",
        self.command, self.version, self.domain, self.family, self.tag,
        self.address, self.subnet, self.nexthop, self.metric)

      return data
    end,

  },

  -- The Response class contains code needed to parse a RIPv2 response
  Response = {

    -- Creates a new Response instance based on raw socket data
    --
    -- @param data string containing the raw socket response
    -- @return o Response instance
    new = function(self, data)
      local o = { data = data }

      if ( not(data) or #data < 3 ) then
        return
      end
      local pos
      pos, o.command, o.version = bin.unpack(">CCS", data)
      if ( o.command ~= RIPv2 and o.version ~= 2 ) then
        return
      end

      local routes = tab.new(2)
      tab.addrow(routes, "ip", "netmask", "nexthop", "metric")

      while( #data - pos >= 20 ) do
        local family, address, metric, _, netmask, nexthop
        pos, family, _, address, netmask, nexthop,
          metric = bin.unpack(">SS<III>I", data, pos)

        if ( family == RIPv2.AddressFamily.IP ) then
          local ip = ipOps.fromdword(address)
          netmask = ipOps.fromdword(netmask)
          nexthop = ipOps.fromdword(nexthop)
          tab.addrow(routes, ip, netmask, nexthop, metric)
        end
      end

      if ( #routes > 1 ) then o.routes = routes end

      setmetatable(o, self)
      self.__index = self
      return o
    end,

  }

}


action = function()
  local timeout = stdnse.parse_timespec(stdnse.get_script_args('broadcast-rip-discover.timeout'))
  timeout = (timeout or 5) * 1000

  local socket = nmap.new_socket("udp")
  socket:set_timeout(timeout)

  local rip = RIPv2.Request:new(RIPv2.Command.Request)
  local status, err = socket:sendto("224.0.0.9",
    { number = 520, protocol = "udp" },
    tostring(rip))
  local result = {}
  repeat
    local data
    status, data = socket:receive()
    if ( status ) then
      local status, _, _, rhost, _ = socket:get_info()
      local response = RIPv2.Response:new(data)
      table.insert(result, rhost)

      if ( response and response.routes and #response.routes > 0 ) then
        --response.routes.name = "Routes"
        table.insert(result, { tab.dump(response.routes) } )
      end

    end
  until( not(status) )

  if ( #result > 0 ) then
    result.name = "Discovered RIPv2 devices"
  end
  return stdnse.format_output(true, result)
end
