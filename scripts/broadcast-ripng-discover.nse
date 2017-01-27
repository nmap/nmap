local bin = require "bin"
local ipOps = require "ipOps"
local nmap = require "nmap"
local stdnse = require "stdnse"
local tab = require "tab"
local table = require "table"

description = [[
Discovers hosts and routing information from devices running RIPng on the
LAN by sending a broadcast RIPng Request command and collecting any responses.
]]

---
-- @usage
-- nmap --script broadcast-ripng-discover
--
-- @output
-- | broadcast-ripng-discover:
-- |   fe80::a00:27ff:fe9a:880c
-- |     route                       metric  next hop
-- |     fe80:470:0:0:0:0:0:0/64     1
-- |     fe80:471:0:0:0:0:0:0/64     1
-- |_    fe80:472:0:0:0:0:0:0/64     1
--
-- @args broadcast-ripng-discover.timeout sets the connection timeout
--       (default: 5s)

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"broadcast", "safe"}


prerule = function() return ( nmap.address_family() == "inet6" ) end

RIPng = {

  -- Supported RIPng commands
  Command = {
    Request = 1,
    Response = 2,
  },

  -- Route table entry
  RTE = {

    -- Creates a new Route Table Entry
    -- @param prefix string containing the ipv6 route prefix
    -- @param tag number containing the route tag
    -- @param prefix_len number containing the length in bits of the
    --        significant part of the prefix
    -- @param metric number containing the current metric for the
    --        destination
    new = function(self, prefix, tag, prefix_len, metric)
      local o = {
        prefix = prefix,
        tag = tag,
        prefix_len = prefix_len,
        metric = metric
      }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    -- Parses a byte string and creates an instance of RTE
    -- @param data string of bytes
    -- @return rte instance of RTE
    parse = function(data)
      local rte = RIPng.RTE:new()
      local pos, ip

      pos, ip, rte.tag, rte.prefix_len, rte.metric = bin.unpack(">A16SCC", data)
      ip = select(2, bin.unpack("B" .. #ip, ip))
      rte.prefix = ipOps.bin_to_ip(ip)
      return rte
    end,

    -- Converts a RTE instance to string
    -- @return string of bytes to send to the server
    __tostring = function(self)
      local ipstr = ipOps.ip_to_str(self.prefix)
      assert(16 == #ipstr, "Invalid IPv6 address encountered")
      return bin.pack(">ASCC", ipstr, self.tag, self.prefix_len, self.metric)
    end,


  },

  -- The Request class contains functions to build a RIPv2 Request
  Request = {

    -- Creates a new Request instance
    --
    -- @param command number containing the RIPv2 Command to use
    -- @return o instance of request
    new = function(self, entries)
      local o = {
        command = 1,
        version = 1,
        entries = entries,
      }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    -- Converts the whole request to a string
    __tostring = function(self)
      local RESERVED = 0
      local str = {bin.pack(">CCS", self.command, self.version, RESERVED)}
      for _, rte in ipairs(self.entries) do
        str[#str+1] = tostring(rte)
      end
      return table.concat(str)
    end,

  },

  -- A RIPng Response
  Response = {

    -- Creates a new Response instance
    -- @return o new instance of Response
    new = function(self)
      local o = {  }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    -- Creates a new Response instance based on a string of bytes
    -- @return resp new instance of Response
    parse = function(data)
      local resp = RIPng.Response:new()
      local pos, _

      pos, resp.command, resp.version, _ = bin.unpack(">CCS", data)
      resp.entries = {}
      while( pos < #data ) do
        local e = RIPng.RTE.parse(data:sub(pos))
        table.insert(resp.entries, e)
        pos = pos + 20
      end

      return resp
    end,
  }
}

local function fail(err) return stdnse.format_output(false, err) end

-- Parses a RIPng response
-- @return ret string containing the routing table
local function parse_response(resp)
  local next_hop
  local result = tab.new(3)
  tab.addrow(result, "route", "metric", "next hop")
  for _, rte in pairs(resp.entries or {}) do
    -- next hop information is specified in a separate RTE according to
    -- RFC 2080 section 2.1.1
    if ( 0xFF == rte.metric ) then
      next_hop = rte.prefix
    else
      tab.addrow(result, ("%s/%d"):format(rte.prefix, rte.prefix_len), rte.metric, next_hop or "")
    end
  end
  return tab.dump(result)
end

action = function()

  local req = RIPng.Request:new( { RIPng.RTE:new("0::", 0, 0, 16) } )
  local host, port = "FF02::9", { number = 521, protocol = "udp" }
  local iface = nmap.get_interface()
  local timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME..".timeout"))
  timeout = (timeout or 5) * 1000

  local sock = nmap.new_socket("udp")
  sock:bind(nil, 521)
  sock:set_timeout(timeout)

  local status = sock:sendto(host, port, tostring(req))

  -- do we need to add the interface name to the address?
  if ( not(status) ) then
    if ( not(iface) ) then
      return fail("Couldn't determine what interface to use, try supplying it with -e")
    end
    status = sock:sendto(host .. "%" .. iface, port, tostring(req))
  end

  if ( not(status) ) then
    return fail("Failed to send request to server")
  end

  local responses = {}
  while(true) do
    local status, data = sock:receive()
    if ( not(status) ) then
      break
    else
      local status, _, _, rhost = sock:get_info()
      if ( not(status) ) then
        rhost = "unknown"
      end
      responses[rhost] = RIPng.Response.parse(data)
    end
  end

  local result = {}
  for ip, resp in pairs(responses) do
    stdnse.debug1(ip, resp)
    table.insert(result, { name = ip, parse_response(resp) } )
  end
  return stdnse.format_output(true, result)
end
