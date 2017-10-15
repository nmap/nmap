local bin = require "bin"
local bit = require "bit"
local nmap = require "nmap"
local os = require "os"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Discovers Sybase Anywhere servers on the LAN by sending broadcast discovery messages.
]]

---
-- @usage
-- nmap --script broadcast-sybase-asa-discover
--
-- @output
-- Pre-scan script results:
-- | broadcast-sybase-asa-discover:
-- |   ip=192.168.0.1; name=mysqlanywhere1; port=2638
-- |_  ip=192.168.0.2; name=mysqlanywhere2; port=49152
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "broadcast", "safe" }

prerule = function() return ( nmap.address_family() == "inet") end

--
-- The following code is a bit overkill and is meant to go into a library once
-- more scripts that make use of it are developed.
--
Ping = {

  -- The PING request class
  Request = {

    -- Creates a new Ping request
    new = function(self)
      local o = {}
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    -- returns the ping request as a string
    __tostring = function(self)
      return bin.pack("HAH", "1b00003d0000000012", "CONNECTIONLESS_TDS",
      "000000010000040005000500000102000003010104080000000000000000070204b1")
    end
  },

  -- The Ping Response class
  Response = {
    -- Creates a new response
    -- @param data string containing the raw data as received over the socket
    -- @return o instance of Response
    new = function(self, data)
      local o = { data = data }
      setmetatable(o, self)
      self.__index = self
      o:parse()
      if ( o.dbinstance ) then
        return o
      end
    end,

    -- Parses the raw response and populates the
    -- <code>dbinstance.name</code> and <code>dbinstance.port</code> fields
    parse = function(self)
      -- do a very basic length check
      local pos, len = bin.unpack(">I", self.data)
      len = bit.band(len, 0x0000FFFF)

      if ( len ~= #self.data ) then
        stdnse.debug2("The packet length was reported as %d, expected %d", len, #self.data)
        return
      end

      local connectionless_tds
      pos, connectionless_tds = bin.unpack("p", self.data, 9)
      if ( connectionless_tds ~= "CONNECTIONLESS_TDS" ) then
        stdnse.debug2("Did not find the expected CONNECTIONLESS_TDS header")
        return
      end

      self.dbinstance = {}
      pos, self.dbinstance.name = bin.unpack("p", self.data, 40)
      pos = pos + 2
      pos, self.dbinstance.port = bin.unpack(">S", self.data, pos)
    end,
  }

}

-- Main script interface
Helper = {

  -- Creates a new helper instance
  -- @param host table as received by the action method
  -- @param port table as received by the action method
  -- @param options table containing:
  --   <code>timeout</code> - the amount of time to listen for responses
  -- @return o instance of Helper
  new = function(self, host, port, options)
    local o = {
      host = host,
      port = port,
      options = options or {}
    }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  -- Sends a ping request to the service and processes the response
  -- @return status true on success, false on failure
  -- @return instances table of instance tables containing
  --  <code>name</code> - the instance name
  --  <code>ip</code> - the instance ip
  --  <code>port</code> - the instance port
  --         err string containing error message on failure
  ping = function(self)
    local socket = nmap.new_socket("udp")
    socket:set_timeout(1000)

    -- send 2 packets just in case
    for i=1, 2 do
      local ping_req = Ping.Request:new()
      local status, err = socket:sendto(self.host, self.port, tostring(ping_req))
      if ( not(status) ) then
        return false, "Failed to send broadcast packet"
      end
    end

    local stime = os.time()
    local instances = {}
    local timeout = self.options.timeout or ( 20 / ( nmap.timing_level() + 1 ) )

    repeat
      local status, data = socket:receive()
      if ( status ) then
        local response = Ping.Response:new(data)
        if ( response ) then
          local status, _, _, rhost, _ = socket:get_info()
          if ( not(status) ) then
            socket:close()
            return false, "Failed to get socket information"
          end
          response.dbinstance.ip = rhost
          -- avoid duplicates
          instances[response.dbinstance.name] = response.dbinstance
        end
      end
    until( os.time() - stime > timeout )
    socket:close()

    return true, instances
  end,


}

action = function()

  local timeout = ( 20 / ( nmap.timing_level() + 1 ) )
  local host = { ip = "255.255.255.255" }
  local port = { number = 2638, protocol = "udp" }

  local helper = Helper:new(host, port)
  local status, instances = helper:ping()

  if ( not(status) ) then
    return stdnse.format_output(false, instances)
  end

  -- if we don't have any instances, silently abort
  if ( next(instances) == nil ) then
    return
  end

  local result = {}
  for _, instance in pairs(instances) do
    table.insert(result, ("ip=%s; name=%s; port=%d"):format(instance.ip, instance.name, instance.port))
  end
  table.sort(result)
  return stdnse.format_output(true, result)
end
