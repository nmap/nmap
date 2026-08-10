---
-- Minimalistic DHCP6 (Dynamic Host Configuration Protocol for IPv6)
-- implementation supporting basic DHCP6 Solicit requests The library
-- is structured around the following classes:
-- * DHCP6.Option - DHCP6 options encoders (for requests) and decoders
--                  (for responses)
-- * DHCP6.Request - DHCP6 request encoder and decoder
-- * DHCP6.Response - DHCP6 response encoder and decoder
-- * Helper - The helper class, primary script interface
--
-- The following sample code sends a DHCP6 Solicit request and returns a
-- response suitable for script output:
-- <code>
--   local helper = DHCP6.Helper:new("eth0")
--   local status, response = helper:solicit()
--   if ( status ) then
--      return stdnse.format_output(true, response)
--   end
-- </code>
--
-- @author Patrik Karlsson <patrik@cqure.net>
--

local datetime = require "datetime"
local ipOps = require "ipOps"
local math = require "math"
local nmap = require "nmap"
local os = require "os"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
_ENV = stdnse.module("dhcp6", stdnse.seeall)

DHCP6 = {}

-- DHCP6 request and response types
DHCP6.Type = {
  SOLICIT = 1,
  ADVERTISE = 2,
  REQUEST = 3,
}

-- DHCP6 type as string
DHCP6.TypeStr = {
  [DHCP6.Type.SOLICIT] = "Solicit",
  [DHCP6.Type.ADVERTISE] = "Advertise",
  [DHCP6.Type.REQUEST] = "Request",
}

-- DHCP6 option types
DHCP6.OptionTypes = {
  OPTION_CLIENTID = 0x01,
  OPTION_SERVERID = 0x02,
  OPTION_IA_NA = 0x03,
  OPTION_IAADDR = 0x05,
  OPTION_ELAPSED_TIME = 0x08,
  OPTION_STATUS_CODE = 0x0d,
  OPTION_DNS_SERVERS = 0x17,
  OPTION_DOMAIN_LIST = 0x18,
  OPTION_IA_PD = 0x19,
  OPTION_SNTP_SERVERS = 0x1f,
  OPTION_CLIENT_FQDN = 0x27,
}

local DHCP6_EPOCH = os.time({year=2000, day=1, month=1, hour=0, min=0, sec=0})
-- DHCP6 options
DHCP6.Option = {

  [DHCP6.OptionTypes.OPTION_ELAPSED_TIME] = {

    -- Create a new class instance
    -- @param time in ms since last request
    -- @return o new instance of class
    new = function(self, time)
      local o = {
        type = DHCP6.OptionTypes.OPTION_ELAPSED_TIME,
        time = time,
        -- in case no time was created, we need this to be able to
        -- calculate time since instantiation
        created = os.time(),
      }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    -- Converts option to a string
    -- @return str string containing the class instance as string
    __tostring = function(self)
      local data
      if ( self.time ) then
        data = string.pack(">I2", self.time)
      else
        data = string.pack(">I2", (os.time() - self.created) * 1000)
      end
      return string.pack(">I2s2", self.type, data)
    end,

  },

  [DHCP6.OptionTypes.OPTION_CLIENTID] = {

    -- Create a new class instance
    -- @param mac string containing the mac address
    -- @param duid number the duid of the client
    -- @param hwtype number the hwtype of the client
    -- @param time number time since 2000-01-01 00:00:00
    -- @return o new instance of class
    new = function(self, mac, duid, hwtype, time)
      local o = {
        type = DHCP6.OptionTypes.OPTION_CLIENTID,
        duid = duid or 1,
        hwtype = hwtype or 1,
        time = time or os.time() - DHCP6_EPOCH,
        mac = mac,
      }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    -- Parse the data string and create an instance of the class
    -- @param data string containing the data as received over the socket
    -- @return opt new instance of option
    parse = function(data)
      local opt = DHCP6.Option[DHCP6.OptionTypes.OPTION_CLIENTID]:new()
      local pos
      opt.duid, pos = string.unpack(">I2", data, pos)
      if ( 1 ~= opt.duid ) then
        stdnse.debug1("Unexpected DUID type (%d)", opt.duid)
        return
      end
      opt.hwtype, opt.time = string.unpack(">I2I4", data, pos)
      opt.mac = data:sub(pos)
      opt.time = opt.time + DHCP6_EPOCH
      return opt
    end,

    -- Converts option to a string
    -- @return str string containing the class instance as string
    __tostring = function(self)
      local data = string.pack(">I2I2I4", self.duid, self.hwtype, self.time) .. self.mac
      return string.pack(">I2s2", self.type, data)
    end,
  },

  [DHCP6.OptionTypes.OPTION_SERVERID] = {
    -- Create a new class instance
    -- @param mac string containing the mac address
    -- @param duid number the duid of the client
    -- @param hwtype number the hwtype of the client
    -- @param time number time since 2000-01-01 00:00:00
    -- @return o new instance of class
    new = function(...) return DHCP6.Option[DHCP6.OptionTypes.OPTION_CLIENTID].new(...) end,

    -- Parse the data string and create an instance of the class
    -- @param data string containing the data as received over the socket
    -- @return opt new instance of option
    parse = function(...) return DHCP6.Option[DHCP6.OptionTypes.OPTION_CLIENTID].parse(...) end,

    -- Converts option to a string
    -- @return str string containing the class instance as string
    __tostring = function(...) return DHCP6.Option[DHCP6.OptionTypes.OPTION_CLIENTID].__tostring(...) end,
  },

  [DHCP6.OptionTypes.OPTION_STATUS_CODE] = {

    -- Create a new class instance
    -- @param code number containing the error code
    -- @param msg string containing the error message
    -- @return o new instance of class
    new = function(self, code, msg)
      local o = {
        type = DHCP6.OptionTypes.OPTION_STATUS_CODE,
        code = code,
        msg = msg,
      }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    -- Parse the data string and create an instance of the class
    -- @param data string containing the data as received over the socket
    -- @return opt new instance of option
    parse = function(data)
      local opt = DHCP6.Option[DHCP6.OptionTypes.OPTION_STATUS_CODE]:new()

      local pos
      opt.code, pos = string.unpack(">I2", data)
      opt.msg = data:sub(pos)

      return opt
    end,

  },

  [DHCP6.OptionTypes.OPTION_DNS_SERVERS] = {

    -- Create a new class instance
    -- @param servers table containing DNS servers
    -- @return o new instance of class
    new = function(self, servers)
      local o = {
        type = DHCP6.OptionTypes.OPTION_DNS_SERVERS,
        servers = servers or {},
      }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    -- Parse the data string and create an instance of the class
    -- @param data string containing the data as received over the socket
    -- @return opt new instance of option
    parse = function(data)
      local opt = DHCP6.Option[DHCP6.OptionTypes.OPTION_DNS_SERVERS]:new()
      local pos, count = 1, #data/16

      for i=1,count do
        local srv
        srv, pos = string.unpack(">c16", data, pos)
        table.insert(opt.servers, srv)
      end
      return opt
    end,

    -- Converts option to a string
    -- @return str string containing the class instance as string
    __tostring = function(self)
      local data = {}
      for _, ipv6 in ipairs(self.servers) do
        data[#data+1] = ipOps.ip_to_str(ipv6)
      end
      data = table.concat(data)
      return string.pack(">I2s2", self.type, data)
    end
  },

  [DHCP6.OptionTypes.OPTION_DOMAIN_LIST] = {

    -- Create a new class instance
    -- @param domain table containing the search domains
    -- @return o new instance of class
    new = function(self, domains)
      local o = {
        type = DHCP6.OptionTypes.OPTION_DOMAIN_LIST,
        domains = domains or {},
      }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    -- Parse the data string and create an instance of the class
    -- @param data string containing the data as received over the socket
    -- @return opt new instance of option
    parse = function(data)
      local opt = DHCP6.Option[DHCP6.OptionTypes.OPTION_DOMAIN_LIST]:new()
      local pos = 1

      repeat
        local domain = {}
        repeat
          local part
          part, pos = string.unpack("s1", data, pos)
          if ( part ~= "" ) then
            table.insert(domain, part)
          end
        until( part == "" )
        table.insert(opt.domains, table.concat(domain, "."))
      until( pos > #data )
      return opt
    end,


  },

  [DHCP6.OptionTypes.OPTION_IA_PD] = {

    -- Create a new class instance
    -- @param iad number containing iad
    -- @param t1 number containing t1
    -- @param t2 number containing t2
    -- @param option string containing any options
    -- @return o new instance of class
    new = function(self, iaid, t1, t2, options)
      local o = {
        type = DHCP6.OptionTypes.OPTION_IA_PD,
        iaid = iaid,
        t1 = t1 or 0,
        t2 = t2 or 0,
        options = options or "",
      }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    -- Converts option to a string
    -- @return str string containing the class instance as string
    __tostring = function(self)
      local data = string.pack(">I4I4I4", self.iaid, self.t1, self.t2) .. self.options
      return string.pack(">I2s2", self.type, data)
    end,

  },

  [DHCP6.OptionTypes.OPTION_IA_NA] = {

    -- Create a new class instance
    -- @param iad number containing iad
    -- @param t1 number containing t1
    -- @param t2 number containing t2
    -- @param option table containing any options
    -- @return o new instance of class
    new = function(self, iaid, t1, t2, options)
      local o = {
        type = DHCP6.OptionTypes.OPTION_IA_NA,
        iaid = iaid,
        t1 = t1 or 0,
        t2 = t2 or 0,
        options = options or {},
      }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    -- Parse the data string and create an instance of the class
    -- @param data string containing the data as received over the socket
    -- @return opt new instance of option
    parse = function(data)
      local opt = DHCP6.Option[DHCP6.OptionTypes.OPTION_IA_NA]:new()
      local pos

      opt.iaid, opt.t1, opt.t2, pos = string.unpack(">I4I4I4", data)

      -- do we have any options
      while ( pos < #data ) do
        local typ, len, ipv6, pref_lt, valid_lt, options
        typ, len, pos = string.unpack(">I2I2", data, pos)

        if ( 5 == DHCP6.OptionTypes.OPTION_IAADDR ) then
          local addr = { type = DHCP6.OptionTypes.OPTION_IAADDR }
          addr.ipv6, addr.pref_lt, addr.valid_lt, pos = string.unpack(">c16I4I4", data, pos)
          table.insert(opt.options, addr)
        else
          pos = pos + len
        end
      end
      return opt
    end,

    -- Converts option to a string
    -- @return str string containing the class instance as string
    __tostring = function(self)
      local data = string.pack(">I4I4I4", self.iaid, self.t1, self.t2)

      -- TODO: we don't cover self.options here, we should probably add that
      return string.pack(">I2s2", self.type, data)
    end,
  },

  [DHCP6.OptionTypes.OPTION_SNTP_SERVERS] = {

    -- Create a new class instance
    -- @param servers table containing the NTP servers
    -- @return o new instance of class
    new = function(self, servers)
      local o = {
        type = DHCP6.OptionTypes.OPTION_SNTP_SERVERS,
        servers = servers or {},
      }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    -- Parse the data string and create an instance of the class
    -- @param data string containing the data as received over the socket
    -- @return opt new instance of option
    parse = function(data)
      local opt = DHCP6.Option[DHCP6.OptionTypes.OPTION_SNTP_SERVERS]:new()
      local pos, server

      repeat
        server, pos = string.unpack(">c16", data, pos)
        table.insert( opt.servers, ipOps.str_to_ip(server) )
      until( pos > #data )
      return opt
    end,
  },

  [DHCP6.OptionTypes.OPTION_CLIENT_FQDN] = {

    -- Create a new class instance
    -- @param fqdn string containing the fqdn
    -- @return o new instance of class
    new = function(self, fqdn)
      local o = {
        type = DHCP6.OptionTypes.OPTION_CLIENT_FQDN,
        fqdn = fqdn or "",
      }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    -- Parse the data string and create an instance of the class
    -- @param data string containing the data as received over the socket
    -- @return opt new instance of option
    parse = function(data)
      local opt = DHCP6.Option[DHCP6.OptionTypes.OPTION_CLIENT_FQDN]:new()
      local pos = 2
      local pieces = {}

      repeat
        local tmp
        tmp, pos = string.unpack("s1", data, pos)
        table.insert(pieces, tmp)
      until(pos >= #data)
      opt.fqdn = table.concat(pieces, ".")
      return opt
    end,

  }

}


DHCP6.Request = {

  -- Create a new class instance
  -- @param msgtype number containing the message type
  -- @param xid number containing the transaction id
  -- @param opts table containing any request options
  -- @return o new instance of class
  new = function(self, msgtype, xid, opts)
    local o = {
      type = msgtype,
      xid = xid or math.random(1048575),
      opts = opts or {}
    }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  -- Adds a new DHCP6 option to the request
  -- @param opt instance of object to add to the request
  addOption = function(self, opt)
    table.insert(self.opts, opt)
  end,

  -- Converts option to a string
  -- @return str string containing the class instance as string
  __tostring = function(self)
    local tmp = (self.type << 24) + self.xid
    local data = {}

    for _, opt in ipairs(self.opts) do
      data[#data+1] = tostring(opt)
    end
    return string.pack(">I4", tmp) .. table.concat(data)
  end,

}

-- The Response class handles responses from the server
DHCP6.Response = {

  -- Creates a new instance of the response class
  -- @param msgtype number containing the type of DHCP6 message
  -- @param xid number containing the transaction ID
  new = function(self, msgtype, xid, opts)
    local o = {
      msgtype = msgtype,
      xid = xid,
      opts = opts or {},
    }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  -- Parse the data string and create an instance of the class
  -- @param data string containing the data as received over the socket
  -- @return opt new instance of option
  parse = function(data)
    local resp = DHCP6.Response:new()
    local tmp, pos = string.unpack(">I4", data)

    resp.msgtype = (tmp & 0xFF000000)
    resp.msgtype = (resp.msgtype >> 24)
    resp.xid = (tmp & 0x00FFFFFF)
    while( pos < #data ) do
      local opt = {}
      opt.type, opt.data, pos = string.unpack(">I2s2", data, pos)
      if ( DHCP6.Option[opt.type] and DHCP6.Option[opt.type].parse ) then
        local opt_parsed = DHCP6.Option[opt.type].parse(opt.data)
        if ( not(opt_parsed) ) then
          table.insert(resp.opts, { type = opt.type, raw = opt.data })
        else
          table.insert(resp.opts, { type = opt.type, resp = opt_parsed, raw = opt.data })
        end
      else
        stdnse.debug2("No option decoder for type: %d; len: %d", opt.type, #(opt.data or ""))
        table.insert(resp.opts, { type = opt.type, raw = opt.data })
      end
    end
    return resp
  end

}

-- Table of option to string converters
-- Each option should have its own function to convert an instance of option
-- to a printable string.
--
-- TODO: These functions could eventually be moved to a method in its
-- respective class.
OptionToString = {

  [DHCP6.OptionTypes.OPTION_CLIENTID] = function(opt)
    local HWTYPE_ETHER = 1
    if ( HWTYPE_ETHER == opt.hwtype ) then
      local mac = stdnse.tohex(opt.mac):upper()
      mac = mac:gsub("..", "%1:"):sub(1, -2)
      local tm = datetime.format_timestamp(opt.time)
      return "Client identifier", ("MAC: %s; Time: %s"):format(mac, tm)
    end
  end,

  [DHCP6.OptionTypes.OPTION_SERVERID] = function(opt)
    local topic, str = OptionToString[DHCP6.OptionTypes.OPTION_CLIENTID](opt)
    return "Server identifier", str
  end,

  [DHCP6.OptionTypes.OPTION_IA_NA] = function(opt)
    if ( opt.options and 1 == #opt.options ) then
      local ipv6 = ipOps.str_to_ip(opt.options[1].ipv6)
      return "Non-temporary Address", ipv6
    end
  end,

  [DHCP6.OptionTypes.OPTION_DNS_SERVERS] = function(opt)
    local servers = {}
    for _, srv in ipairs(opt.servers) do
      local ipv6 = ipOps.str_to_ip(srv)
      table.insert(servers, ipv6)
    end
    return "DNS Servers", table.concat(servers, ",")
  end,

  [DHCP6.OptionTypes.OPTION_DOMAIN_LIST] = function(opt)
    return "Domain Search", table.concat(opt.domains, ", ")
  end,

  [DHCP6.OptionTypes.OPTION_STATUS_CODE] = function(opt)
    return "Error", ("Code: %d; Message: %s"):format(opt.code, opt.msg)
  end,

  [DHCP6.OptionTypes.OPTION_SNTP_SERVERS] = function(opt)
    return "NTP Servers", table.concat(opt.servers, ", ")
  end,
}

-- The Helper class serves as the main interface to scripts
Helper = {

  -- Creates a new Helper class instance
  -- @param iface string containing the interface name
  -- @param options table containing any options, currently
  --        <code>timeout</code> - socket timeout in ms
  -- @return o new instance of Helper
  new = function(self, iface, options)
    local o = {
      iface = iface,
      options = options or {},
    }
    setmetatable(o, self)
    self.__index = self

    local info, err = nmap.get_interface_info(iface)
    -- if we fail to get interface info, don't return a helper
    -- this is true on OS X for interfaces like: p2p0 and vboxnet0
    if ( not(info) and err ) then
      return
    end
    o.mac = info.mac
    o.socket = nmap.new_socket("udp")
    o.socket:bind(nil, 546)
    o.socket:set_timeout(o.options.timeout or 5000)
    return o
  end,

  -- Sends a DHCP6 Solicit message to the server, essentially requesting a new
  -- IPv6 non-temporary address
  -- @return table of results suitable for use with
  --         <code>stdnse.format_output</code>
  solicit = function(self)
    local req = DHCP6.Request:new( DHCP6.Type.SOLICIT )
    local option = DHCP6.Option
    req:addOption(option[DHCP6.OptionTypes.OPTION_ELAPSED_TIME]:new())
    req:addOption(option[DHCP6.OptionTypes.OPTION_CLIENTID]:new(self.mac))

    local iaid = string.unpack(">I4", self.mac:sub(3))
    req:addOption(option[DHCP6.OptionTypes.OPTION_IA_NA]:new(iaid, 3600, 5400))

    self.host, self.port = { ip = "ff02::1:2" }, { number = 547, protocol = "udp"}
    local status, err = self.socket:sendto( self.host, self.port, tostring(req) )
    if ( not(status) ) then
      self.host.ip = ("%s%%%s"):format(self.host.ip, self.iface)
      status, err = self.socket:sendto( self.host, self.port, tostring(req) )
      if ( not(status) ) then
        return false, "Failed to send DHCP6 request to server"
      end
    end

    local resp, retries = {}, 3
    repeat
      retries = retries - 1
      local status, data = self.socket:receive()
      if ( not(status) ) then
        return false, "Failed to receive DHCP6 request from server"
      end

      resp = DHCP6.Response.parse(data)
      if ( not(resp) ) then
        return false, "Failed to decode DHCP6 response from server"
      end
    until( req.xid == resp.xid or retries == 0 )

    if ( req.xid ~= resp.xid ) then
      return false, "Failed to receive DHCP6 response from server"
    end

    local result, result_options = {}, { name = "Options" }
    local resptype = DHCP6.TypeStr[resp.msgtype] or ("Unknown (%d)"):format(resp.msgtype)

    table.insert(result, ("Message type: %s"):format(resptype))
    table.insert(result, ("Transaction id: %d"):format(resp.xid))

    for _, opt in ipairs(resp.opts or {}) do
      if ( OptionToString[opt.type] ) then
        local topic, str = OptionToString[opt.type](opt.resp)
        if ( topic and str ) then
          table.insert(result_options, ("%s: %s"):format(topic, str))
        end
      else
        stdnse.debug2("No decoder for option type: %d", opt.type)
      end
    end
    table.insert(result, result_options)
    return true, result
  end,
}


return _ENV;
