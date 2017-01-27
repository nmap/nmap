---
-- Implementation of the XDMCP (X Display Manager Control Protocol) based on:
--   x http://www.xfree86.org/current/xdmcp.pdf
--
-- @author Patrik Karlsson <patrik@cqure.net>

local bin = require "bin"
local ipOps = require "ipOps"
local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"
_ENV = stdnse.module("xdmcp", stdnse.seeall)

-- Supported operations
OpCode = {
  BCAST_QUERY = 1,
  QUERY = 2,
  WILLING = 5,
  REQUEST = 7,
  ACCEPT = 8,
  MANAGE = 10,
}

-- Packet class
Packet = {

  -- The cdmcp header
  Header = {

    -- Creates a new instance of class
    -- @param version number containing the protocol version
    -- @param opcode number containing the opcode type
    -- @param length number containing the length of the data
    -- @return o instance of class
    new = function(self, version, opcode, length)
      local o = { version = version, opcode = opcode, length = length }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    -- Parses data based on which a new object is instantiated
    -- @param data opaque string containing data received over the wire
    -- @return hdr instance of class
    parse = function(data)
      local pos, hdr = nil, Packet.Header:new()
      pos, hdr.version, hdr.opcode, hdr.length = bin.unpack(">SSS", data)
      return hdr
    end,

    -- Converts the instance to an opaque string
    -- @return str string containing the instance
    __tostring = function(self)
      assert(self.length, "No header length was supplied")
      return bin.pack(">SSS", self.version, self.opcode, self.length)
    end,
  },

  [OpCode.QUERY] = {

    -- Creates a new instance of class
    -- @param authnames table of strings containing authentication
    --        mechanism names.
    -- @return o instance of class
    new = function(self, authnames)
      local o = {
        header = Packet.Header:new(1, OpCode.QUERY),
        authnames = authnames or {},
      }
      o.header.length = #o.authnames + 1
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    -- Converts the instance to an opaque string
    -- @return str string containing the instance
    __tostring = function(self)
      local data = tostring(self.header)
      data = data .. bin.pack("C", #self.authnames)
      for _, name in ipairs(self.authnames) do
        data = data .. bin.pack("P", name)
      end
      return data
    end,

  },

  [OpCode.BCAST_QUERY] = {
    new = function(...)
      local packet = Packet[OpCode.QUERY]:new(...)
      packet.header.opcode = OpCode.BCAST_QUERY
      return packet
    end,

    __tostring = function(...)
      return Packet[OpCode.QUERY]:__tostring(...)
    end

  },

  [OpCode.WILLING] = {

    -- Creates a new instance of class
    -- @return o instance of class
    new = function(self)
      local o = {
        header = Packet.Header:new(1, OpCode.WILLING)
      }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    -- Parses data based on which a new object is instantiated
    -- @param data opaque string containing data received over the wire
    -- @return hdr instance of class
    parse = function(data)
      local willing = Packet[OpCode.WILLING]:new()
      willing.header = Packet.Header.parse(data)

      local pos = 7
      pos, willing.authname, willing.hostname,
      willing.status = bin.unpack("ppp", data, pos)
      return willing
    end,

  },

  [OpCode.REQUEST] = {

    -- The connection class
    Connection = {

      IpType = {
        IPv4 = 0,
        IPv6 = 6,
      },

      -- Creates a new instance of class
      -- @param iptype number
      -- @param ip opaque string containing the ip
      -- @return o instance of class
      new = function(self, iptype, ip)
        local o = {
          iptype = iptype,
          ip = ip,
        }
        setmetatable(o, self)
        self.__index = self
        return o
      end,

    },

    -- Creates a new instance of class
    -- @param disp_no number containing the display name
    -- @param auth_name string containing the authentication name
    -- @param auth_data string containing additional authentication data
    -- @param authr_names string containing authorization mechanisms
    -- @param manf_id string containing the manufacturer id
    -- @return o instance of class
    new = function(self, disp_no, conns, auth_name, auth_data, authr_names, manf_id )
      local o = {
        header = Packet.Header:new(1, OpCode.REQUEST),
        disp_no = disp_no or 1,
        conns = conns or {},
        auth_name = auth_name or "",
        auth_data = auth_data or "",
        authr_names = authr_names or {},
        manf_id = manf_id or "",
      }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    -- Adds a new connection entry
    -- @param conn instance of Connections
    addConnection = function(self, conn)
      table.insert(self.conns, conn)
    end,

    -- Adds a new authorization entry
    -- @param str string containing the name of the authorization mechanism
    addAuthrName = function(self, str)
      table.insert(self.authr_names, str)
    end,

    -- Converts the instance to an opaque string
    -- @return str string containing the instance
    __tostring = function(self)
      local data = bin.pack(">SC", self.disp_no, #self.conns)
      for _, conn in ipairs(self.conns) do
        data = data .. bin.pack(">S", conn.iptype)
      end
      data = data .. bin.pack("C", #self.conns)
      for _, conn in ipairs(self.conns) do
        data = data .. bin.pack(">P", ipOps.ip_to_str(conn.ip))
      end
      data = data .. bin.pack(">PP", self.auth_name, self.auth_data)
      data = data .. bin.pack("C", #self.authr_names)
      for _, authr in ipairs(self.authr_names) do
        data = data .. bin.pack(">P", authr)
      end
      data = data .. bin.pack(">P", self.manf_id)
      self.header.length = #data

      return tostring(self.header) .. data
    end,

  },

  [OpCode.ACCEPT] = {

    -- Creates a new instance of class
    -- @param session_id number containing the session id
    -- @param auth_name string containing the authentication name
    -- @param auth_data string containing additional authentication data
    -- @param authr_name string containing the authorization mechanism name
    -- @param authr_names string containing authorization mechanisms
    -- @return o instance of class
    new = function(self, session_id, auth_name, auth_data, authr_name, authr_data)
      local o = {
        header = Packet.Header:new(1, OpCode.ACCEPT),
        session_id = session_id,
        auth_name = auth_name,
        auth_data = auth_data,
        authr_name = authr_name,
        authr_data = authr_data,
      }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    -- Parses data based on which a new object is instantiated
    -- @param data opaque string containing data received over the wire
    -- @return hdr instance of class
    parse = function(data)
      local accept = Packet[OpCode.ACCEPT]:new()
      accept.header = Packet.Header.parse(data)
      local pos = 7
      pos, accept.session_id, accept.auth_name, accept.auth_data,
      accept.authr_name, accept.authr_data = bin.unpack(">IPPPP", data, pos)
      return accept
    end,

  },

  [OpCode.MANAGE] = {

    -- Creates a new instance of class
    -- @param session_id number containing the session id
    -- @param disp_no number containing the display number
    -- @param disp_class string containing the display class
    -- @return o instance of class
    new = function(self, sess_id, disp_no, disp_class)
      local o = {
        header = Packet.Header:new(1, OpCode.MANAGE),
        session_id = sess_id,
        disp_no = disp_no,
        disp_class = disp_class or ""
      }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    -- Converts the instance to an opaque string
    -- @return str string containing the instance
    __tostring = function(self)
      local data = bin.pack(">ISP", self.session_id, self.disp_no, self.disp_class)
      self.header.length = #data
      return tostring(self.header) .. data
    end,

  }

}

-- The Helper class serves as the main script interface
Helper = {

  -- Creates a new instance of Helper
  -- @param host table as received by the action method
  -- @param port table as received by the action method
  -- @param options table
  -- @return o new instance of Helper
  new = function(self, host, port, options)
    local o = {
      host = host,
      port = port,
      options = options or {},
    }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  -- "Connects" to the server (ie. creates the socket)
  -- @return status, true on success, false on failure
  connect = function(self)
    self.socket = nmap.new_socket("udp")
    self.socket:set_timeout(self.options.timeout or 10000)
    return true
  end,

  -- Creates a xdmcp session
  -- @param auth_name string containing the authentication name
  -- @param authr_name string containing the authorization mechanism name
  -- @param disp_class string containing the display class
  -- @return status true on success, false on failure
  -- @return response table or err string containing an error message
  createSession = function(self, auth_names, authr_names, disp_no)
    local info  = nmap.get_interface_info(self.host.interface)
    if ( not(info) ) then
      return false, ("Failed to get information for interface %s"):format(self.host.interface)
    end

    local req = Packet[OpCode.QUERY]:new(auth_names)
    local status, response = self:exch(req)
    if ( not(status) ) then
      return false, response
    elseif ( response.header.opcode ~= OpCode.WILLING ) then
      return false, "Received unexpected response"
    end

    local REQ = Packet[OpCode.REQUEST]
    local iptype = REQ.Connection.IpType.IPv4
    if ( nmap.address_family() == 'inet6' ) then
      iptype = REQ.Connection.IpType.IPv6
    end

    local conns = { REQ.Connection:new(iptype, info.address) }
    local req = REQ:new(disp_no, conns, nil, nil, authr_names)
    local status, response = self:exch(req)
    if ( not(status) ) then
      return false, response
    elseif ( response.header.opcode ~= OpCode.ACCEPT ) then
      return false, "Received unexpected response"
    end

    -- Sending this last manage packet doesn't make any sense as we can't
    -- set up a listening TCP server anyway. When we can, we could enable
    -- this and wait for the incoming request and retrieve X protocol info.

    -- local manage = Packet[OpCode.MANAGE]:new(response.session_id,
    --   disp_no, "MIT-unspecified")
    -- local status, response = self:exch(manage)
    -- if ( not(status) ) then
    --   return false, response
    -- end

    return true, {
      session_id = response.session_id,
      auth_name = response.auth_name,
      auth_data = response.auth_data,
      authr_name = response.authr_name,
      authr_data = response.authr_data,
    }
  end,

  send = function(self, req)
    return self.socket:sendto(self.host, self.port, tostring(req))
  end,

  recv = function(self)
    local status, data = self.socket:receive()
    if ( not(status) ) then
      return false, data
    end
    local header = Packet.Header.parse(data)
    if ( not(header) ) then
      return false, "Failed to parse xdmcp header"
    end
    if ( not(Packet[header.opcode]) ) then
      return false, ("No parser for opcode: %d"):format(header.opcode)
    end
    local resp = Packet[header.opcode].parse(data)
    if ( not(resp) ) then
      return false, "Failed to parse response"
    end
    return true, resp
  end,

  -- Sends a request to the server, receives and parses a response
  -- @param req instance of Packet
  -- @return status true on success, false on failure
  -- @return response instance of response packet
  exch = function(self, req)
    local status, err = self:send(req)
    if ( not(status) ) then
      return false, "Failed to send xdmcp request"
    end
    return self:recv()
  end,

}

return _ENV;
