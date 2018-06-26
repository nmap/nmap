---
-- This library implements the fundamentals needed to communicate with the
-- WinPcap Remote Capture Daemon. It currently supports authenticating to
-- the service using either NULL-, or Password-based authentication.
-- In addition it has the capabilities to list the interfaces that may be
-- used for sniffing.
--
-- The library consist of classes handling <code>Request</code> and classes
-- handling <code>Response</code>. The communication with the service is
-- handled by the <code>Comm</code> class, and the main interface for script
-- writers is kept under the <code>Helper</code> class.
--
-- The following code snippet illustrates how to connect to the service and
-- extract information about network interfaces:
-- <code>
--   local helper = rpcap.Helper:new(host, port)
--   helper:connect()
--   helper:login()
--   helper:findAllInterfaces()
--   helper:close()
-- </code>
--
-- For a more complete example, consult the rpcap-info.nse script.
--
-- @author Patrik Karlsson <patrik@cqure.net>


local bin = require "bin"
local ipOps = require "ipOps"
local match = require "match"
local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"
_ENV = stdnse.module("rpcap", stdnse.seeall)

RPCAP = {

  MessageType = {
    ERROR = 1,
    FIND_ALL_INTERFACES = 2,
    AUTH_REQUEST = 8,
  },

  -- Holds the two supported authentication mechanisms PWD and NULL
  Authentication = {

    PWD = {

      new = function(self, username, password)
        local o = {
          type = 1,
          username = username,
          password = password,
        }
        setmetatable(o, self)
        self.__index = self
        return o
      end,

      __tostring = function(self)
        local DUMMY = 0
        return bin.pack(">SSSSAA", self.type, DUMMY, #self.username, #self.password, self.username, self.password)
      end,

    },

    NULL = {

      new = function(self)
        local o = {
          type = 0,
        }
        setmetatable(o, self)
        self.__index = self
        return o
      end,

      __tostring = function(self)
        local DUMMY = 0
        return bin.pack(">SSSS", self.type, DUMMY, 0, 0)
      end,

    }

  },

  -- The common request and response header
  Header = {
    size = 8,
    new = function(self, type, value, length)
      local o = {
        version = 0,
        type = type,
        value= value or 0,
        length = length or 0
      }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    parse = function(data)
      local header = RPCAP.Header:new()
      local pos
      pos, header.version, header.type, header.value, header.length = bin.unpack(">CCSI", data)
      return header
    end,

    __tostring = function(self)
      return bin.pack(">CCSI", self.version, self.type, self.value, self.length)
    end,

  },

  -- The implemented request types are kept here
  Request = {

    Authentication = {

      new = function(self, data)
        local o = {
          header = RPCAP.Header:new(RPCAP.MessageType.AUTH_REQUEST, nil, #data),
          data = data,
        }
        setmetatable(o, self)
        self.__index = self
        return o
      end,

      __tostring = function(self)
        return tostring(self.header) .. tostring(self.data)
      end,

    },

    FindAllInterfaces = {

      new = function(self)
        local o = {
          header = RPCAP.Header:new(RPCAP.MessageType.FIND_ALL_INTERFACES)
        }
        setmetatable(o, self)
        self.__index = self
        return o
      end,

      __tostring = function(self)
        return tostring(self.header)
      end,


    }

  },

  -- Parsers for responses are kept here
  Response = {

    Authentication = {
      new = function(self)
        local o = { }
        setmetatable(o, self)
        self.__index = self
        return o
      end,

      parse = function(data)
        local resp = RPCAP.Response.Authentication:new()
        local pos = RPCAP.Header.size + 1
        resp.header = RPCAP.Header.parse(data)
        return resp
      end
    },

    Error = {
      new = function(self)
        local o = { }
        setmetatable(o, self)
        self.__index = self
        return o
      end,

      parse = function(data)
        local err = RPCAP.Response.Error:new()
        local pos = RPCAP.Header.size + 1
        err.header = RPCAP.Header.parse(data)
        pos, err.error = bin.unpack("A" .. err.header.length, data, pos)
        return err
      end

    },

    FindAllInterfaces = {
      new = function(self)
        local o = { }
        setmetatable(o, self)
        self.__index = self
        return o
      end,

      parse = function(data)

        -- Each address is made up of 4 128 byte fields, this function
        -- parses these fields and return the response, if it
        -- understands it. Otherwise it simply increases the pos by the
        -- correct offset, to get us to the next field.
        local function parseField(data, pos)
          local offset = pos
          local family, port
          pos, family, port = bin.unpack(">SS", data, pos)

          if ( family == 0x0017 ) then
            -- not sure why...
            pos = pos + 4

            local ipv6
            pos, ipv6 = bin.unpack("B16", data, pos)
            return offset + 128, ipOps.bin_to_ip(ipv6)
          elseif ( family == 0x0002 ) then
            local ipv4
            pos, ipv4 = bin.unpack("B4", data, pos)
            return offset + 128, ipOps.bin_to_ip(ipv4)
          end

          return offset + 128, nil
        end

        -- Parses one of X addresses returned for an interface
        local function parseAddress(data, pos)
          local fields = {"ip", "netmask", "bcast", "p2p"}
          local addr = {}

          for _, f in ipairs(fields) do
            pos, addr[f] = parseField(data, pos)
          end

          return pos, addr
        end

        local resp = RPCAP.Response.FindAllInterfaces:new()
        local pos = RPCAP.Header.size + 1
        resp.header = RPCAP.Header.parse(data)
        resp.ifaces = {}

        for i=1, resp.header.value do
          local name_len, desc_len, iface_flags, addr_count, dummy
          pos, name_len, desc_len, iface_flags, addr_count, dummy = bin.unpack(">SSISS", data, pos)

          local name, desc
          pos, name, desc = bin.unpack("A" .. name_len .. "A" .. desc_len, data, pos)

          local addrs = {}
          for j=1, addr_count do
            local addr
            pos, addr = parseAddress(data, pos)
            local cidr
            if ( addr.netmask ) then
              local bits = ipOps.ip_to_bin(addr.netmask)
              local ones = bits:match("^(1*)")
              cidr = #ones
              table.insert(addrs, ("%s/%d"):format(addr.ip,cidr))
            else
              table.insert(addrs, addr.ip)
            end
          end
          table.insert(resp.ifaces, { name = name, desc = desc, addrs = addrs })
        end
        return resp
      end,
    }


  }

}

-- Maps packet types to classes
RPCAP.TypeToClass = {
  [1] = RPCAP.Response.Error,
  [130] = RPCAP.Response.FindAllInterfaces,
  [136] = RPCAP.Response.Authentication,
}


-- The communication class
Comm = {

  -- Creates a new instance of the Comm class
  -- @param host table
  -- @param port table
  -- @return o instance of Comm
  new = function(self, host, port, socket)
    local o = { host = host, port = port, socket = socket or nmap.new_socket() }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  -- Connects the socket to the server
  connect = function(self)
    return self.socket:connect(self.host, self.port)
  end,

  -- Sends an instance of the request class to the server
  -- @param req class instance
  -- @return status true on success, false on failure
  -- @return err string containing error message if status is false
  send = function(self, req)
    return self.socket:send(req)
  end,

  -- receives a packet and attempts to parse it if it has a supported parser
  -- in RPCAP.TypeToClass
  -- @return status true on success, false on failure
  -- @return resp instance of a Response class or
  --         err string containing the error message
  recv = function(self)
    local status, hdr_data = self.socket:receive_buf(match.numbytes(RPCAP.Header.size), true)
    if ( not(status) ) then
      return status, hdr_data
    end

    local header = RPCAP.Header.parse(hdr_data)
    if ( not(header) ) then
      return false, "rpcap: Failed to parse header"
    end

    local status, data = self.socket:receive_buf(match.numbytes(header.length), true)
    if ( not(status) ) then
      return false, "rpcap: Failed to read packet data"
    end

    if ( RPCAP.TypeToClass[header.type] ) then
      local resp = RPCAP.TypeToClass[header.type].parse(hdr_data .. data)
      if ( resp ) then
        return true, resp
      end
    end

    return false, "Failed to receive response from server"
  end,

  -- Sends and request and receives the response
  -- @param req the instance of the Request class to send
  -- @return status true on success, false on failure
  -- @return resp instance of a Response class or
  --         err string containing the error message
  exch = function(self, req)
    local status, data = self:send(tostring(req))
    if ( not(status) ) then
      return status, data
    end
    return self:recv()
  end,

  -- closes the socket
  close = function(self)
    return self.socket:close()
  end,

}


Helper = {

  -- Creates a new instance of the Helper class
  -- @param host table
  -- @param port table
  -- @return o instance of Helper
  new = function(self, host, port)
    local o = {
      host = host,
      port = port,
      comm = Comm:new(host, port)
    }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  -- Connects to the server
  connect = function(self)
    return self.comm:connect(self.host, self.port)
  end,

  -- Authenticates to the service, in case no username or password is given
  -- NULL authentication is assumed.
  -- @param username [optional]
  -- @param password [optional]
  -- @return status true on success, false on failure
  -- @return err string containing error message on failure
  login = function(self, username, password)
    local auth

    if ( username and password ) then
      auth = RPCAP.Authentication.PWD:new(username, password)
    else
      auth = RPCAP.Authentication.NULL:new()
    end

    local req = RPCAP.Request.Authentication:new(tostring(auth))
    local status, resp = self.comm:exch(req)

    if ( not(status) ) then
      return false, resp
    end

    if ( status and resp.error ) then
      return false, resp.error
    end
    return true
  end,

  -- Requests a list of all interfaces
  -- @return table containing interfaces and addresses
  findAllInterfaces = function(self)
    local req = RPCAP.Request.FindAllInterfaces:new()
    local status, resp = self.comm:exch(req)

    if ( not(status) ) then
      return false, resp
    end

    local results = {}
    for _, iface in ipairs(resp.ifaces) do
      local entry = {}
      entry.name = iface.name
      table.insert(entry, iface.desc)
      table.insert(entry, { name = "Addresses", iface.addrs })
      table.insert(results, entry)
    end
    return true, results
  end,

  -- Closes the connection to the server
  close = function(self)
    return self.comm:close()
  end,
}

return _ENV;
