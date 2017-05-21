---
-- A Vuze DHT protocol implementation based on the following documentation:
-- o http://wiki.vuze.com/w/Distributed_hash_table
--
-- It currently supports the PING and FIND_NODE requests and parses the
-- responses. The following main classes are used by the library:
--
-- o Request  - the request class containing all of the request classes. It
--              currently contains the Header, PING and FIND_NODE classes.
--
-- o Response - the response class containing all of the response classes. It
--              currently contains the Header, PING, FIND_NODE and ERROR
--              class.
--
-- o Session  - a class containing "session state" such as the transaction- and
--              instance ID's.
--
-- o Helper   - The helper class that serves as the main interface between
--              scripts and the library.
--
-- @author Patrik Karlsson <patrik@cqure.net>
--

local bin = require "bin"
local ipOps = require "ipOps"
local math = require "math"
local nmap = require "nmap"
local os = require "os"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local openssl = stdnse.silent_require "openssl"
_ENV = stdnse.module("vuzedht", stdnse.seeall)


Request = {

  Actions = {
    ACTION_PING = 1024,
    FIND_NODE = 1028,
  },

  -- The request Header class shared by all Requests classes
  Header = {

    -- Creates a new Header instance
    -- @param action number containing the request action
    -- @param session instance of Session
    -- @return o new instance of Header
    new = function(self, action, session)
      local o = {
        conn_id = string.char(255) .. openssl.rand_pseudo_bytes(7),
        -- we need to handle this one like this, due to a bug in nsedoc
        -- it used to be action = action, but that breaks parsing
        ["action"] = action,
        trans_id = session:getTransactionId(),
        proto_version = 0x32,
        vendor_id = 0,
        network_id = 0,
        local_proto_version = 0x32,
        address = session:getAddress(),
        port = session:getPort(),
        instance_id = session:getInstanceId(),
        time = os.time(),
      }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    -- Converts the header to a string
    __tostring = function(self)
      local lhost = ipOps.todword(self.address)
      return bin.pack( ">AIICCICCISIL", self.conn_id, self.action, self.trans_id,
      self.proto_version, self.vendor_id, self.network_id, self.local_proto_version,
      4, lhost, self.port, self.instance_id, self.time )
    end,

  },

  -- The PING Request class
  Ping = {

    -- Creates a new Ping instance
    -- @param session instance of Session
    -- @return o new instance of Ping
    new = function(self, session)
      local o = {
        header = Request.Header:new(Request.Actions.ACTION_PING, session)
      }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    -- Converts a Ping Request to a string
    __tostring = function(self)
      return tostring(self.header)
    end,

  },

  -- The FIND_NODES Request class
  FindNode = {

    -- Creates a new FindNode instance
    -- @param session instance of Session
    -- @return o new instance of FindNode
    new = function(self, session)
      local o = {
        header = Request.Header:new(Request.Actions.FIND_NODE, session),
        id_length = 20,
        node_id = '\xA7' .. openssl.rand_pseudo_bytes(19),
        status = 0xFFFFFFFF,
        dht_size = 0,
      }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    -- Converts a FindNode Request to a string
    __tostring = function(self)
      local data = tostring(self.header)
      .. bin.pack(">CAII", self.id_length, self.node_id, self.status, self.dht_size)
      return data
    end,
  }

}

Response = {

  -- A table of currently supported Actions (Responses)
  -- It's used in the fromString method to determine which class to create.
  Actions = {
    ACTION_PING = 1025,
    FIND_NODE = 1029,
    ERROR = 1032,
  },

  -- Creates an address record based on received data
  -- @param data containing an address record [C][I|H][S] where
  --        [C] is the length of the address (4 or 16)
  --        [I|H] is the address as a dword or hex string
  --        [S] is the port number as a short
  -- @return o Address instance on success, nil on failure
  Address = {
    new = function(self, data)
      local o = { data = data }
      setmetatable(o, self)
      self.__index = self
      if ( o:parse() ) then
        return o
      end
    end,

    -- Parses the received data
    -- @return true on success, false on failure
    parse = function(self)
      local pos, addr_len = bin.unpack("C", self.data)
      if ( addr_len == 4 ) then
        self.length = 4 + 2 + 1
        pos, self.ip = bin.unpack(">I", self.data, pos)
        self.ip = ipOps.fromdword(self.ip)
      elseif( addr_len == 16 ) then
        self.length = 16 + 2 + 1
        pos, self.ip = bin.unpack("H16", self.data, pos)
      else
        stdnse.debug1("Unknown address type (length: %d)", addr_len)
        return false, "Unknown address type"
      end
      pos, self.port = bin.unpack(">S", self.data, pos)
      return true
    end
  },

  -- The response header, present in all packets
  Header = {

    Vendors = {
      [0] = "Azureus",
      [1] = "ShareNet",
      [255] = "Unknown", -- to be honest, we report all except 0 and 1 as unknown
    },

    Networks = {
      [0] = "Stable",
      [1] = "CVS"
    },

    -- Creates a new Header instance
    -- @param data string containing the received data
    -- @return o instance of Header
    new = function(self, data)
      local o = { data = data }
      setmetatable(o, self)
      self.__index = self
      o:parse()
      return o
    end,

    -- parses the header
    parse = function(self)
      local pos
      pos, self.action, self.trans_id, self.conn_id,
      self.proto_version, self.vendor_id, self.network_id,
      self.instance_id = bin.unpack(">IIH8CCII", self.data)
    end,

    -- Converts the header to a suitable string representation
    __tostring = function(self)
      local result = {}
      table.insert(result, ("Transaction id: %d"):format(self.trans_id))
      table.insert(result, ("Connection id: 0x%s"):format(self.conn_id))
      table.insert(result, ("Protocol version: %d"):format(self.proto_version))
      table.insert(result, ("Vendor id: %s (%d)"):format(
        Response.Header.Vendors[self.vendor_id] or "Unknown", self.vendor_id))
      table.insert(result, ("Network id: %s (%d)"):format(
        Response.Header.Networks[self.network_id] or "Unknown", self.network_id))
      table.insert(result, ("Instance id: %d"):format(self.instance_id))
      return stdnse.format_output(true, result)
    end,

  },

  -- The PING response
  PING = {

    -- Creates a new instance of PING
    -- @param data string containing the received data
    -- @return o new PING instance
    new = function(self, data)
      local o = {
        header = Response.Header:new(data)
      }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    -- Creates a new PING instance based on received data
    -- @param data string containing received data
    -- @return status true on success, false on failure
    -- @return new instance of PING on success, error message on failure
    fromString = function(data)
      local ping = Response.PING:new(data)
      if ( ping ) then
        return true, ping
      end
      return false, "Failed to parse PING response"
    end,

    -- Converts the PING response to a response suitable for script output
    -- @return result formatted script output
    __tostring = function(self)
      return tostring(self.header)
    end,
  },

  -- A class to process the response from a FIND_NODE query
  FIND_NODE = {

    -- Creates a new FIND_NODE instance
    -- @param data string containing the received data
    -- @return o new instance of FIND_NODE
    new = function(self, data)
      local o = {
        header = Response.Header:new(data),
        data = data:sub(27)
      }
      setmetatable(o, self)
      self.__index = self
      o:parse()
      return o
    end,

    -- Parses the FIND_NODE response
    parse = function(self)
      local pos
      pos, self.spoof_id, self.node_type, self.dht_size,
      self.network_coords = bin.unpack(">IIIH20", self.data)

      local contact_count
      pos, contact_count = bin.unpack("C", self.data, pos)
      self.contacts = {}
      for i=1, contact_count do
        local contact, addr_len, address = {}
        pos, contact.type, contact.proto_version, addr_len = bin.unpack("CCC", self.data, pos)

        if ( addr_len == 4 ) then
          pos, address = bin.unpack(">I", self.data, pos)
          contact.address = ipOps.fromdword(address)
        elseif ( addr_len == 16 ) then
          pos, contact.address = bin.unpack("H16", self.data, pos)
        end
        pos, contact.port = bin.unpack(">S", self.data, pos)
        table.insert(self.contacts, contact)
      end
    end,

    -- Creates a new instance of FIND_NODE based on received data
    -- @param data string containing received data
    -- @return status true on success, false on failure
    -- @return new instance of FIND_NODE on success, error message on failure
    fromString = function(data)
      local find = Response.FIND_NODE:new(data)
      if ( find.header.proto_version < 13 ) then
        stdnse.debug1("ERROR: Unsupported version %d", find.header.proto_version)
        return false
      end

      return true, find
    end,

    -- Convert the FIND_NODE response to formatted string data, suitable
    -- for script output.
    -- @return string with formatted FIND_NODE data
    __tostring = function(self)
      if ( not(self.contacts) ) then
        return ""
      end

      local result = {}
      for _, contact in ipairs(self.contacts) do
        table.insert(result, ("%s:%d"):format(contact.address, contact.port))
      end
      return stdnse.format_output(true, result)
    end
  },

  -- The ERROR action
  ERROR = {

    -- Creates a new ERROR instance based on received socket data
    -- @return o new ERROR instance on success, nil on failure
    new = function(self, data)
      local o = {
        header = Response.Header:new(data),
        data = data:sub(27)
      }
      setmetatable(o, self)
      self.__index = self
      if ( o:parse() ) then
        return o
      end
    end,

    -- parses the received data and attempts to create an ERROR response
    -- @return true on success, false on failure
    parse = function(self)
      local pos, err_type = bin.unpack(">I", self.data)
      if ( 1 == err_type ) then
        self.addr = Response.Address:new(self.data:sub(5))
        return true
      end
      return false
    end,

    -- creates a new ERROR instance based on the received data
    -- @return true on success, false on failure
    fromString = function(data)
      local err = Response.ERROR:new(data)
      if ( err ) then
        return true, err
      end
      return false
    end,

    -- Converts the ERROR action to a formatted response
    -- @return string containing the formatted response
    __tostring = function(self)
      return ("Wrong address, expected: %s"):format(self.addr.ip)
    end,

  },

  -- creates a suitable Response class based on the Action received
  -- @return true on success, false on failure
  -- @return response instance of suitable Response class on success,
  --         err string error message if status is false
  fromString = function(data)
    local pos, action = bin.unpack(">I", data)

    if ( action == Response.Actions.ACTION_PING ) then
      return Response.PING.fromString(data)
    elseif ( action == Response.Actions.FIND_NODE ) then
      return Response.FIND_NODE.fromString(data)
    elseif ( action == Response.Actions.ERROR ) then
      return Response.ERROR.fromString(data)
    end

    stdnse.debug1("ERROR: Unknown response received from server")
    return false, "Failed to parse response"
  end,



}

-- The Session
Session = {

  -- Creates a new Session instance to keep track on some of the protocol
  -- stuff, such as transaction- and instance- identities.
  -- @param address the local address to pass in the requests to the server
  --        this could be either the local address or the IP of the router
  --        depending on if NAT is used or not.
  -- @param port the local port to pass in the requests to the server
  -- @return o new instance of Session
  new = function(self, address, port)
    local o = {
      trans_id = math.random(12345678),
      instance_id = math.random(12345678),
      address = address,
      port = port,
    }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  -- Gets the next transaction ID
  -- @return trans_id number
  getTransactionId = function(self)
    self.trans_id = self.trans_id + 1
    return self.trans_id
  end,

  -- Gets the next instance ID
  -- @return instance_id number
  getInstanceId = function(self)
    self.instance_id = self.instance_id + 1
    return self.instance_id
  end,

  -- Gets the stored local address used to create the session
  -- @return string containing the IP passed to the session
  getAddress = function(self)
    return self.address
  end,

  -- Get the stored local port used to create the session
  -- @return number containing the local port
  getPort = function(self)
    return self.port
  end

}

-- The Helper class, used as main interface between the scripts and the library
Helper = {

  -- Creates a new instance of the Helper class
  -- @param host table as passed to the action method
  -- @param port table as passed to the action method
  -- @param lhost [optional] used if an alternate local address is to be
  --        passed in the requests to the remote node (ie. NAT is in play).
  -- @param lport [optional] used if an alternate port is to be passed in
  --        the requests to the remote node.
  -- @return o new instance of Helper
  new = function(self, host, port, lhost, lport)
    local o = {
      host = host,
      port = port,
      lhost = lhost,
      lport = lport
    }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  -- Connects to the remote Vuze Node
  -- @return true on success, false on failure
  -- @return err string error message if status is false
  connect = function(self)
    local lhost = self.lhost or stdnse.get_script_args('vuzedht.lhost')
    local lport = self.lport or stdnse.get_script_args('vuzedht.lport')

    self.socket = nmap.new_socket()

    if ( lport ) then
      self.socket:bind(nil, lport)
    end
    local status, err = self.socket:connect(self.host, self.port)
    if ( not(status) ) then
      return false, "Failed to connect to server"
    end

    if ( not(lhost) or not(lport) ) then
      local status, lh, lp, _, _ = self.socket:get_info()
      if ( not(status) ) then
        return false, "Failed to get socket information"
      end
      lhost = lhost or lh
      lport = lport or lp
    end

    self.session = Session:new(lhost, lport)
    return true
  end,

  -- Sends a Vuze PING request to the server and parses the response
  -- @return status true on success, false on failure
  -- @return response PING response instance on success,
  --         err string containing the error message on failure
  ping = function(self)
    local ping = Request.Ping:new(self.session)
    local status, err = self.socket:send(tostring(ping))
    if ( not(status) ) then
      return false, "Failed to send PING request to server"
    end

    local data
    status, data = self.socket:receive()
    if ( not(status) ) then
      return false, "Failed to receive PING response from server"
    end
    local response
    status, response = Response.fromString(data)
    if ( not(status) ) then
      return false, "Failed to parse PING response from server"
    end
    return true, response
  end,

  -- Requests a list of known nodes by sending the FIND_NODES request
  -- to the remote node and parses the response.
  -- @return status true on success, false on failure
  -- @return response FIND_NODE response instance on success
  --         err string containing the error message on failure
  findNodes = function(self)
    local find = Request.FindNode:new(self.session)
    local status, err = self.socket:send(tostring(find))
    if ( not(status) ) then
      return false, "Failed to send FIND_NODE request to server"
    end

    local data
    status, data = self.socket:receive()
    local response
    status, response = Response.fromString(data)
    if ( not(status) ) then
      return false, "Failed to parse FIND_NODE response from server"
    end
    return true, response
  end,

  -- Closes the socket connect to the remote node
  close = function(self)
    self.socket:close()
  end,
}

return _ENV;
