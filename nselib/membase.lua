---
-- A smallish implementation of the Couchbase Membase TAP protocol
-- Based on the scarce documentation from the Couchbase Wiki:
-- * http://www.couchbase.org/wiki/display/membase/SASL+Authentication+Example
--
-- @args membase.authmech SASL authentication mechanism to use. Default and
--                        currently supported: PLAIN
--
-- @author Patrik Karlsson <patrik@cqure.net>
--


local match = require "match"
local nmap = require "nmap"
local sasl = require "sasl"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
_ENV = stdnse.module("membase", stdnse.seeall)

-- A minimalistic implementation of the Couchbase Membase TAP protocol
TAP = {

  -- Operations
  Op = {
    LIST_SASL_MECHS = 0x20,
    AUTHENTICATE = 0x21,
  },

  -- Requests
  Request = {

    -- Header breakdown
    -- Field        (offset) (value)
    -- Magic            (0): 0x80 (PROTOCOL_BINARY_REQ)
    -- Opcode           (1): 0x00
    -- Key length     (2-3): 0x0000 (0)
    -- Extra length     (4): 0x00
    -- Data type        (5): 0x00
    -- vbucket        (6-7): 0x0000 (0)
    -- Total body    (8-11): 0x00000000 (0)
    -- Opaque       (12-15): 0x00000000 (0)
    -- CAS          (16-23): 0x0000000000000000 (0)
    Header = {

      -- Creates a new instance of Header
      -- @param opcode number containing the operation
      -- @return o new instance of Header
      new = function(self, opcode)
        local o = {
          magic = 0x80,
          opcode = tonumber(opcode),
          keylen = 0x0000,
          extlen = 0x00,
          data_type = 0x00,
          vbucket = 0x0000,
          total_body = 0x00000000,
          opaque = 0x00000000,
          CAS = 0x0000000000000000,
        }
        setmetatable(o, self)
        self.__index = self
        return o
      end,

      -- Converts the header to string
      -- @return string containing the Header as string
      __tostring = function(self)
        return string.pack(">BB I2 BB I2 I4 I4 I8", self.magic, self.opcode, self.keylen,
        self.extlen, self.data_type, self.vbucket, self.total_body,
        self.opaque, self.CAS)
      end,
    },

    -- List SASL authentication mechanism
    SASLList = {

      -- Creates a new instance of the request
      -- @return o instance of request
      new = function(self)
        local o = {
          -- 0x20 SASL List Mechs
          header = TAP.Request.Header:new(TAP.Op.LIST_SASL_MECHS)
        }
        setmetatable(o, self)
        self.__index = self
        return o
      end,

      -- Converts the request to string
      -- @return string containing the request as string
      __tostring = function(self)
        return tostring(self.header)
      end,
    },

    -- Authenticates using SASL
    Authenticate = {

      -- Creates a new instance of the request
      -- @param username string containing the username
      -- @param password string containing the password
      -- @param mech string containing the SASL mechanism, currently supported:
      --        PLAIN - plain-text authentication
      -- @return o instance of request
      new = function(self, username, password, mech)
        local o = {
          -- 0x20 SASL List Mechs
          header = TAP.Request.Header:new(TAP.Op.AUTHENTICATE),
          username = username,
          password = password,
          mech = mech,
        }
        setmetatable(o, self)
        self.__index = self
        return o
      end,

      -- Converts the request to string
      -- @return string containing the request as string
      __tostring = function(self)
        if ( self.mech == "PLAIN" ) then
          local mech_params = { self.username, self.password }
          local auth_data = sasl.Helper:new(self.mech):encode(table.unpack(mech_params))

          self.header.keylen = #self.mech
          self.header.total_body = #auth_data + #self.mech
          return tostring(self.header) .. self.mech .. auth_data
        end
      end,

    }

  },

  -- Responses
  Response = {

    -- The response header
    -- Header breakdown
    -- Field        (offset) (value)
    -- Magic            (0): 0x81 (PROTOCOL_BINARY_RES)
    -- Opcode           (1): 0x00
    -- Key length     (2-3): 0x0000 (0)
    -- Extra length     (4): 0x00
    -- Data type        (5): 0x00
    -- Status         (6-7): 0x0000 (SUCCESS)
    -- Total body    (8-11): 0x00000005 (5)
    -- Opaque       (12-15): 0x00000000 (0)
    -- CAS          (16-23): 0x0000000000000000 (0)
    Header = {

      -- Creates a new instance of Header
      -- @param data string containing the raw data
      -- @return o new instance of Header
      new = function(self, data)
        local o = {
          data = data
        }
        setmetatable(o, self)
        self.__index = self
        if ( o:parse() ) then
          return o
        end
      end,

      -- Parse the raw header and populates the class members
      -- @return status true on success, false on failure
      parse = function(self)
        if ( 24 > #self.data ) then
          stdnse.debug1("membase: Header packet too short (%d bytes)", #self.data)
          return false, "Packet to short"
        end
        local pos
        self.magic, self.opcode, self.keylen, self.extlen,
          self.data_type, self.status, self.total_body, self.opaque,
          self.BAI2 , pos = string.unpack(">BB I2 BB I2 I4 I4 I8", self.data)
        return true
      end

    },

    -- Decoders
    Decoder = {

      -- TAP.Op.LIST_SASL_MECHS
      [0x20] = {
        -- Creates a new instance of the decoder
        -- @param data string containing the raw response
        -- @return o instance if successfully parsed, nil on failure
        --         the member variable <code>mechs</code> contains the
        --         supported authentication mechanisms.
        new = function(self, data)
          local o = { data = data }
          setmetatable(o, self)
          self.__index = self
          if ( o:parse() ) then
            return o
          end
        end,

        -- Parses the raw response
        -- @return true on success
        parse = function(self)
          self.mechs = self.data
          return true
        end
      },

      -- Login response
      [0x21] = {
        -- Creates a new instance of the decoder
        -- @param data string containing the raw response
        -- @return o instance if successfully parsed, nil on failure
        --         the member variable <code>status</code> contains the
        --         servers authentication response.
        new = function(self, data)
          local o = { data = data }
          setmetatable(o, self)
          self.__index = self
          if ( o:parse() ) then
            return o
          end
        end,

        -- Parses the raw response
        -- @return true on success
        parse = function(self)
          self.status = self.data
          return true
        end
      }

    }

  },

}

-- The Helper class is the main script interface
Helper = {

  -- Creates a new instance of the helper
  -- @param host table as received by the action method
  -- @param port table as received by the action method
  -- @param options table including options to the helper, currently:
  --        <code>timeout</code> - socket timeout in milliseconds
  new = function(self, host, port, options)
    local o = {
      host = host,
      port = port,
      mech = stdnse.get_script_args("membase.authmech"),
      options = options or {}
    }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  -- Connects the socket to the server
  -- @return true on success, false on failure
  connect = function(self, socket)
    self.socket = socket or nmap.new_socket()
    self.socket:set_timeout(self.options.timeout or 10000)
    return self.socket:connect(self.host, self.port)
  end,

  -- Closes the socket
  close = function(self)
    return self.socket:close()
  end,

  -- Sends a request to the server, receives and parses the response
  -- @param req a Request instance
  -- @return status true on success, false on failure
  -- @return response instance of Response
  exch = function(self, req)
    local status, err = self.socket:send(tostring(req))
    if ( not(status) ) then
      return false, "Failed to send data"
    end

    local data
    status, data = self.socket:receive_buf(match.numbytes(24), true)
    if ( not(status) ) then
      return false, "Failed to receive data"
    end

    local header = TAP.Response.Header:new(data)

    if ( header.opcode ~= req.header.opcode ) then
      stdnse.debug1("WARNING: Received invalid op code, request contained (%d), response contained (%d)", req.header.opcode, header.opcode)
    end

    if ( not(TAP.Response.Decoder[tonumber(header.opcode)]) ) then
      return false, ("No response handler for opcode: %d"):format(header.opcode)
    end

    local status, data = self.socket:receive_buf(match.numbytes(header.total_body), true)
    if ( not(status) ) then
      return false, "Failed to receive data"
    end

    local response = TAP.Response.Decoder[tonumber(header.opcode)]:new(data)
    if ( not(response) ) then
      return false, "Failed to parse response from server"
    end
    return true, response
  end,

  -- Gets list of supported SASL authentication mechanisms
  getSASLMechList = function(self)
    return self:exch(TAP.Request.SASLList:new())
  end,

  -- Logins to the server
  -- @param username string containing the username
  -- @param password string containing the password
  -- @param mech string containing the SASL mechanism to use
  -- @return status true on success, false on failure
  -- @return response string containing "Auth failure" on failure
  login = function(self, username, password, mech)
    mech = mech or self.mech or "PLAIN"
    local status, response = self:exch(TAP.Request.Authenticate:new(username, password, mech))
    if ( not(status) ) then
      return false, "Auth failure"
    end
    if ( response.status == "Auth failure" ) then
      return false, response.status
    end
    return true, response.status
  end,
}



return _ENV;
