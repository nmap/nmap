---
-- A smallish SOCKS version 5 proxy protocol implementation
--
-- @author Patrik Karlsson <patrik@cqure.net>
--

local bin = require "bin"
local match = require "match"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
_ENV = stdnse.module("socks", stdnse.seeall)

-- SOCKS Authentication methods
AuthMethod = {
  NONE = 0,
  GSSAPI = 1,
  USERPASS = 2,
}

Request = {

  -- Class that handles the connection request to the server
  Connect = {

    -- Creates a new instance of the class
    -- @param auth_method table of requested authentication methods
    -- @return o instance on success, nil on failure
    new = function(self, auth_method)
      local o = {
        version = 5,
        auth_method = ( "table" ~= type(auth_method) and { auth_method } or auth_method )
      }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    -- Converts the instance to string, so that it can be sent to the
    -- server.
    -- @return string containing the raw request
    __tostring = function(self)
      local methods = ""
      for _, m in ipairs(self.auth_method) do
        methods = methods .. string.char(m)
      end
      return bin.pack("Cp", self.version, methods)
    end,

  },

  -- Class that handles the authentication request to the server
  Authenticate = {

    -- Creates a new instance of the class
    -- @param auth_method number with the requested authentication method
    -- @param creds method specific table of credentials
    --        currently only user and pass authentication is supported
    --        this method requires two fields to be present
    --        <code>username</code> and <code>password</code>
    -- @return o instance on success, nil on failure
    new = function(self, auth_method, creds)
      local o = {
        auth_method = auth_method,
        creds = creds
      }
      setmetatable(o, self)
      self.__index = self
      if ( auth_method == 2 ) then
        return o
      end
    end,

    -- Converts the instance to string, so that it can be sent to the
    -- server.
    -- @return string containing the raw request
    __tostring = function(self)
      -- we really don't support anything but 2, but let's pretend that
      -- we actually do
      if ( 2 == self.auth_method ) then
        local version = 1
        local username= self.creds.username or ""
        local password= self.creds.password or ""

        username = (username == "") and "\0" or username
        password = (password == "") and "\0" or password

        return bin.pack("Cpp", version, username, password)
      end
    end,

  }

}

Response = {

  -- Class that handles the connection response
  Connect = {

    -- Creates a new instance of the class
    -- @param data string containing the data as received over the socket
    -- @return o instance on success, nil on failure
    new = function(self, data)
      local o = { data = data }
      setmetatable(o, self)
      self.__index = self
      if ( o:parse() ) then
        return o
      end
    end,

    -- Parses the received data and populates member variables
    -- @return true on success, false on failure
    parse = function(self)
      if ( #self.data ~= 2 ) then
        return
      end
      local pos
      pos, self.version, self.method = bin.unpack("CC", self.data)
      return true
    end

  },

  -- Class that handles the authentication response
  Authenticate = {

    Status = {
      SUCCESS = 0,
      -- could be anything but zero
      FAIL    = 1,
    },

    -- Creates a new instance of the class
    -- @param data string containing the data as received over the socket
    -- @return o instance on success, nil on failure
    new = function(self, data)
      local o = { data = data }
      setmetatable(o, self)
      self.__index = self
      if ( o:parse() ) then
        return o
      end
    end,

    -- Parses the received data and populates member variables
    -- @return true on success, false on failure
    parse = function(self)
      if ( #self.data ~= 2 ) then
        return
      end
      local pos
      pos, self.version, self.status = bin.unpack("CC", self.data)
      return true
    end,

    -- checks if the authentication was successful or not
    -- @return true on success, false on failure
    isSuccess = function(self)
      return ( self.status == self.Status.SUCCESS )
    end,

  }

}

-- The main script interface
Helper = {

  -- Create a new instance of the class
  -- @param host table containing the host table
  -- @param port table containing the port table
  -- @param options table containing library options, currently:
  --        <code>timeout</code> - socket timeout in ms
  -- @return o instance of Helper
  new = function(self, host, port, options)
    options = options or {}
    local o = { host = host, port = port, options = options }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  -- Get the authentication method name by number
  -- @param method number containing the authentication method
  -- @return string containing the method name or Unknown
  authNameByNumber = function(self, method)
    local methods = {
      [0]  = "No authentication",
      [1]  = "GSSAPI",
      [2]  = "Username and password",
    }
    return methods[method] or ("Unknown method (%d)"):format(method)
  end,

  -- Connects to the SOCKS server
  -- @param auth_method table containing the auth. methods to request
  -- @return status true on success, false on failure
  -- @return response table containing the response or err string on failure
  connect = function(self, auth_method, socket)
    self.socket = socket or nmap.new_socket()
    self.socket:set_timeout(self.options.timeout or 10000)
    local status, err = self.socket:connect(self.host, self.port)
    if ( not(status) ) then
      return status, err
    end

    auth_method = auth_method or {AuthMethod.NONE, AuthMethod.GSSAPI, AuthMethod.USERPASS}
    status = self.socket:send( tostring(Request.Connect:new(auth_method)) )
    if ( not(status) ) then
      self.socket:close()
      return false, "Failed to send connection request to server"
    end

    local status, data = self.socket:receive_buf(match.numbytes(2), true)
    if ( not(status) ) then
      self.socket:close()
      return false, "Failed to receive connection response from server"
    end

    local response = Response.Connect:new(data)
    if ( not(response) ) then
      return false, "Failed to parse response from server"
    end

    if ( response.version ~= 5 ) then
      return false, ("Unsupported SOCKS version (%d)"):format(response.version)
    end
    if ( response.method == 0xFF ) then
      return false, "No acceptable authentication methods"
    end

    -- store the method so authenticate knows what to use
    self.auth_method = response.method
    return true, response
  end,

  -- Authenticates to the SOCKS server
  -- @param creds table containing authentication method specific fields
  --        currently only authentication method 2 (username and pass) is
  --        implemented. That method requires the following fields:
  --        <code>username</code> - containing the username
  --        <code>password</code> - containing the password
  -- @return status true on success, false on failure
  -- @return err string containing the error message
  authenticate = function(self, creds)
    if ( self.auth_method ~= 2 ) then
      return false, "Authentication method not supported"
    end
    local req = Request.Authenticate:new(self.auth_method, creds)
    if ( not(req) ) then
      return false, "Failed to create authentication request"
    end

    local status = self.socket:send(tostring(req))
    if ( not(status) ) then
      return false, "Failed to send authentication request"
    end

    if ( 2 == self.auth_method ) then
      local status, data = self.socket:receive_buf(match.numbytes(2), true)
      local auth = Response.Authenticate:new(data)

      if ( not(auth) ) then
        return false, "Failed to parse authentication response"
      end

      if ( auth:isSuccess() ) then
        return true, "Authentication was successful"
      else
        return false, "Authentication failed"
      end

    end
    return false, "Unsupported authentication method"
  end,

  -- closes the connection to the server
  close = function(self)
    return self.socket:close()
  end,

}

return _ENV;
