---
-- A minimalist RSYNC (remote file sync) library
--
-- @author Patrik Karlsson <patrik@cqure.net>

local base64 = require "base64"
local match = require "match"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local openssl = stdnse.silent_require "openssl"
_ENV = stdnse.module("rsync", stdnse.seeall)


-- The Helper class serves as the main interface for script writers
Helper = {

  -- Creates a new instance of the Helper class
  -- @param host table as received by the action function
  -- @param port table as received by the action function
  -- @param options table containing any additional options
  -- @return o instance of Helper
  new = function(self, host, port, options)
    local o = { host = host, port = port, options = options or {} }
    assert(o.options.module, "No rsync module was specified, aborting ...")
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  -- Handles send and receive of control messages
  -- @param data string containing the command to send
  -- @return status true on success, false on failure
  -- @return data containing the response from the server
  --         err string, if status is false
  ctrl_exch = function(self, data)
    local status, err = self.socket:send(data.."\n")
    if ( not(status) ) then
      return false, err
    end
    local status, data = self.socket:receive_buf(match.pattern_limit("\n", 2048), false)
    if( not(status) ) then
      return false, err
    end
    return true, data
  end,

  -- Connects to the rsync server
  -- @return status, true on success, false on failure
  -- @return err string containing an error message if status is false
  connect = function(self, socket)
    self.socket = socket or nmap.new_socket()
    self.socket:set_timeout(self.options.timeout or 5000)
    local status, err = self.socket:connect(self.host, self.port)
    if ( not(status) ) then
      return false, err
    end

    local data
    status, data = self:ctrl_exch("@RSYNCD: 29")
    if ( not(status) ) then
      return false, data
    end
    if ( not(data:match("^@RSYNCD: [%.%d]+$")) ) then
      return false, "Protocol error"
    end
    return true
  end,

  -- Authenticates against the rsync module. If no username is given, assume
  -- no authentication is required.
  -- @param username [optional] string containing the username
  -- @param password [optional] string containing the password
  login = function(self, username, password)
    password = password or ""
    local status, data = self:ctrl_exch(self.options.module)
    if (not(status)) then
      return false, data
    end

    local chall
    if ( data:match("@RSYNCD: OK") ) then
      return true, "No authentication was required"
    else
      chall = data:match("^@RSYNCD: AUTHREQD (.*)$")
      if ( not(chall) and data:match("^@ERROR: Unknown module") ) then
        return false, data:match("^@ERROR: (.*)$")
      elseif ( not(chall) ) then
        return false, "Failed to retrieve challenge"
      end
    end

    if ( chall and not(username) ) then
      return false, "Authentication required"
    end

    local md4 = openssl.md4("\0\0\0\0" .. password .. chall)
    local resp = base64.enc(md4):sub(1,-3)
    status, data = self:ctrl_exch(username .. " " .. resp)
    if (not(status)) then
      return false, data
    end

    if ( data == "@RSYNCD: OK" ) then
      return true, "Authentication successful"
    end
    return false, "Authentication failed"
  end,

  -- Lists accessible modules from the rsync server
  -- @return status true on success, false on failure
  -- @return modules table containing a list of modules
  listModules = function(self)
    local status, data = self.socket:send("\n")
    if (not(status)) then
      return false, data
    end

    local modules = {}
    while(true) do
      status, data = self.socket:receive_buf(match.pattern_limit("\n", 2048), false)
      if (not(status)) then
        return false, data
      end
      if ( data == "@RSYNCD: EXIT" ) then
        break
      else
        table.insert(modules, data)
      end
    end
    return true, modules
  end,

  -- Lists the files available for the directory/module
  -- TODO: Add support for parsing results, seemed straight forward at
  --       first, but wasn't.
  listFiles = function(self)
    -- list recursively and enable MD4 checksums
    local data = ("--server\n--sender\n-rc\n.\n%s\n\n"):format(self.options.module)
    local status, data = self.socket:send(data)
    if ( not(status) ) then
      return false, data
    end
    status, data = self.socket:receive_bytes(4)
    if ( not(status) ) then
      return false, data
    end

    status, data = self.socket:send("\0\0\0\0")
    if ( not(status) ) then
      return false, data
    end

    status, data = self.socket:receive_buf(match.numbytes(4), true)
    if ( not(status) ) then
      return false, data
    end

    local len = string.unpack("<I2", data)
    status, data = self.socket:receive_buf(match.numbytes(len), true)
    if ( not(status) ) then
      return false, data
    end

    -- Parsing goes here
  end,

  -- Disconnects from the rsync server
  -- @return status true on success, false on failure
  disconnect = function(self) return self.socket:close() end,

}

return _ENV;
