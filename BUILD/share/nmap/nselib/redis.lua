--- A minimalistic Redis (in-memory key-value data store) library.
--
-- @author "Patrik Karlsson <patrik@cqure.net>"

local match = require "match"
local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"
_ENV = stdnse.module("redis", stdnse.seeall)

Request = {

  new = function(self, cmd, ...)
    local o = { cmd = cmd, args = {...} }
    setmetatable (o,self)
    self.__index = self
    return o
  end,

  __tostring = function(self)
    local output = ("*%s\r\n$%d\r\n%s\r\n"):format(#self.args + 1, #self.cmd, self.cmd)

    for _, arg in ipairs(self.args) do
      arg = tostring(arg)
      output = output .. ("$%s\r\n%s\r\n"):format(#arg, arg)
    end

    return output
  end

}


Response = {

  Type = {
    STATUS = 0,
    ERROR = 1,
    INTEGER = 2,
    BULK = 3,
    MULTIBULK = 4,
  },

  new = function(self, socket)
    local o = { socket = socket }
    setmetatable (o,self)
    self.__index = self
    return o
  end,

  receive = function(self)
    local status, data = self.socket:receive_buf("\r\n", false)
    if ( not(status) ) then
      return false, "Failed to receive data from server"
    end

    -- if we have a status, integer or error message
    if ( data:match("^[%-%+%:]") ) then
      local response = { data = data }
      local t = data:match("^([-+:])")
      if ( t == "-" ) then
        response.type = Response.Type.ERROR
      elseif ( t == "+" ) then
        response.type = Response.Type.STATUS
      elseif ( t == ":" ) then
        response.type = Response.Type.INTEGER
      end

      return true, response
    end

    -- process bulk reply
    if ( data:match("^%$") ) then
      -- non existing key
      if ( data == "$-1" ) then
        return true, nil
      end

      local len = tonumber(data:match("^%$(%d*)"))
      -- we should only have a single line, so we can just peel of the length
      status, data = self.socket:receive_buf(match.numbytes(len), false)
      if( not(status) ) then
        return false, "Failed to receive data from server"
      end

      return true, { data = data, type = Response.Type.BULK }
    end

    -- process multi-bulk reply
    if ( data:match("^%*%d*") ) then
      local count = data:match("^%*(%d*)")
      local results = {}

      for i=1, count do
        -- peel of the length
        local status = self.socket:receive_buf("\r\n", false)
        if( not(status) ) then
          return false, "Failed to receive data from server"
        end

        status, data = self.socket:receive_buf("\r\n", false)
        if( not(status) ) then
          return false, "Failed to receive data from server"
        end
        table.insert(results, data)
      end
      return true, { data = results, type = Response.Type.MULTIBULK }
    end

    return false, "Unsupported response"
  end,



}

Helper = {

  new = function(self, host, port)
    local o = { host = host, port = port }
    setmetatable (o,self)
    self.__index = self
    return o
  end,

  connect = function(self)
    self.socket = nmap.new_socket()
    return self.socket:connect(self.host, self.port)
  end,

  reqCmd = function(self, cmd, ...)
    local req = Request:new(cmd, ...)
    local status, err = self.socket:send(tostring(req))
    if (not(status)) then
      return false, "Failed to send command to server"
    end
    return Response:new(self.socket):receive()
  end,

  close = function(self)
    return self.socket:close()
  end

}

return _ENV;
