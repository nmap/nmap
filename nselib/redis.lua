--- A minimalistic Redis (in-memory key-value data store) library.
--
-- @author Patrik Karlsson <patrik@cqure.net>

local match = require "match"
local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"
local comm = require "comm"
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

local socket_wrapper = {
  new = function(self, socket, init)
    local o = {
      socket = socket,
      init = init,
      pos = init and 1 or nil,
    }
    setmetatable (o,self)
    self.__index = self
    return o
  end,

  getline = function(self)
    if self.pos then
      local oldpos = self.pos
      local first, last = self.init:find("\r\n", oldpos)
      if first then
        stdnse.debug1("getline: found line: %s", self.init:sub(oldpos, first-1))
        self.pos = last < #self.init and (last + 1) or nil
        return true, self.init:sub(oldpos, first-1)
      else
        stdnse.debug1("getline: no line found: %s", self.init:sub(oldpos))
        self.pos = nil
        local status, more = self.socket:receive_buf(match.pattern_limit("\r\n", 2048), false)
        if not status then
          return status, more
        end
        return true, self.init:sub(oldpos) .. more
      end
    end
    return self.socket:receive_buf(match.pattern_limit("\r\n", 2048), false)
  end,

  getbytes = function(self, len)
    if self.pos then
      local remains = #self.init - self.pos + 1
      stdnse.debug1("getbytes(%d), remains=%d", len, remains)
      if remains == len then
        self.pos = nil
        return true, self.init:sub(-len)
      elseif remains > len then
        local part = self.init:sub(self.pos, self.pos + len - 1)
        self.pos = self.pos + len
        return true, part
      else
        local part = self.init:sub(self.pos)
        self.pos = nil
        local status, more = self.socket:receive_buf(match.numbytes(len - #part), false)
        if not status then
          return status, more
        end
        return true, part .. more
      end
    end
    return self.socket:receive_buf(match.numbytes(len), true)
  end,
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

  receive = function(self, init)
    stdnse.debug1("Response.receive(%d)", #(init or ""))
    local sock = socket_wrapper:new(self.socket, init)
    local status, data = sock:getline()
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
      status, data = sock:getbytes(len)
      if( not(status) ) then
        return false, "Failed to receive data from server"
      end
      -- move past the terminal CRLF
      local status, crlf = sock:getline()

      return true, { data = data, type = Response.Type.BULK }
    end

    -- process multi-bulk reply
    if ( data:match("^%*%d*") ) then
      local count = data:match("^%*(%d*)")
      local results = {}

      for i=1, count do
        -- peel of the length
        local status = sock:getline()
        if( not(status) ) then
          return false, "Failed to receive data from server"
        end

        status, data = sock:getline()
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
    return true
  end,

  do_send = function(self, payload)
    local response
    if not self.socket then
      self.socket, response = comm.tryssl(self.host, self.port, payload)
      return not not self.socket, response
    else
      return self.socket:send(payload)
    end
  end,

  reqCmd = function(self, cmd, ...)
    local req = Request:new(cmd, ...)
    local status, err_or_response = self:do_send(tostring(req))
    if (not(status)) then
      return false, "Failed to send command to server"
    end
    return Response:new(self.socket):receive(err_or_response)
  end,

  close = function(self)
    return self.socket:close()
  end

}

return _ENV;
