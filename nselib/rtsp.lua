---
-- This Real Time Streaming Protocol (RTSP) library implements only a minimal
-- subset of the protocol needed by the current scripts.
--
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
-- @author Patrik Karlsson <patrik@cqure.net>
--
-- The library contains the following classes:
--
-- * <code>Request</code>
-- ** This class contains the functions needed to create the RTSP request
--
-- * <code>Response</code>
-- ** This class contains the functions needed to parse the RTSP response
--
-- * <code>Client</code>
-- ** This class contains the RTSP client, a class responsible for sending
--    and receiving requests and responses to/from the server
--
-- * <code>Helper</code>
-- ** This class serves as the main interface for script writers
--
-- The following sample code shows how to use the library:
-- <code>
--   local helper = rtsp.Helper:new(host, port)
--   local status = helper:connect()
--   local response
--   status, response = helper:describe(url)
--   helper:close()
-- </code>

--
-- Version 0.1
-- Created 10/23/2011 - v0.1 - Created by Patrik Karlsson
--

local nmap = require "nmap"
local stdnse = require "stdnse"
local table = require "table"
_ENV = stdnse.module("rtsp", stdnse.seeall)

-- The RTSP Request object
Request = {

  --- Creates a new Request instance
  -- @return o instance of Request
  new = function(self, url, headers)
    local o = { url = url, req = {}, headers = headers or {} }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  --- Sets the RTSP Request method
  -- @param method string containing the RTSP method
  setMethod = function(self, method)
    self.method = method
  end,

  --- Sets the RTSP sequence number
  -- @param cseq number containing the sequence number
  setCSeq = function(self, cseq)
    self.cseq = cseq
  end,

  --- Adds an optional header to the RTSP request
  -- @param header string containing the header name
  -- @param value string containing the header value
  addHeader = function(self, header, value)
    table.insert( self.headers, { header = value } )
  end,

  --- Converts the Request to a string
  --
  -- @return req string containing the request as a string
  __tostring = function(self)
    assert(self.cseq, "Request is missing required header CSeq")
    assert(self.url, "Request is missing URL")

    local req = stdnse.strjoin("\r\n", {
      ("%s %s RTSP/1.0"):format(self.method, self.url),
      ("CSeq: %d"):format(self.cseq)
    } ) .. "\r\n"
    if ( #self.headers > 0 ) then
      req = req .. stdnse.strjoin("\r\n", self.headers) .. "\r\n"
    end

    return req .. "\r\n"
  end,
}

-- The RTSP response instance
Response = {

  --- Creates a new Response instance
  -- @param data string containing the unparsed data
  new = function(self, data)
    assert(data, "No data was supplied")
    local o = {
      raw = data,
      status = tonumber(data:match("^RTSP%/1%.0 (%d*) "))
    }

    -- Split the response into a temporary array
    local tmp = stdnse.strsplit("\r\n", data)
    if ( not(tmp) ) then return nil end

    -- we should have atleast one entry
    if ( #tmp > 1 ) then
      o.headers = {}
      for i=2, #tmp do
        -- if we have an empty line, this should be the end of headers
        if ( #tmp[i] == 0 ) then break end
        local key, val = tmp[i]:match("^(.-): (.*)$")
        -- create a key per header name
        o.headers[key] = val
      end
    end

    setmetatable(o, self)
    self.__index = self
    return o
  end,

}


-- RTSP Client class
Client = {

  -- Creates a new Client instance
  -- @param host table as received by the action method
  -- @param port table as received by the action method
  -- @return o instance of Client
  new = function(self, host, port)
    local o = {
      host = host,
      port = port,
      cseq = 0,
      headers = { },
      retries = 3,
      timeout = 10 * 1000,
    }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  --- Sets the number of retries for socket reads
  -- @param retries number containing the number of retries
  setRetries = function(self, retries) self.retries = retries end,

  --- Sets the socket connection timeout in ms
  -- @param timeout number containing the timeout in ms
  setTimeout = function(self, timeout) self.timeout = timeout end,

  --- Adds a RTSP header to the request
  -- @param header string containing the header name
  -- @param value string containing the header value
  addHeader = function(self, header, value)
    table.insert(self.headers, { ("%s: %s"):format(header,value) } )
  end,

  --- Connects to the RTSP server
  -- @return status true on success, false on failure
  -- @return err string containing the error message on failure
  connect = function(self)
    self.socket = nmap.new_socket()
    self.socket:set_timeout(self.timeout)
    local status = self.socket:connect(self.host, self.port)
    if ( not(status) ) then
      stdnse.debug2("Failed to connect to the server: %s", self.host.ip)
      return false, ("Failed to connect to the server: %s"):format(self.host.ip)
    end
    return true
  end,

  --- Sends a DESCRIBE request to the server and receives the response
  -- @param url string containing the RTSP URL
  -- @return status true on success, false on failure
  -- @return response Response instance on success
  --         err string containing the error message on failure
  describe = function(self, url)
    local req = Request:new(url, self.headers)
    req:setMethod("DESCRIBE")
    return self:exch(req)
  end,

  options = function(self, url)
    local req = Request:new(url, self.headers)
    req:setMethod("OPTIONS")
    return self:exch(req)
  end,

  --- Sends a request to the server and receives the response and attempts
  --  to retry if either send or receive fails.
  -- @param request instance of Request
  -- @return status true on success, false on failure
  -- @return response Response instance on success
  --         err string containing the error message on failure
  exch = function(self, req)
    local retries = self.retries
    local status, data
    self.cseq = self.cseq + 1
    req:setCSeq( self.cseq )

    repeat
      local err
      status, err = self.socket:send( tostring(req) )
      -- check if send was successful, in case it wasn't AND
      -- this is our last retry, ABORT
      if ( not(status) and 0 == retries - 1 ) then
        stdnse.debug2("Failed to send request to server (%s)", err)
        return false, ("Failed to send request to server (%s)"):format(err)
      -- if send was successful, attempt to receive the response
      elseif ( status ) then
        status, data = self.socket:receive()
        -- if we got the response all right, break out of retry loop
        if ( status ) then break end
      end
      -- if either send or receive fails, re-connect the socket
      if ( not(status) ) then
        self:close()
        local status, err = self:connect()
        -- if re-connect fails, BAIL out of here
        if ( not(status) ) then
          stdnse.debug2("Failed to reconnect socket to server (%s)", err)
          return false, ("Failed to reconnect socket to server (%s)"):format(err)
        end
      end
      retries = retries - 1
    until( status or retries == 0 )

    if( not(status) ) then
      stdnse.debug2("Failed to receive response from server (%s)", data)
      return false, ("Failed to receive response from server (%s)"):format(data)
    end

    return true, Response:new(data)
  end,

  --- Closes the RTSP socket with the server
  close = function(self)
    return self.socket:close()
  end,

}

-- The Helper class is the main script interface
Helper = {

  -- Creates a new Helper instance
  -- @param host table as received by the action method
  -- @param port table as received by the action method
  -- @return o instance of Client
  new = function(self, host, port)
    local o = { host = host, port = port, client = Client:new(host, port) }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  -- Connects to the RTSP server
  -- @return status true on success, false on failure
  -- @return err string containing the error message on failure
  connect = function(self)
    return self.client:connect()
  end,

  -- Closes the RTSP socket with the server
  close = function(self)
    return self.client:close()
  end,

  -- Sends a DESCRIBE request to the server and receives the response
  --
  -- @param url string containing the RTSP URL
  -- @return status true on success, false on failure
  -- @return response string containing the unparsed RTSP response on success
  --         err string containing the error message on failure
  describe = function(self, url)
    return self.client:describe(url)
  end,

  options = function(self, url)
    return self.client:options(url)
  end,

}

return _ENV;
