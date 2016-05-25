---
-- A minimalistic Asterisk IAX2 (Inter-Asterisk eXchange v2) VoIP protocol implementation.
-- The library implements the minimum needed to perform brute force password guessing.
--
-- @author "Patrik Karlsson <patrik@cqure.net>"
--

local bin = require "bin"
local bit = require "bit"
local math = require "math"
local nmap = require "nmap"
local os = require "os"
local stdnse = require "stdnse"
local openssl = stdnse.silent_require "openssl"
local table = require "table"
_ENV = stdnse.module("iax2", stdnse.seeall)


IAX2 = {

  FrameType = {
    IAX = 6,
  },

  SubClass = {
    ACK = 0x04,
    REGACK = 0x0f,
    REGREJ = 0x10,
    REGREL = 0x11,
    CALLTOKEN = 0x28,
  },

  InfoElement = {
    USERNAME = 0x06,
    CHALLENGE = 0x0f,
    MD5_RESULT = 0x10,
    CALLTOKEN = 0x36,
  },

  PacketType = {
    FULL = 1,
  },

  -- The IAX2 Header
  Header = {

    -- Creates a new Header instance
    -- @param src_call number containing the source call
    -- @param dst_call number containing the dest call
    -- @param timestamp number containing a timestamp
    -- @param oseqno number containing the seqno of outgoing packets
    -- @param iseqno number containing the seqno of incoming packets
    -- @param frametype number containing the frame type
    -- @param subclass number containing the subclass type
    new = function(self, src_call, dst_call, timestamp, oseqno, iseqno, frametype, subclass)
      local o = {
        type = IAX2.PacketType.FULL,
        retrans = false,
        src_call = src_call,
        dst_call = dst_call,
        timestamp = timestamp,
        oseqno = oseqno,
        iseqno = iseqno,
        frametype = frametype,
        subclass = subclass,
      }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    -- Parses data, a byte string, and creates a new Header instance
    -- @return header instance of Header
    parse = function(data)
      local header = IAX2.Header:new()
      local pos, frame_type = bin.unpack("C", data)
      if ( bit.band(frame_type, 0x80) == 0 ) then
        print("frame_type", stdnse.tohex(frame_type))
        stdnse.debug2("Frametype not supported")
        return
      end
      header.type = IAX2.PacketType.FULL
      pos, header.src_call = bin.unpack(">S", data)
      header.src_call = bit.band(header.src_call, 0x7FFF)

      local retrans
      pos, retrans = bin.unpack("C", data, pos)
      if ( bit.band(retrans, 0x80) == 8 ) then
        header.retrans = true
      end
      pos, header.dst_call = bin.unpack(">S", data, pos - 1)
      header.dst_call = bit.band(header.dst_call, 0x7FFF)

      pos, header.timestamp, header.oseqno,
        header.iseqno, header.frametype, header.subclass = bin.unpack(">ICCCC", data, pos)

      return header
    end,

    -- Converts the instance to a string
    -- @return str containing the instance
    __tostring = function(self)
      assert(self.src_call < 32767, "Source call exceeds 32767")
      assert(self.dst_call < 32767, "Dest call exceeds 32767")
      local src_call = self.src_call
      local dst_call = self.dst_call
      if ( self.type == IAX2.PacketType.FULL ) then
        src_call = src_call + 32768
      end
      if ( self.retrans ) then
        dst_call = dst_call + 32768
      end
      return bin.pack(">SSICCCC", src_call, dst_call, self.timestamp,
        self.oseqno, self.iseqno, self.frametype, self.subclass)
    end,
  },

  -- The IAX2 Request class
  Request = {

    -- Creates a new instance
    -- @param header instance of Header
    new = function(self, header)
      local o = {
        header = header,
        ies = {}
      }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    -- Sets an Info Element or adds one, in case it's missing
    -- @param key the key value of the IE to add
    -- @param value string containing the value to set or add
    setIE = function(self, key, value)
      for _, ie in ipairs(self.ies or {}) do
        if ( key == ie.type ) then
          ie.value = value
        end
      end
      table.insert(self.ies, { type = key, value = value } )
    end,

    -- Gets an information element
    -- @param key number containing the element number to retrieve
    -- @return ie table containing the info element if it exists
    getIE = function(self, key)
      for _, ie in ipairs(self.ies or {}) do
        if ( key == ie.type ) then
          return ie
        end
      end
    end,

    -- Converts the instance to a string
    -- @return str containing the instance
    __tostring = function(self)
      local data = ""
      for _, ie in ipairs(self.ies) do
        data = data .. bin.pack("Cp", ie.type, ie.value )
      end

      return tostring(self.header) .. data
    end,

  },


  -- The IAX2 Response
  Response = {

    -- Creates a new instance
    new = function(self)
      local o = { ies = {} }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    -- Sets an Info Element or adds one, in case it's missing
    -- @param key the key value of the IE to add
    -- @param value string containing the value to set or add
    setIE = function(self, key, value)
      for _, ie in ipairs(self.ies or {}) do
        if ( key == ie.type ) then
          ie.value = value
        end
      end
      table.insert(self.ies, { type = key, value = value } )
    end,

    -- Gets an information element
    -- @param key number containing the element number to retrieve
    -- @return ie table containing the info element if it exists
    getIE = function(self, key)
      for _, ie in ipairs(self.ies or {}) do
        if ( key == ie.type ) then
          return ie
        end
      end
    end,

    -- Parses data, a byte string, and creates a response
    -- @return resp instance of response
    parse = function(data)
      local resp = IAX2.Response:new()
      if ( not(resp) ) then return end

      resp.header = IAX2.Header.parse(data)
      if ( not(resp.header) ) then return end

      local pos = 13
      resp.ies = {}
      repeat
        local ie = {}
        pos, ie.type, ie.value = bin.unpack(">Cp", data, pos)
        table.insert(resp.ies, ie)
      until( pos > #data )
      return resp
    end,

  }

}


Helper = {

  -- Creates a new Helper instance
  -- @param host table as received by the action method
  -- @param port table as received by the action method
  -- @param options table containing helper options, currently
  --        <code>timeout</code> socket timeout in ms
  -- @return o instance of Helper
  new = function(self, host, port, options)
    local o = { host = host, port = port, options = options or {} }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  -- Connects the UDP socket to the server
  -- @return status true on success, false on failure
  -- @return err message containing error if status is false
  connect = function(self)
    self.socket = nmap.new_socket()
    self.socket:set_timeout(self.options.timeout or 5000)
    return self.socket:connect(self.host, self.port)
  end,

  -- Sends a request to the server and receives the response
  -- @param req instance containing the request to send to the server
  -- @return status true on success, false on failure
  -- @return resp instance of response on success,
  --         err containing the error message on failure
  exch = function(self, req)
    local status, err = self.socket:send(tostring(req))
    if ( not(status) ) then
      return false, "Failed to send request to server"
    end
    local status, data = self.socket:receive()
    if ( not(status) ) then
      return false, "Failed to receive response from server"
    end

    local resp = IAX2.Response.parse(data)
    return true, resp
  end,

  -- Request a session release
  -- @param username string containing the extension (username)
  -- @param password string containing the password
  regRelease = function(self, username, password)

    local src_call = math.random(32767)
    local header = IAX2.Header:new(src_call, 0, os.time(), 0, 0, IAX2.FrameType.IAX, IAX2.SubClass.REGREL)
    local regrel = IAX2.Request:new(header)

    regrel:setIE(IAX2.InfoElement.USERNAME, username)
    regrel:setIE(IAX2.InfoElement.CALLTOKEN, "")

    local status, resp = self:exch(regrel)
    if ( not(status) ) then
      return false, resp
    end

    if ( not(resp) or IAX2.SubClass.CALLTOKEN ~= resp.header.subclass ) then
      return false, "Unexpected response"
    end

    local token = resp:getIE(IAX2.InfoElement.CALLTOKEN)
    if ( not(token) ) then
      return false, "Failed to get token"
    end

    regrel:setIE(IAX2.InfoElement.CALLTOKEN, token.value)
    status, resp = self:exch(regrel)
    if ( not(status) ) then
      return false, resp
    end

    local challenge = resp:getIE(IAX2.InfoElement.CHALLENGE)
    if ( not(challenge) ) then
      return false, "Failed to retrieve challenge from server"
    end

    regrel.header.iseqno = 1
    regrel.header.oseqno = 1
    regrel.header.dst_call = resp.header.src_call
    regrel.ies = {}

    local hash = stdnse.tohex(openssl.md5(challenge.value .. password))
    regrel:setIE(IAX2.InfoElement.USERNAME, username)
    regrel:setIE(IAX2.InfoElement.MD5_RESULT, hash)

    status, resp = self:exch(regrel)
    if ( not(status) ) then
      return false, resp
    end

    if ( IAX2.SubClass.ACK == resp.header.subclass ) then
      local data
      status, data = self.socket:receive()
      resp = IAX2.Response.parse(data)
    end

    if ( status and IAX2.SubClass.REGACK == resp.header.subclass ) then
      return true
    end
    return false, "Release failed"
  end,

  -- Close the connection with the server
  -- @return true on success, false on failure
  close = function(self)
    return self.socket:close()
  end,


}

return _ENV;
