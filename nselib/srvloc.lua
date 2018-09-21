--- A relatively small implementation of the Service Location Protocol.
-- It was initially designed to support requests for discovering Novell NCP
-- servers, but should work for any other service as well.
--
-- The implementation is based on the following classes:
-- * Request.Service
--    - Contains necessary code to produce a service request
--
-- * Request.Attributes
--    - Contains necessary code to produce a attribute request
--
-- * Reply.Service
--    - Contains necessary code to process and parse the response to the
--      service request
--
-- * Reply.Attributes
--    - Contains necessary code to process and parse the response to the
--      attribute request
--
-- The following code illustrates intended use of the library:
--
--  <code>
--    local helper = srvloc.Helper:new()
--    local status, tree = helper:ServiceRequest("ndap.novell", "DEFAULT")
--    if ( status ) then tree = tree:match("%/%/%/(.*)%.$") end
--  </code>

--@author Patrik Karlsson <patrik@cqure.net>
--@copyright Same as Nmap--See https://nmap.org/book/man-legal.html

-- Version 0.1
-- Created 24/04/2011 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>

local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
_ENV = stdnse.module("srvloc", stdnse.seeall)

PacketFunction = {
  SERVICE_REQUEST = 1,
  SERVICE_REPLY = 2,
  ATTRIB_REQUEST = 6,
}

Reply = {

  Service = {

    --- Creates a new instance of the Reply.Service class
    -- @param data string containing the raw reply as read from the socket
    -- @return o instance of Reply.Service
    new = function(self, data)
      local o = { data = data }
      setmetatable(o, self)
      self.__index = self
      o:parse(data)
      return o
    end,

    --- Parses the service reply raw packet data
    -- @param data string containing the raw reply as read from the socket
    parse = function(self, data)
      local pos

      self.version, self.func, self.len, self.flags, pos = string.unpack(">BBI3I2", data)

      self.next_extension_offset, self.xid, self.lang_tag, pos = string.unpack(">I3I2s2", data, pos)

      local no_urls, reserved, url_len
      self.error_code, no_urls, pos = string.unpack(">I2I2", data, pos)

      if ( no_urls > 0 ) then
        local num_auths
        self.url_lifetime, self.url, num_auths, pos = string.unpack(">xI2s2C", data, pos)
      end
    end,

    --- Attempts to create an instance by reading data off the socket
    -- @param socket socket connected to the SRVLOC service
    -- @return new instance of the Reply.Service class
    fromSocket = function(socket)
      local status, data = socket:receive()
      if ( not(status) ) then return end
      return Reply.Service:new(data)
    end,

    --- Gets the url value from the reply
    -- @return uri string containing the reply url
    getUrl = function(self) return self.url end,
  },

  Attribute = {

    --- Creates a new instance of Reply.Attribute
    -- @param data string containing the raw reply as read from the socket
    -- @return o instance of Reply.Attribute
    new = function(self, data)
      local o = { data = data }
      setmetatable(o, self)
      self.__index = self
      o:parse(data)
      return o
    end,

    --- Parses the service reply raw packet data
    -- @param data string containing the raw reply as read from the socket
    parse = function(self, data)
      local pos

      self.version, self.func, self.len, pos = string.unpack(">BBI3", data)
      self.next_extension_offset, self.xid, self.lang_tag, pos = string.unpack(">I3I2s2", data, pos)

      local num_auths
      self.error_code, self.attrib_list, num_auths, pos = string.unpack(">I2s2B", data, pos)
    end,

    --- Attempts to create an instance by reading data off the socket
    -- @param socket socket connected to the SRVLOC service
    -- @return new instance of the Reply.Attribute class
    fromSocket = function(socket)
      local status, data = socket:receive()
      if ( not(status) ) then return end
      return Reply.Attribute:new(data)
    end,

    --- Gets the attribute list
    -- @return attrib_list
    getAttribList = function(self) return self.attrib_list end,
  }
}


Request = {

  -- The attribute request
  Attribute = {

    --- Creates a new instance of the Attribue request
    -- @return o instance of Attribute
    new = function(self)
      local o = {
        lang_tag = "en", version = 2, service_type = "",
        scope = "", next_extension_offset = 0,
        prev_resp_list_len = 0, slp_spi_len = 0 }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    --- Sets the request scope
    -- @param scope string containing the request scope
    setScope = function(self, scope) self.scope = scope end,

    --- Sets the language tag
    -- @param lang string containing the language
    setLangTag = function(self, lang) self.lang_tag = lang end,

    --- Sets the request flags
    -- @param flags number containing the numeric flag representation
    setFlags = function(self, flags) self.flags = flags end,

    --- Sets the request XID
    -- @param xid number containing the request XID
    setXID = function(self, xid) self.xid = xid end,

    --- Sets the request function
    -- @param func number containing the request function number
    setFunction = function(self, func) self.func = func end,

    --- Sets the request taglist
    -- @param tl string containing the taglist
    setTagList = function(self, tl) self.tag_list = tl end,

    --- Sets the request url
    -- @param u string containing the url
    setUrl = function(self, u) self.url = u end,

    --- "Serializes" the request to a string
    -- @return data string containing a string representation of the request
    __tostring = function(self)
      assert(self.func, "Packet function was not specified")
      assert(self.scope, "Packet scope was not specified")

      local BASE_LEN = 24
      local len = BASE_LEN + #self.lang_tag + self.prev_resp_list_len +
      self.slp_spi_len + #self.service_type + #self.url +
      #self.tag_list + #self.scope

      local data = string.pack(">BBI3I2I3I2s2I2s2s2s2I2", self.version, self.func,
        len, self.flags, self.next_extension_offset, self.xid, self.lang_tag,
        self.prev_resp_list_len, self.url, self.scope,
        self.tag_list, self.slp_spi_len)

      return data
    end
  },

  -- The Service request
  Service = {

    --- Creates a new instance of the Service request
    -- @return o instance of Service
    new = function(self)
      local o = {
        lang_tag = "en", version = 2, service_type = "",
        scope = "", next_extension_offset = 0,
        prev_resp_list_len = 0, predicate_len = 0, slp_spi_len = 0 }
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    --- Sets the service type of the request
    -- @param t string containing the type of the request
    setServiceType = function(self, t) self.service_type = t end,

    --- Sets the request scope
    -- @param scope string containing the request scope
    setScope = function(self, scope) self.scope = scope end,

    --- Sets the language tag
    -- @param lang string containing the language
    setLangTag = function(self, lang) self.lang_tag = lang end,

    --- Sets the request flags
    -- @param flags number containing the numeric flag representation
    setFlags = function(self, flags) self.flags = flags end,

    --- Sets the request XID
    -- @param xid number containing the request XID
    setXID = function(self, xid) self.xid = xid end,

    --- Sets the request function
    -- @param func number containing the request function number
    setFunction = function(self, func) self.func = func end,

    --- "Serializes" the request to a string
    -- @return data string containing a string representation of the request
    __tostring = function(self)
      assert(self.func, "Packet function was not specified")
      assert(self.scope, "Packet scope was not specified")

      local BASE_LEN = 24
      local len = BASE_LEN + #self.lang_tag + self.prev_resp_list_len +
        self.predicate_len + self.slp_spi_len + #self.service_type +
        #self.scope
      local len_hi = ((len >> 16) & 0x00FF)
      local len_lo = (len & 0xFFFF)
      local neo_hi = ((self.next_extension_offset >> 16) & 0x00FF)
      local neo_lo = (self.next_extension_offset & 0xFFFF)

      local data = string.pack(">BBI3I2I3I2s2I2s2s2I2I2", self.version, self.func,
        len, self.flags, self.next_extension_offset, self.xid, self.lang_tag,
        self.prev_resp_list_len, self.service_type,
        self.scope, self.predicate_len, self.slp_spi_len)

      return data
    end
  }

}


-- The Helper class serves as primary interface for scripts using the library
Helper = {

  new = function(self, host, port)
    local o = { xid = 1, socket = nmap.new_socket("udp") }
    setmetatable(o, self)
    self.__index = self
    local family = nmap.address_family()
    o.host = host or (family=="inet6" and "FF02::116" or "239.255.255.253")
    o.port = port or { number=427, proto="udp" }
    return o
  end,

  --- Sends a service request and waits for the response
  -- @param srvtype string containing the service type to query
  -- @param scope string containing the scope of the request
  -- @return true on success, false on failure
  -- @return url string (on success) containing the url of the ServiceReply
  -- @return err string (on failure) containing the error message
  ServiceRequest = function(self, srvtype, scope)
    local srvtype = srvtype or ""
    local scope = scope or ""
    local sr = Request.Service:new()
    sr:setXID(self.xid)
    sr:setServiceType(srvtype)
    sr:setScope(scope)
    sr:setFunction(PacketFunction.SERVICE_REQUEST)
    sr:setFlags(0x2000)

    self.socket:set_timeout(5000)
    self.socket:sendto( self.host, self.port, tostring(sr) )

    local result = {}
    repeat
      local r = Reply.Service.fromSocket(self.socket)
      if ( r ) then
        table.insert(result, r:getUrl())
      end
      self.xid = self.xid + 1
    until(not(r))

    if ( #result == 0 ) then
      return false, "ERROR: Helper.Locate no response received"
    end
    return true, result
  end,

  --- Requests an attribute from the server
  -- @param url as retrieved by the Service request
  -- @param scope string containing the request scope
  -- @param taglist string containing the request tag list
  AttributeRequest = function(self, url, scope, taglist)
    local url = url or ""
    local scope = scope or ""
    local taglist = taglist or ""
    local ar = Request.Attribute:new()
    ar:setXID(self.xid)
    ar:setScope(scope)
    ar:setUrl(url)
    ar:setTagList(taglist)
    ar:setFunction(PacketFunction.ATTRIB_REQUEST)
    ar:setFlags(0x2000)

    self.socket:set_timeout(5000)
    self.socket:sendto( self.host, self.port, tostring(ar) )

    local r = Reply.Attribute.fromSocket(self.socket)

    self.xid = self.xid + 1
    if ( not(r) ) then
      return false, "ERROR: Helper.Locate no response received"
    end
    return true, r:getAttribList()
  end,

  close = function(self)
    return self.socket:close()
  end,
}

return _ENV;
