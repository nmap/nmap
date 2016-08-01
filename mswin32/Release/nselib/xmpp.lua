--- A XMPP (Jabber) library, implementing a minimal subset of the protocol
-- enough to do authentication brute-force.
--
-- The XML parsing of tags isn't optimal but there's no other easy way
-- (nulls or line-feeds) to match the end of a message. The parse_tag
-- method in the XML class was borrowed from the initial xmpp.nse
-- script written by Vasiliy Kulikov.
--
-- The library consist of the following classes:
-- * <code>XML</code> - containing a minimal XML parser written by
--                     Vasiliy Kulikov.
-- * <code>TagProcessor</code> - Contains processing code for common tags
-- * <code>XMPP</code> - containing the low-level functions used to
--                       communicate with the Jabber server.
-- * <code>Helper</code> - containing the main interface for script
--                         writers
--
-- The following sample illustrates how to use the library to authenticate
-- to a XMPP sever:
-- <code>
-- local helper = xmpp.Helper:new(host, port, options)
-- local status, err = helper:connect()
-- status, err = helper:login(user, pass, "DIGEST-MD5")
-- </code>
--
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
-- @author Patrik Karlsson <patrik@cqure.net>

-- Version 0.2
-- Created 07/19/2011 - v0.1 - Created by Patrik Karlsson
-- Revised 07/22/2011 - v0.2 - Added TagProcessors and two new auth mechs:
--                             CRAM-MD5 and LOGIN <patrik@cqure.net>

local base64 = require "base64"
local nmap = require "nmap"
local sasl = require "sasl"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
_ENV = stdnse.module("xmpp", stdnse.seeall)


-- This is a trivial XML processor written by Vasiliy Kulikov.  It doesn't
-- fully support XML, but it should be sufficient for the basic XMPP
-- stream handshake.  If you see stanzas with uncommon symbols, feel
-- free to enhance these regexps.
XML = {

  ---XML tag table
  --@class table
  --@name XML.tag
  --@field name The tag name
  --@field attrs The tag attributes as a key-value table
  --@field start True if this was an opening tag.
  --@field contents The contents of the tag
  --@field finish true if the tag was closed.

  ---Parse an XML tag
  --@name XML.parse_tag
  --@param s String containing the XML tag
  --@return XML tag table
  --@see XML.tag
  parse_tag = function(s)
    local _, _, contents, empty, name = string.find(s, "([^<]*)<(/?)([?:%w-]+)")
    local attrs = {}
    if not name then
      return
    end
    for k, v in string.gmatch(s, "%s([%w:]+)='([^']+)'") do
      attrs[k] = v
    end
    for k, v in string.gmatch(s, "%s([%w:]+)=\"([^\"]+)\"") do
      attrs[k] = v
    end

    local finish = (empty ~= "") or (s:sub(#s-1) == '/>')

    return { name = name,
    attrs = attrs,
    start = (empty == ""),
    contents = contents,
    finish = finish }
  end,

}

TagProcessor = {

  ["failure"] = function(socket, tag)
    return TagProcessor["success"](socket,tag)
  end,

  ["success"] = function(socket, tag)
    if ( tag.finish ) then return true end
    local newtag
    repeat
      local status, data = socket:receive_buf(">", true)
      if ( not(status) ) then
        return false, ("ERROR: Failed to process %s tag"):format(tag.name)
      end
      newtag = XML.parse_tag(data)
    until( newtag.finish and newtag.name == tag.name )
    if ( newtag.name == tag.name ) then return true, tag end
    return false, ("ERROR: Failed to process %s tag"):format(tag.name)
  end,

  ["challenge"] = function(socket, tag)
    local status, data = socket:receive_buf(">", true)
    if ( not(status) ) then return false, "ERROR: Failed to read challenge tag" end
    local tag = XML.parse_tag(data)

    if ( not(status) or tag.name ~= "challenge" ) then
      return false, "ERROR: Failed to process challenge"
    end
    return status, (tag.contents and base64.dec(tag.contents))
  end,


}

XMPP = {

  --- Creates a new instance of the XMPP class
  --
  -- @name XMPP.new
  -- @param host table as received by the action function
  -- @param port table as received by the action function
  -- @param options table containing options, currently supported
  -- * <code>timeout</code> - sets the socket timeout
  -- * <code>servername</code> - sets the server name to use in
  --                            communication with the server.
  -- * <code>starttls</code> - start TLS handshake even if it is optional.
  new = function(self, host, port, options)
    local o = { host = host,
    port = port,
    options = options or {},
    auth = { mechs = {} } }
    o.options.timeout = o.options.timeout and o.options.timeout or 10
    o.servername = stdnse.get_hostname(host) or o.options.servername
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  --- Sends data to XMPP server
  -- @name XMPP.send
  -- @param data string containing data to send to server
  -- @return status true on success false on failure
  -- @return err string containing error message
  send = function(self, data)

    -- this ain't pretty, but we try to "flush" what's left of the receive
    -- buffer, prior to send. This way we account for not reading to the
    -- end of one message resulting in the next read reading from our
    -- previous message.
    self.socket:set_timeout(1)
    repeat
      local status = self.socket:receive_buf("\0", false)
    until(not(status))
    self.socket:set_timeout(self.options.timeout * 1000)

    return self.socket:send(data)
  end,

  --- Receives a XML tag from the server
  --
  -- @name XMPP.receive_tag
  -- @param tag [optional] if unset, receives the next available tag
  --            if set, reads until the given tag has been found
  -- @param close [optional] if set, matches a closing tag
  -- @return true on success, false on error
  -- @return The XML tag table, or error message
  -- @see XML.tag
  receive_tag = function(self, tag, close)
    local result
    repeat
      local status, data = self.socket:receive_buf(">", true)
      if ( not(status) ) then return false, data end
      result = XML.parse_tag(data)
    until( ( not(tag) and (close == nil or result.finish == close ) ) or
      ( tag == result.name and ( close == nil or result.finish == close ) ) )
    return true, result
  end,

  --- Connects to the XMPP server
  -- @name XMPP.connect
  -- @return status true on success, false on failure
  -- @return err string containing an error message if status is false
  connect = function(self)
    assert(self.servername,
    "Cannot connect to XMPP server without valid server name")

    -- we may be reconnecting using SSL
    if ( not(self.socket) ) then
      self.socket = nmap.new_socket()
      self.socket:set_timeout(self.options.timeout * 1000)
      local status, err = self.socket:connect(self.host, self.port)
      if ( not(status) ) then
        return false, err
      end
    end
    local data = ("<?xml version='1.0' ?><stream:stream to='%s' xmlns='jabber:client'" ..
    " xmlns:stream='http://etherx.jabber.org/streams'" ..
    " version='1.0'>"):format(self.servername)

    local status, err = self:send(data)
    if ( not(status) ) then return false, "ERROR: Failed to connect to server" end

    local version, start_tls
    repeat
      local status, tag = self:receive_tag()
      if ( not(status) ) then return false, "ERROR: Failed to connect to server" end

      if ( tag.name == "stream:stream" ) then
        version = tag.attrs and tag.attrs.version
      elseif ( tag.name == "starttls" and tag.start ) then
        status, tag = self:receive_tag()
        if ( not(status) ) then
          return false, "ERROR: Failed to connect to server"
        end
        if ( tag.name ~= "starttls" ) then
          start_tls = tag.name
        else
          start_tls = "optional"
        end
      elseif ( tag.name == "mechanism" and tag.finish ) then
        self.auth.mechs[tag.contents] = true
      end
    until(tag.name == "stream:features" and tag.finish)

    if ( version ~= "1.0" ) then
      return false, "ERROR: Only version 1.0 is supported"
    end

    if ( start_tls == "required" or self.options.starttls) then
      status, err = self:send("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
      if ( not(status) ) then return false, "ERROR: Failed to initiate STARTTLS" end
      local status, tag = self:receive_tag()
      if ( not(status) ) then return false, "ERROR: Failed to receive from server" end
      if ( tag.name == "proceed" ) then
        status, err = self.socket:reconnect_ssl()
        self.options.starttls = false
        return self:connect()
      end
    end

    return true
  end,

  --- Logs in to the XMPP server
  --
  -- @name XMPP.login
  -- @param username string
  -- @param password string
  -- @param mech string containing a supported authentication mechanism
  -- @return status true on success, false on failure
  -- @return err string containing error message if status is false
  login = function(self, username, password, mech)
    assert(mech == "PLAIN" or
    mech == "DIGEST-MD5" or
    mech == "CRAM-MD5" or
    mech == "LOGIN",
    "Unsupported authentication mechanism")

    local auth = ("<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' " ..
    "mechanism='%s'/>"):format(mech)

    -- we currently don't do anything with the realm
    local realm

    -- we need to cut the @domain.tld from the username
    if ( username:match("@") ) then
      username, realm = username:match("^(.*)@(.*)$")
    end

    local status, result

    if ( mech == "PLAIN" ) then
      local mech_params = { username, password }
      local auth_data = sasl.Helper:new(mech):encode(table.unpack(mech_params))
      auth = ("<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' " ..
      "mechanism='%s'>%s</auth>"):format(mech, base64.enc(auth_data))

      status, result = self.socket:send(auth)
      if ( not(status) ) then return false, "ERROR: Failed to send SASL PLAIN authentication" end

      status, result = self:receive_tag()
      if ( not(status) ) then return false, "ERROR: Failed to receive login response" end

      if ( result.name == "failure" ) then
        status = TagProcessor[result.name](self.socket, result)
      end
    else
      local status, err = self.socket:send(auth)
      if(not(status)) then return false, "ERROR: Failed to initiate SASL login" end

      local chall
      status, result = self:receive_tag()
      if ( not(status) ) then return false, "ERROR: Failed to retrieve challenge" end
      status, chall = TagProcessor[result.name](self.socket, result)

      if ( mech == "LOGIN" ) then
        if ( chall ~= "User Name" ) then
          return false, ("ERROR: Login expected 'User Name' received: %s"):format(chall)
        end
        self.socket:send("<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>" ..
        base64.enc(username) ..
        "</response>")

        status, result = self:receive_tag()
        if ( not(status) or result.name ~= "challenge") then
          return false, "ERROR: Receiving tag from server"
        end
        status, chall = TagProcessor[result.name](self.socket, result)

        if ( chall ~= "Password" ) then
          return false, ("ERROR: Login expected 'Password' received: %s"):format(chall)
        end

        self.socket:send("<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>" ..
        base64.enc(password) ..
        "</response>")

        status, result = self:receive_tag()
        if ( not(status) ) then return false, "ERROR: Failed to receive login challenge" end
        if ( result.name == "failure" ) then
          status = TagProcessor[result.name](self.socket, result)
          return false, "Login failed"
        end
      else
        local mech_params = { username, password, chall, "xmpp", "xmpp/" .. self.servername  }
        local auth_data = sasl.Helper:new(mech):encode(table.unpack(mech_params))
        auth_data = "<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>" ..
        base64.enc(auth_data) .. "</response>"

        status, err = self.socket:send(auth_data)

        -- read to the end tag regardless of what it is
        -- it should be one of either: success, challenge or error
        repeat
          status, result = self:receive_tag()
          if ( not(status) ) then return false, "ERROR: Failed to receive login challenge" end

          if ( result.name == "failure" ) then
            status = TagProcessor[result.name](self.socket, result)
            return false, "Login failed"
          elseif ( result.name == "success" ) then
            status = TagProcessor[result.name](self.socket, result)
            if ( not(status) ) then return false, "Failed to process success message" end
            return true, "Login success"
          elseif ( result.name ~= "challenge" ) then
            return false, "ERROR: Failed to receive login challenge"
          end
        until( result.name == "challenge" and result.finish )

        if ( result.name == "challenge" and mech == "DIGEST-MD5" ) then
          status, result = self.socket:send("<response xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>")
          if ( not(status) ) then return false, "ERROR: Failed to send DIGEST-MD5 request" end
          status, result = self:receive_tag()
          if ( not(status) ) then return false, "ERROR: Failed to receive DIGEST-MD5 response" end
        end
      end
    end
    if ( result.name == "success" ) then
      return true, "Login success"
    end

    return false, "Login failed"
  end,

  --- Retrieves the available authentication mechanisms
  -- @name XMPP.getAuthMechs
  -- @return table containing all available authentication mechanisms
  getAuthMechs = function(self) return self.auth.mechs end,

  --- Disconnects the socket from the server
  -- @name XMPP.disconnect
  -- @return status true on success, false on failure
  -- @return error message if status is false
  disconnect = function(self)
    local status, err = self.socket:close()
    self.socket = nil
    return status, err
  end,

}


Helper = {

  --- Creates a new Helper instance
  -- @name Helper.new
  -- @param host table as received by the action function
  -- @param port table as received by the action function
  -- @param options table containing options, currently supported
  -- * <code>timeout</code> - sets the socket timeout
  -- * <code>servername</code> - sets the server name to use in
  --                            communication with the server.
  new = function(self, host, port, options)
    local o = { host = host,
    port = port,
    options = options or {},
    xmpp = XMPP:new(host, port, options),
    state = "" }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  --- Connects to the XMPP server and starts the initial communication
  -- @name Helper.connect
  -- @return status true on success, false on failure
  -- @return err string containing an error message is status is false
  connect = function(self)
    if ( not(self.host.targetname) and
      not(self.options.servername) ) then
      return false, "ERROR: Cannot connect to XMPP server without valid server name"
    end
    self.state = "CONNECTED"
    return self.xmpp:connect()
  end,

  --- Login to the XMPP server
  --
  -- @name Helper.login
  -- @param username string
  -- @param password string
  -- @param mech string containing a supported authentication mechanism
  -- @see Helper.getAuthMechs
  -- @return status true on success, false on failure
  -- @return err string containing error message if status is false
  login = function(self, username, password, mech)
    return self.xmpp:login(username, password, mech)
  end,

  --- Retrieves the available authentication mechanisms
  -- @name Helper.getAuthMechs
  -- @return table containing all available authentication mechanisms
  getAuthMechs = function(self)
    if ( self.state == "CONNECTED" ) then
      return self.xmpp:getAuthMechs()
    end
    return
  end,

  --- Closes the connection to the server
  -- @name Helper.close
  close = function(self)
    self.xmpp:disconnect()
    self.state = "DISCONNECTED"
  end,

}

return _ENV;
