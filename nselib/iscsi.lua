--- An iSCSI library implementing written by Patrik Karlsson <patrik@cqure.net>
-- The library currently supports target discovery and login.
--
-- The implementation is based on packetdumps and the iSCSI RFC
-- * http://tools.ietf.org/html/rfc3720
--
-- The library contains the protocol message pairs in <code>Packet</code>
-- E.g. <code>LoginRequest</code> and <code>LoginResponse</code>
--
-- Each request can be "serialized" to a string using:
-- <code>tostring(request)</code>.
-- All responses can be read and instantiated from the socket by calling:
-- <code>local status,resp = Response.fromSocket(sock)</code>
--
-- In addition the library has the following classes:
-- * <code>Packet</code>
-- ** A class containing the request and response packets
-- * <code>Comm</code>
-- ** A class used to send and receive packet between the library and server
-- ** The class handles some of the packet "counting" and value updating
-- * <code>KVP</code>
-- ** A key/value pair class that holds key value pairs
-- * <code>Helper</code>
-- ** A class that wraps the <code>Comm</code> and <code>Packet</code> classes
-- ** The purpose of the class is to provide easy access to common iSCSI task
--
--
-- @author Patrik Karlsson <patrik@cqure.net>
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html

-- Version 0.2
-- Created 2010/11/18 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 2010/11/28 - v0.2 - improved error handling, fixed discovery issues
--                             with multiple addresses <patrik@cqure.net>


local bin = require "bin"
local bit = require "bit"
local ipOps = require "ipOps"
local match = require "match"
local nmap = require "nmap"
local stdnse = require "stdnse"
local openssl = stdnse.silent_require "openssl"
local string = require "string"
local table = require "table"
_ENV = stdnse.module("iscsi", stdnse.seeall)


Packet = {

  Opcode = {
    LOGIN = 0x03,
    TEXT = 0x04,
    LOGOUT = 0x06,
  },

  LoginRequest = {

    CSG = {
      SecurityNegotiation = 0,
      LoginOperationalNegotiation = 1,
      FullFeaturePhase = 3,
    },

    NSG = {
      SecurityNegotiation = 0,
      LoginOperationalNegotiation = 1,
      FullFeaturePhase = 3,
    },

    --- Creates a new instance of LoginRequest
    --
    -- @return instance of LoginRequest
    new = function( self )
      local o = {}
      setmetatable(o, self)
      self.__index = self
      o.immediate = 0
      o.opcode = Packet.Opcode.LOGIN
      o.flags = {}
      o.ver_max = 0
      o.ver_min = 0
      o.total_ahs_len = 0
      o.data_seg_len = 0
      o.isid = { t=0x01, a=0x00, b=0x0001, c=0x37, d=0 }
      o.tsih = 0
      o.initiator_task_tag = 1
      o.cid = 1
      o.cmdsn = 0
      o.expstatsn = 1
      o.kvp = KVP:new()
      return o
    end,

    setImmediate = function(self, b) self.immediate = ( b and 1 or 0 ) end,

    --- Sets the transit bit
    --
    -- @param b boolean containing the new transit value
    setTransit = function(self, b) self.flags.transit = ( b and 1 or 0 ) end,

    --- Sets the continue bit
    --
    -- @param b boolean containing the new continue value
    setContinue = function(self, b) self.flags.continue = ( b and 1 or 0 ) end,

    --- Sets the CSG values
    --
    -- @param csg number containing the new NSG value
    setCSG = function(self, csg) self.flags.csg = csg end,

    --- Sets the NSG values
    --
    -- @param nsg number containing the new NSG value
    setNSG = function(self, nsg) self.flags.nsg = nsg end,

    --- Converts the class instance to string
    --
    -- @return string containing the converted instance
    __tostring = function( self )
      local reserved = 0
      local kvps = tostring(self.kvp)

      self.data_seg_len = #kvps

      local pad = 4 - ((#kvps + 48) % 4)
      pad = ( pad == 4 ) and 0 or pad

      local len = bit.lshift( self.total_ahs_len, 24 ) + self.data_seg_len
      local flags = bit.lshift( ( self.flags.transit or 0 ), 7 )
      flags = flags + bit.lshift( ( self.flags.continue or 0 ), 6)
      flags = flags + ( self.flags.nsg or 0 )
      flags = flags + bit.lshift( ( self.flags.csg or 0 ), 2 )

      local opcode = self.opcode + bit.lshift((self.immediate or 0), 6)

      local data = bin.pack(">CCCCICSCSSISSIILLAA", opcode,
      flags, self.ver_max, self.ver_min, len,
      bit.lshift( self.isid.t, 6 ) + bit.band( self.isid.a, 0x3f),
      self.isid.b, self.isid.c, self.isid.d, self.tsih,
      self.initiator_task_tag, self.cid, reserved, self.cmdsn,
      self.expstatsn, reserved, reserved, kvps, string.rep('\0', pad) )

      return data
    end

  },

  LoginResponse = {

    -- Error messages
    ErrorMsgs = {
      [0x0000] = "Success",
      [0x0101] = "Target moved temporarily",
      [0x0102] = "Target moved permanently",
      [0x0200] = "Initiator error",
      [0x0201] = "Authentication failure",
      [0x0202] = "Authorization failure",
      [0x0203] = "Target not found",
      [0x0204] = "Target removed",
      [0x0205] = "Unsupported version",
      [0x0206] = "Too many connections",
      [0x0207] = "Missing parameter",
      [0x0208] = "Can't include in session",
      [0x0209] = "Session type not supported",
      [0x020a] = "Session does not exist",
      [0x020b] = "Invalid request during login",
      [0x0300] = "Target error",
      [0x0301] = "Service unavailable",
      [0x0302] = "Out of resources",
    },

    -- Error constants
    Errors = {
      SUCCESS = 0,
      AUTH_FAILED = 0x0201,
    },

    --- Creates a new instance of LoginResponse
    --
    -- @return instance of LoginResponse
    new = function( self )
      local o = {}
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    --- Returns the error message
    getErrorMessage = function( self )
      return Packet.LoginResponse.ErrorMsgs[self.status_code] or "Unknown error"
    end,

    --- Returns the error code
    getErrorCode = function( self ) return self.status_code or 0 end,

    --- Creates a LoginResponse with data read from the socket
    --
    -- @return status true on success, false on failure
    -- @return resp instance of LoginResponse
    fromSocket = function( s )
      local status, header = s:receive_buf(match.numbytes(48), true)

      if ( not(status) ) then
        return false, "Failed to read header from socket"
      end

      local resp = Packet.LoginResponse:new()
      local pos, len = bin.unpack(">I", header, 5)

      resp.total_ahs_len = bit.rshift(len, 24)
      resp.data_seg_len = bit.band(len, 0x00ffffff)
      pos, resp.status_code = bin.unpack(">S", header, 37)

      local pad = ( 4 - ( resp.data_seg_len % 4 ) )
      pad = ( pad == 4 ) and 0 or pad

      local status, data = s:receive_buf(match.numbytes(resp.data_seg_len + pad), true)
      if ( not(status) ) then
        return false, "Failed to read data from socket"
      end

      resp.kvp = KVP:new()
      for _, kvp in ipairs(stdnse.strsplit( "\0", data )) do
        local k, v = kvp:match("(.*)=(.*)")
        if ( v ) then resp.kvp:add( k, v ) end
      end

      return true, resp
    end,

  },

  TextRequest = {

    --- Creates a new instance of TextRequest
    --
    -- @return instance of TextRequest
    new = function( self )
      local o = {}
      setmetatable(o, self)
      self.__index = self
      o.opcode = Packet.Opcode.TEXT
      o.flags = {}
      o.flags.final = 0
      o.flags.continue = 0
      o.total_ahs_len = 0
      o.data_seg_len = 0
      o.lun = 0
      o.initiator_task_tag = 1
      o.target_trans_tag = 0xffffffff
      o.cmdsn = 2
      o.expstatsn = 1
      o.kvp = KVP:new()
      return o
    end,

    --- Sets the final bit of the TextRequest
    setFinal = function( self, b ) self.flags.final = ( b and 1 or 0 ) end,

    --- Sets the continue bit of the TextRequest
    setContinue = function( self, b ) self.flags.continue = ( b and 1 or 0 ) end,

    --- Converts the class instance to string
    --
    -- @return string containing the converted instance
    __tostring = function(self)
      local flags = bit.lshift( ( self.flags.final or 0 ), 7 )
      flags = flags + bit.lshift( (self.flags.continue or 0), 6 )

      local kvps = tostring(self.kvp)
      kvps = kvps .. string.rep('\0', #kvps % 2)
      self.data_seg_len = #kvps

      local len = bit.lshift( self.total_ahs_len, 24 ) + self.data_seg_len
      local reserved = 0
      local data = bin.pack(">CCSILIIIILLA", self.opcode, flags, reserved,
      len, self.lun, self.initiator_task_tag, self.target_trans_tag,
      self.cmdsn, self.expstatsn, reserved, reserved, kvps)

      return data
    end,

  },

  TextResponse = {

    --- Creates a new instance of TextResponse
    --
    -- @return instance of TextResponse
    new = function( self )
      local o = {}
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    --- Creates a TextResponse with data read from the socket
    --
    -- @return status true on success, false on failure
    -- @return instance of TextResponse
    --         err string containing error message
    fromSocket = function( s )
      local resp = Packet.TextResponse:new()
      local textdata = ""

      repeat
        local status, header = s:receive_buf(match.numbytes(48), true)
        if not status then return status, header end
        local pos, _, flags, _, _, len = bin.unpack(">CCCCI", header)
        local cont = ( bit.band(flags, 0x40) == 0x40 )

        resp.total_ahs_len = bit.rshift(len, 24)
        resp.data_seg_len = bit.band(len, 0x00ffffff)

        local data
        status, data = s:receive_buf(match.numbytes(resp.data_seg_len), true)

        textdata = textdata .. data

      until( not(cont) )

      resp.records = {}

      local kvps = stdnse.strsplit( "\0", textdata )
      local record

      -- Each target record starts with one text key of the form:
      --   TargetName=<target-name-goes-here>
      -- Followed by zero or more address keys of the form:
      --  TargetAddress=<hostname-or-ipaddress>[:<tcp-port>],
      --  <portal-group-tag>
      for _, kvp in ipairs(kvps) do
        local k, v = kvp:match("(.*)%=(.*)")
        if ( k == "TargetName" ) then
          if ( record ) then
            table.insert(resp.records, record)
            record = {}
          end
          if ( #resp.records == 0 ) then record = {} end
          record.name = v
        elseif ( k == "TargetAddress" ) then
          record.addr = record.addr or {}
          table.insert( record.addr, v )
        elseif ( not(k) ) then
          -- this should be the ending empty kvp
          table.insert(resp.records, record)
          break
        else
          stdnse.debug1("ERROR: iscsi.TextResponse: Unknown target record (%s)", k)
        end
      end

      return true, resp
    end,
  },

  --- Class handling a login request
  LogoutRequest = {

    --- Creates a new instance of LogoutRequest
    --
    -- @return instance of LogoutRequest
    new = function( self )
      local o = {}
      setmetatable(o, self)
      self.__index = self
      o.opcode = Packet.Opcode.LOGOUT
      o.immediate = 1
      o.reasoncode = 0
      o.total_ahs_len = 0
      o.data_seg_len = 0
      o.initiator_task_tag = 2
      o.cid = 1
      o.cmdsn = 0
      o.expstatsn = 1
      return o
    end,

    --- Converts the class instance to string
    --
    -- @return string containing the converted instance
    __tostring = function(self)
      local opcode = self.opcode + bit.lshift((self.immediate or 0), 6)
      local reserved = 0
      local len = bit.lshift( self.total_ahs_len, 24 ) + self.data_seg_len
      local data = bin.pack(">CCSILISSIILL", opcode, (0x80 + self.reasoncode),
      reserved, len, reserved,self.initiator_task_tag, self.cid,
      reserved, self.cmdsn, self.expstatsn, reserved, reserved )

      return data
    end,
  },


  --- Class handling the Logout response
  LogoutResponse = {

    --- Creates a new instance of LogoutResponse
    --
    -- @return instance of LogoutResponse
    new = function( self )
      local o = {}
      setmetatable(o, self)
      self.__index = self
      return o
    end,

    --- Creates a LogoutResponse with data read from the socket
    --
    -- @return status true on success, false on failure
    -- @return instance of LogoutResponse
    --         err string containing error message
    fromSocket = function( s )
      local resp = Packet.LogoutResponse:new()
      local status, header = s:receive_buf(match.numbytes(48), true)
      if ( not(status) ) then return status, header end
      return true, resp
    end

  }
}

--- The communication class handles socket reads and writes
--
-- In addition it keeps track of both immediate packets and the amount of read
-- packets and updates cmdsn and expstatsn accordingly.
Comm = {

  --- Creates a new instance of Comm
  --
  -- @return instance of Comm
  new = function(self, socket)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.expstatsn = 0
    o.cmdsn = 1
    o.socket = socket
    return o
  end,

  --- Sends a packet and retrieves the response
  --
  -- @param out_packet instance of a packet to send
  -- @param in_class class of the packet to read
  -- @return status true on success, false on failure
  -- @return r decoded instance of in_class
  exchange = function( self, out_packet, in_class )

    local expstatsn = ( self.expstatsn == 0 ) and 1 or self.expstatsn

    if ( out_packet.immediate and out_packet.immediate == 1 ) then
      self.cmdsn = self.cmdsn + 1
    end

    out_packet.expstatsn = expstatsn
    out_packet.cmdsn = self.cmdsn

    self.socket:send( tostring( out_packet ) )

    local status, r = in_class.fromSocket( self.socket )
    self.expstatsn = self.expstatsn + 1

    return status, r
  end,


}

--- Key/Value pairs class
KVP = {

  --- Creates a new instance of KVP
  --
  -- @return instance of KVP
  new = function( self )
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.kvp = {}
    return o
  end,

  --- Adds a key/value pair
  --
  -- @param key string containing the key name
  -- @param value string containing the value
  add = function( self, key, value )
    table.insert( self.kvp, {[key]=value} )
  end,

  --- Gets all values for a specific key
  --
  -- @param key string containing the name of the key to retrieve
  -- @return values table containing all values for the specified key
  get = function( self, key )
    local values = {}
    for _, kvp in ipairs(self.kvp) do
      for k, v in pairs( kvp ) do
        if ( key == k ) then
          table.insert( values, v )
        end
      end
    end
    return values
  end,

  --- Returns all key value pairs as string delimited by \0
  -- eg. "key1=val1\0key2=val2\0"
  --
  -- @return string containing all key/value pairs
  __tostring = function( self )
    local ret = ""
    for _, kvp in ipairs(self.kvp) do
      for k, v in pairs( kvp ) do
        ret = ret .. ("%s=%s\0"):format(k,v)
      end
    end
    return ret
  end,

}

--- CHAP authentication class
CHAP = {

  --- Calculate a CHAP - response
  --
  -- @param identifier number containing the CHAP identifier
  -- @param challenge string containing the challenge
  -- @param secret string containing the users password
  -- @return response string containing the CHAP response
  calcResponse = function( identifier, challenge, secret )
    return openssl.md5( identifier .. secret .. challenge )
  end,

}

--- The helper class contains functions with more descriptive names
Helper = {

  --- Creates a new instance of the Helper class
  --
  -- @param host table as received by the script action function
  -- @param port table as received by the script action function
  -- @return o instance of Helper
  new = function( self, host, port )
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.host, o.port = host, port
    o.socket = nmap.new_socket()
    return o
  end,

  --- Connects to the iSCSI target
  --
  -- @return status true on success, false on failure
  -- @return err string containing error message is status is false
  connect = function( self )
    self.socket:set_timeout(10000)
    local status, err = self.socket:connect(self.host, self.port, "tcp")
    if ( not(status) ) then return false, err end

    self.comm = Comm:new( self.socket )
    return true
  end,

  --- Attempts to discover accessible iSCSI targets on the remote server
  --
  -- @return status true on success, false on failure
  -- @return targets table containing discovered targets
  --         each table entry is a target table with <code>name</code>
  --         and <code>addr</code>.
  --         err string containing an error message is status is false
  discoverTargets = function( self )
    local p = Packet.LoginRequest:new()

    p:setTransit(true)
    p:setNSG(Packet.LoginRequest.NSG.LoginOperationalNegotiation)
    p.kvp:add( "InitiatorName", "iqn.1991-05.com.microsoft:nmap_iscsi_probe" )
    p.kvp:add( "SessionType", "Discovery" )
    p.kvp:add( "AuthMethod", "None" )

    local status, resp = self.comm:exchange( p, Packet.LoginResponse )
    if ( not(status) ) then
      return false, ("ERROR: iscsi.Helper.discoverTargets: %s"):format(resp)
    end

    local auth_method = resp.kvp:get("AuthMethod")[1]
    if ( auth_method:upper() ~= "NONE" ) then
      return false, "ERROR: iscsi.Helper.discoverTargets: Unsupported authentication method"
    end

    p = Packet.LoginRequest:new()
    p:setTransit(true)
    p:setNSG(Packet.LoginRequest.NSG.FullFeaturePhase)
    p:setCSG(Packet.LoginRequest.CSG.LoginOperationalNegotiation)
    p.kvp:add( "HeaderDigest", "None")
    p.kvp:add( "DataDigest", "None")
    p.kvp:add( "MaxRecvDataSegmentLength", "65536")
    p.kvp:add( "DefaultTime2Wait", "0")
    p.kvp:add( "DefaultTime2Retain", "60")

    status, resp = self.comm:exchange( p, Packet.LoginResponse )

    p = Packet.TextRequest:new()
    p:setFinal(true)
    p.kvp:add( "SendTargets", "All" )
    status, resp = self.comm:exchange( p, Packet.TextResponse )

    if ( not(resp.records) ) then
      return false, "iscsi.discoverTargets: response returned no targets"
    end

    for _, record in ipairs(resp.records) do
      table.sort( record.addr, function(a, b) local c = ipOps.compare_ip(a:match("(.-):"), "le", b:match("(.-):")); return c end )
    end
    return true, resp.records
  end,

  --- Logs out from the iSCSI target
  --
  -- @return status true on success, false on failure
  logout = function(self)
    local p = Packet.LogoutRequest:new()
    local status, resp = self.comm:exchange( p, Packet.LogoutResponse )
    return status
  end,

  --- Authenticate to the iSCSI service
  --
  -- @param target_name string containing the name of the iSCSI target
  -- @param username string containing the username
  -- @param password string containing the password
  -- @param auth_method string containing either "None" or "Chap"
  -- @return status true on success false on failure
  -- @return response containing the loginresponse or
  --         err string containing an error message if status is false
  login = function( self, target_name, username, password, auth_method )

    local auth_method = auth_method or "None"

    if ( not(target_name) ) then
      return false, "No target name specified"
    end

    if ( auth_method:upper()~= "NONE" and
      auth_method:upper()~= "CHAP" ) then
      return false, "Unknown authentication method"
    end

    local p = Packet.LoginRequest:new()

    p:setTransit(true)
    p:setNSG(Packet.LoginRequest.NSG.LoginOperationalNegotiation)
    p.kvp:add( "InitiatorName", "iqn.1991-05.com.microsoft:nmap_iscsi_probe" )
    p.kvp:add( "SessionType", "Normal" )
    p.kvp:add( "TargetName", target_name )
    p.kvp:add( "AuthMethod", auth_method )

    if ( not(self.comm) ) then
      return false, "ERROR: iscsi.Helper.login: Not connected"
    end
    local status, resp = self.comm:exchange( p, Packet.LoginResponse )
    if ( not(status) ) then
      return false, ("ERROR: iscsi.Helper.login: %s"):format(resp)
    end

    if ( resp.status_code ~= 0 ) then
      stdnse.debug3("ERROR: iscsi.Helper.login: Authentication failed (error code: %d)", resp.status_code)
      return false, resp
    elseif ( auth_method:upper()=="NONE" ) then
      return true, resp
    end

    p = Packet.LoginRequest:new()
    p.kvp:add( "CHAP_A", "5" )
    status, resp = self.comm:exchange( p, Packet.LoginResponse )
    if ( not(status) ) then
      return false, ("ERROR: iscsi.Helper.login: %s"):format(resp)
    end

    local alg = resp.kvp:get("CHAP_A")[1]
    if ( alg ~= "5" ) then return false, "Unsupported authentication algorithm" end

    local chall = resp.kvp:get("CHAP_C")[1]
    if ( not(chall) ) then return false, "Failed to decode challenge" end
    chall = bin.pack("H", chall:sub(3))

    local ident = resp.kvp:get("CHAP_I")[1]
    if (not(ident)) then return false, "Failed to decoded identifier" end
    ident = string.char(tonumber(ident))

    local resp = CHAP.calcResponse( ident, chall, password )
    resp = "0x" .. select(2, bin.unpack("H16", resp))

    p = Packet.LoginRequest:new()
    p:setImmediate(true)
    p:setTransit(true)
    p:setNSG(Packet.LoginRequest.NSG.LoginOperationalNegotiation)
    p.kvp:add("CHAP_N", username)
    p.kvp:add("CHAP_R", resp)

    status, resp = self.comm:exchange( p, Packet.LoginResponse )
    if ( not(status) ) then
      return false, ("ERROR: iscsi.Helper.login: %s"):format(resp)
    end

    if ( resp:getErrorCode() ~= Packet.LoginResponse.Errors.SUCCESS ) then
      return false, "Login failed"
    end

    return true, resp
  end,

  --- Disconnects the socket from the server
  close = function(self) self.socket:close() end

}





return _ENV;
