---
-- SNMP library.
--
-- @author Patrik Karlsson <patrik@cqure.net>
-- @author Gioacchino Mazzurco <gmazzurco89@gmail.com>
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html

-- 2015-06-11 Gioacchino Mazzurco - Use creds library to handle SNMP community

local asn1 = require "asn1"
local bin = require "bin"
local creds = require "creds"
local math = require "math"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
_ENV = stdnse.module("snmp", stdnse.seeall)


-- SNMP ASN.1 Encoders
local tagEncoder = {}

-- Override the boolean encoder
tagEncoder['boolean'] = function(self, val)
  return bin.pack('H', '05 00')
end

-- Complex tag encoders
tagEncoder['table'] = function(self, val)
  if val._snmp == '06' then -- OID
    local oidStr = string.char(val[1]*40 + val[2])
    for i = 3, #val do
      oidStr = oidStr .. self.encode_oid_component(val[i])
    end
    return bin.pack("HAA", '06', self.encodeLength(#oidStr), oidStr)

  elseif (val._snmp == '40') then -- ipAddress
    return bin.pack("HC4", '40 04', table.unpack(val))

    -- counter or gauge or timeticks or opaque
  elseif (val._snmp == '41' or val._snmp == '42' or val._snmp == '43' or val._snmp == '44') then
    local val = self:encodeInt(val[1])
    return bin.pack("HAA", val._snmp, self.encodeLength(#val), val)
  end

  local encVal = ""
  for _, v in ipairs(val) do
    encVal = encVal .. self:encode(v) -- todo: buffer?
  end

  local tableType = "\x30"
  if (val["_snmp"]) then
    tableType = bin.pack("H", val["_snmp"])
  end
  return bin.pack('AAA', tableType, self.encodeLength(#encVal), encVal)
end

---
-- Encodes a given value according to ASN.1 basic encoding rules for SNMP
-- packet creation.
-- @param val Value to be encoded.
-- @return Encoded value.
function encode(val)
  local vtype = type(val)
  local encoder = asn1.ASN1Encoder:new()
  encoder:registerTagEncoders( tagEncoder )


  local encVal = encoder:encode(val)

  if encVal then
    return encVal
  end

  return ''
end

-- SNMP ASN.1 Decoders
local tagDecoder = {}

-- Application specific tags
--
-- IP Address

-- Response-PDU
-- TOOD: Figure out how to remove these dependencies
tagDecoder["A2"] = function( self, encStr, elen, pos )
   local seq = {}

   pos, seq = self:decodeSeq(encStr, elen, pos)
   seq._snmp = "A2"
   return pos, seq
end

tagDecoder["40"] = function( self, encStr, elen, pos )
  local ip = {}
  pos, ip[1], ip[2], ip[3], ip[4] = bin.unpack("C4", encStr, pos)
  ip._snmp = '40'
  return pos, ip
end

---
-- Decodes an SNMP packet or a part of it according to ASN.1 basic encoding
-- rules.
-- @param encStr Encoded string.
-- @param pos Current position in the string.
-- @return The position after decoding
-- @return The decoded value(s).
function decode(encStr, pos)
  local decoder = asn1.ASN1Decoder:new()

  if ( #tagDecoder == 0 ) then
    decoder:registerBaseDecoders()
    -- Application specific tags
    -- tagDecoder["40"] = decoder.decoder["06"]  -- IP Address; same as OID
    tagDecoder["41"] = decoder.decoder["02"]  -- Counter; same as Integer
    tagDecoder["42"] = decoder.decoder["02"]  -- Gauge
    tagDecoder["43"] = decoder.decoder["02"]  -- TimeTicks
    tagDecoder["44"] = decoder.decoder["04"]  -- Opaque; same as Octet String
    tagDecoder["45"] = decoder.decoder["06"]  -- NsapAddress
    tagDecoder["46"] = decoder.decoder["02"]  -- Counter64
    tagDecoder["47"] = decoder.decoder["02"]  -- UInteger32

    -- Context specific tags
    tagDecoder["A0"] = decoder.decoder["30"]  -- GetRequest-PDU
    tagDecoder["A1"] = decoder.decoder["30"]  -- GetNextRequest-PDU
    --tagDecoder["A2"] = decoder.decoder["30"]  -- Response-PDU
    tagDecoder["A3"] = decoder.decoder["30"]  -- SetRequest-PDU
    tagDecoder["A4"] = decoder.decoder["30"]  -- Trap-PDU
    tagDecoder["A5"] = decoder.decoder["30"]  -- GetBulkRequest-PDU
    tagDecoder["A6"] = decoder.decoder["30"]  -- InformRequest-PDU (not implemented here yet)
    tagDecoder["A7"] = decoder.decoder["30"]  -- SNMPv2-Trap-PDU (not implemented here yet)
  end


  decoder:registerTagDecoders( tagDecoder )

  return decoder:decode( encStr, pos )
end

---
-- Create an SNMP packet.
-- @param PDU SNMP Protocol Data Unit to be encapsulated in the packet.
-- @param version SNMP version, default <code>0</code> (SNMP V1).
-- @param commStr community string.
function buildPacket(PDU, version, commStr)
  if (not version) then version = 0 end
  local packet = {}
  packet[1] = version
  packet[2] = commStr
  packet[3] = PDU
  return packet
end

--- SNMP options table
-- @class table
-- @name snmp.options
-- @field reqId Request ID.
-- @field err Error.
-- @field errIdx Error index.

---
-- Create an SNMP Get Request PDU.
-- @param options SNMP options table
-- @see snmp.options
-- @param ... Object identifiers to be queried.
-- @return Table representing PDU.
function buildGetRequest(options, ...)
  if not options then options = {} end

  if not options.reqId then options.reqId = math.fmod(nmap.clock_ms(), 65000) end
  if not options.err then options.err = 0 end
  if not options.errIdx then options.errIdx = 0 end

  local req = {}
  req._snmp = 'A0'
  req[1] = options.reqId
  req[2] = options.err
  req[3] = options.errIdx

  local payload = {}
  for i=1, select('#', ...) do
    payload[i] = {}
    payload[i][1] = select(i, ...)
    if type(payload[i][1]) == "string" then
      payload[i][1] = str2oid(payload[i][1])
    end
    payload[i][2] = false
  end
  req[4] = payload
  return req
end


---
-- Create an SNMP Get Next Request PDU.
-- @param options SNMP options table
-- @see snmp.options
-- @param ... Object identifiers to be queried.
-- @return Table representing PDU.
function buildGetNextRequest(options, ...)
  options = options or {}
  options.reqId = options.reqId or math.fmod(nmap.clock_ms(), 65000)
  options.err = options.err or 0
  options.errIdx = options.errIdx or 0

  local req = {}
  req._snmp = 'A1'
  req[1] = options.reqId
  req[2] = options.err
  req[3] = options.errIdx

  local payload = {}
  for i=1, select('#', ...) do
    payload[i] = {}
    payload[i][1] = select(i, ...)
    if type(payload[i][1]) == "string" then
      payload[i][1] = str2oid(payload[i][1])
    end
    payload[i][2] = false
  end
  req[4] = payload
  return req
end

---
-- Create an SNMP Set Request PDU.
--
-- Takes one OID/value pair or an already prepared table.
-- @param options SNMP options table
-- @see snmp.options
-- @param oid Object identifiers of object to be set.
-- @param value To which value object should be set. If given a table, use the
-- table instead of OID/value pair.
-- @return Table representing PDU.
function buildSetRequest(options, oid, value)
  if not options then options = {} end

  if not options.reqId then options.reqId = math.fmod(nmap.clock_ms(), 65000) end
  if not options.err then options.err = 0 end
  if not options.errIdx then options.errIdx = 0 end

  local req = {}
  req._snmp = 'A3'
  req[1] = options.reqId
  req[2] = options.err
  req[3] = options.errIdx

  if (type(value) == "table") then
    req[4] = value
  else
    local payload = {}
    if (type(oid) == "string") then
      payload[1] = str2oid(oid)
    else
      payload[1] = oid
    end
    payload[2] = value
    req[4] = {}
    req[4][1] = payload
  end
  return req
end

---
-- Create an SNMP Trap PDU.
-- @return Table representing PDU
function buildTrap(enterpriseOid, agentIp, genTrap, specTrap, timeStamp)
  local req = {}
  req._snmp = 'A4'
  if (type(enterpriseOid) == "string") then
    req[1] = str2oid(enterpriseOid)
  else
    req[1] = enterpriseOid
  end
  req[2] = {}
  req[2]._snmp = '40'
  for n in string.gmatch(agentIp, "%d+") do
    table.insert(req[2], tonumber(n))
  end
  req[3] = genTrap
  req[4] = specTrap

  req[5] = {}
  req[5]._snmp = '43'
  req[5][1] = timeStamp

  req[6] = {}

  return req
end

---
-- Create an SNMP Get Response PDU.
--
-- Takes one OID/value pair or an already prepared table.
-- @param options SNMP options table
-- @see snmp.options
-- @param oid Object identifiers of object to be sent back.
-- @param value If given a table, use the table instead of OID/value pair.
-- @return Table representing PDU.
function buildGetResponse(options, oid, value)
  if not options then options = {} end

  -- if really a response, should use reqId of request!
  if not options.reqId then options.reqId = math.fmod(nmap.clock_ms(), 65000) end
  if not options.err then options.err = 0 end
  if not options.errIdx then options.errIdx = 0 end

  local resp = {}
  resp._snmp = 'A2'
  resp[1] = options.reqId
  resp[2] = options.err
  resp[3] = options.errIdx

  if (type(value) == "table") then
    resp[4] = value
  else

    local payload = {}
    if (type(oid) == "string") then
      payload[1] = str2oid(oid)
    else
      payload[1] = oid
    end
    payload[2] = value
    resp[4] = {}
    resp[4][1] = payload
  end
  return resp
end

---
-- Transforms a string into an object identifier table.
-- @param oidStr Object identifier as string, for example
-- <code>"1.3.6.1.2.1.1.1.0"</code>.
-- @return Table representing OID.
function str2oid(oidStr)
  local oid = {}
  for n in string.gmatch(oidStr, "%d+") do
    table.insert(oid, tonumber(n))
  end
  oid._snmp = '06'
  return oid
end

---
-- Transforms a table representing an object identifier to a string.
-- @param oid Object identifier table.
-- @return OID string.
function oid2str(oid)
  if (type(oid) ~= "table") then return 'invalid oid' end
  return table.concat(oid, '.')
end

---
-- Transforms a table representing an IP to a string.
-- @param ip IP table.
-- @return IP string.
function ip2str(ip)
  if (type(ip) ~= "table") then return 'invalid ip' end
  return table.concat(ip, '.')
end


---
-- Transforms a string into an IP table.
-- @param ipStr IP as string.
-- @return Table representing IP.
function str2ip(ipStr)
  local ip = {}
  for n in string.gmatch(ipStr, "%d+") do
    table.insert(ip, tonumber(n))
  end
  ip._snmp = '40'
  return ip
end


---
-- Fetches values from a SNMP response.
-- @param resp SNMP Response (will be decoded if necessary).
-- @return Table with all decoded responses and their OIDs.
function fetchResponseValues(resp)
  if (type(resp) == "string") then
    local _
    _, resp = decode(resp)
  end

  if (type(resp) ~= "table") then
    return {}
  end

  local varBind
  if (resp._snmp and resp._snmp == 'A2') then
    varBind = resp[4]
  elseif (resp[3] and resp[3]._snmp and resp[3]._snmp == 'A2') then
    varBind = resp[3][4]
  end

  if (varBind and type(varBind) == "table") then
    local result = {}
    for k, v in ipairs(varBind) do
      local val = v[2]
      if (type(v[2]) == "table") then
        if (v[2]._snmp == '40') then
          val = v[2][1] .. '.' .. v[2][2] .. '.' .. v[2][3] .. '.' .. v[2][4]
        elseif (v[2]._snmp == '41') then
          val = v[2][1]
        elseif (v[2]._snmp == '42') then
          val = v[2][1]
        elseif (v[2]._snmp == '43') then
          val = v[2][1]
        elseif (v[2]._snmp == '44') then
          val = v[2][1]
        end
      end
      table.insert(result, {val, oid2str(v[1]), v[1]})
    end
    return result
  end
  return {}
end


--- SNMP Helper class
--
-- Handles socket communication, parsing, and setting of community strings
Helper = {

  --- Creates a new Helper instance
  --
  -- @param host string containing the host name or ip
  -- @param port number containing the port to connect to
  -- @param community string containing SNMP community
  -- @param options A table with appropriate options:
  --  * timeout - the timeout in milliseconds (Default: 5000)
  --  * version - the SNMP version code (Default: 0 (SNMP V1))
  -- @return o a new instance of Helper
  new = function( self, host, port, community, options )
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.host = host
    o.port = port
    
    o.community = community or "public"
    if community == nil then
      local creds_store = creds.Credentials:new(creds.ALL_DATA, host, port)
      for _,cs in ipairs({creds.State.PARAM, creds.State.VALID}) do
        local account = creds_store:getCredentials(cs)()
        if (account and account.pass) then
          o.community = account.pass == "<empty>" and "" or account.pass
          break
        end
      end
    end

    o.options = options or {
      timeout = 5000,
      version = 0
    }
    
    return o
  end,

  --- Connect to the server
  -- For UDP ports, this doesn't send any packets, but it creates the
  -- socket and locks in the timeout.
  -- @return status true on success, false on failure
  connect = function( self )
    self.socket = nmap.new_socket()
    self.socket:set_timeout(self.options.timeout)
    local status, err = self.socket:connect(self.host, self.port)
    if ( not(status) ) then return false, err end

    return true
  end,

  --- Communications helper
  -- Sends an SNMP message and receives a response.
  -- @param message the result of one of the build*Request functions
  -- @return status False if there was an error, true otherwise.
  -- @return response The raw response read from the socket.
  request = function (self, message)
    local payload = encode( buildPacket(
        message,
        self.version,
        self.community
      ) )

    local status, err = self.socket:send(payload)
    if not status then
      stdnse.debug2("snmp.Helper.request: Send to %s failed: %s", self.host.ip, err)
      return false, err
    end

    return self.socket:receive_bytes(1)
  end,

  --- Sends an SNMP Get Next request
  -- @param options SNMP options table
  -- @see snmp.options
  -- @param ... Object identifiers to be queried.
  -- @return status False if error, true otherwise
  -- @return Table with all decoded responses and their OIDs.
  getnext = function (self, options, ...)
    local status, response = self:request(buildGetNextRequest(options or {}, ...))
    if not status then
      return status, response
    end
    return status, fetchResponseValues(response)
  end,

  --- Sends an SNMP Get request
  -- @param options SNMP options table
  -- @see snmp.options
  -- @param ... Object identifiers to be queried.
  -- @return status False if error, true otherwise
  -- @return Table with all decoded responses and their OIDs.
  get = function (self, options, ...)
    local status, response = self:request(buildGetRequest(options or {}, ...))
    if not status then
      return status, response
    end
    return status, fetchResponseValues(response)
  end,

  --- Sends an SNMP Set request
  -- @param options SNMP options table
  -- @see snmp.options
  -- @param oid Object identifiers of object to be set.
  -- @param value To which value object should be set. If given a table,
  --              use the table instead of OID/value pair.
  -- @return status False if error, true otherwise
  -- @return Table with all decoded responses and their OIDs.
  set = function (self, options, oid, setparam)
    local status, response = self:request(buildSetRequest(options or {}, oid, setparam))
    if not status then
      return status, response
    end
    return status, fetchResponseValues(response)
  end,

  --- Walks the MIB Tree
  --
  -- @param base_oid string containing the base object ID to walk
  -- @return status true on success, false on failure
  -- @return table containing <code>oid</code> and <code>value</code>
  walk = function (self, base_oid)

    local snmp_table = { baseoid = base_oid }
    local oid = base_oid
    local options = {}

    local status, snmpdata = self:getnext(options, oid)
    while ( snmpdata and snmpdata[1] and snmpdata[1][1] and snmpdata[1][2] ) do
      oid  = snmpdata[1][2]
      if not oid:match(base_oid) or base_oid == oid then break end
      
      table.insert(snmp_table, { oid = oid, value = snmpdata[1][1] })
      local _ -- NSE don't want you to use global even if it is _
      _, snmpdata = self:getnext(options, oid)
    end

    return status, snmp_table
  end
}

return _ENV;
