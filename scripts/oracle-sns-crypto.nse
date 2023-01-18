local io = require "io"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local tns = require "tns"

description = [[
Probes a remote Oracle database server's configuration for Native Network Encryption
parameters, e.g. whether cryptographic protections are enabled or mandatory and the 
allowed algorithms. 
]]


---
-- @usage
-- nmap --script oracle-sns-crypto -p 1521 -sV --script-args tns.sid=<SID> <target>
-- @args tns.sid A known, valid database SID (required)
-- @see <https://www.syss.de/fileadmin/dokumente/Publikationen/2021/2021_Oracle_NNE.pdf>
-- @output
-- | oracle-sns-crypto:
-- |   SNS Server Version: 21.0.1.0.0
-- |   ALLOW_WEAK_CRYPTO_CLIENT: false
-- |   DH key size: 2048 bit
-- |   Encryption:
-- |     Status: MANDATORY
-- |     Preferred: AES128
-- |     Allowed: AES256, AES128
-- |   Integrity:
-- |     Status: MANDATORY
-- |     Preferred: SHA256
-- |_    Allowed: SHA384, SHA512, SHA256
--
-- @output 
-- | oracle-sns-crypto:
-- |   SNS Server Version: 18.0.0.0.0
-- |   ALLOW_WEAK_CRYPTO_CLIENT: true
-- |   DH key size: 2048 bit
-- |   Encryption:
-- |     Status: MANDATORY
-- |     Preferred: AES128
-- |     Allowed: AES256, AES128
-- |   Integrity:
-- |     Status: MANDATORY
-- |     Preferred: SHA256
-- |     Allowed: SHA256, SHA384, SHA512
-- |   Issues:
-- |     Latest key derivation not supported, previous versions have known weaknesses
-- |_    Vulnerable to MitM authenticated connection hijacking (CVE-2021-23511)
--
-- @output
-- PORT     STATE SERVICE    VERSION
-- | oracle-sns-crypto:
-- |   SNS Server Version: 11.2.0.2.0
-- |   ALLOW_WEAK_CRYPTO_CLIENT: true
-- |   DH key size: 512 bit
-- |   Encryption:
-- |     Status: OPTIONAL
-- |     Preferred: AES256
-- |     Allowed: RC4_56, RC4_128, DES40C, AES256, AES192, AES128, DES56C, RC4_256, TRIPLEDES112, RC4_40, TRIPLEDES168
-- |   Integrity:
-- |     Status: OPTIONAL
-- |     Preferred: SHA1
-- |     Allowed: SHA1, MD5
-- |   Issues:
-- |     Integrity protection not enforced
-- |     Encryption not enforced
-- |     Weak (< 2048 bit) DH Key
-- |     Latest key derivation not supported, previous versions have known weaknesses
-- |     Allows weak encryption algorithm
-- |     Allows weak integrity algorithm (also implies legacy/RC4 key derivation)
-- |_    Vulnerable to MitM authenticated connection hijacking (CVE-2021-23511)




author = "Moritz Bechler <moritz.bechler@syss.de>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}


portrule = shortport.port_or_service(1521, "oracle-tns", "tcp", "open")

DataTypes = {
  BYTES = 1,
  NUMBER = 3,
  VERSION = 5,
}


ParameterDecoders = {

  [DataTypes.BYTES] = function(val)
    return stdnse.tohex(val)
  end,

  [DataTypes.NUMBER] = function(val)
    if val:len() == 2 then
      return string.unpack(">I2", val)
    end
    return string.unpack(">I4", val)
  end,

  [DataTypes.VERSION] = function(val)
    local x = string.unpack(">I", val)
    local maj = (x >> 24) & 0xFF
    local min1 = (x >> 20) & 0xF
    local min2 = (x >> 12) & 0xFF
    local min3 = (x >> 8) & 0xF
    local min4 = (x & 0xFF)
    return ("%d.%d.%d.%d.%d"):format(maj,min1,min2,min3,min4)
  end,
}

Encryption = {
    RC4_40 = 1, RC4_56 = 8, RC4_128 = 10, RC4_256 = 6,
    DES40C = 3, DES56C = 2,
    TRIPLEDES112 = 11, TRIPLEDES168 = 12,
    AES128 = 15, AES192 = 16, AES256 = 17
}
WeakEncryption = { 
    RC4_40 = 1, RC4_56 = 8, RC4_128 = 10, RC4_256 = 6,
    DES40C = 3, DES56C = 2,
    TRIPLEDES112 = 11, TRIPLEDES168 = 12
}

Integrity = {
    MD5 = 1, SHA1 = 3, SHA512 = 4, SHA256 = 5, SHA384 = 6
}
WeakIntegrity = {
    MD5 = 1, SHA1 = 3
}

function find ( t, value )
  for k,v in pairs(t) do
    if v==value then return k end
  end
  return nil
end

function contain_any(t, items)
    for _, value in pairs(t) do
    if items[value] then
      return true
    end
  end
  return false
end

SNS = {

  tns_type = tns.Packet.TNS.Type.DATA,
  flags = 0,


  clientVersion = 0x15001000,
  unknown1 = 0,
  ialgs = stdnse.fromhex("0301040506"),
  ealgs = stdnse.fromhex("1106100c0f0a0b08020103"),
  authParm = 0xfcff,



  -- Creates a new SNS instance
  --
  -- @return o new instance of the SNS packet
  new = function(self)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  parseResponse = function( self, tns )
    local flags, magic, slen, clientVersion, numServices, unknown1  = string.unpack(">I2I4I2I4I2B", tns.data)
    stdnse.print_debug(3, "SNS Handshare response %s", stdnse.tohex(tns.data))
    if( magic ~= 0xdeadbeef )
    then 
      return false, "Invalid TNS data type"
    end

    stdnse.print_debug(3, "SNS Handshare response %d %x %d %d %d %d", flags, magic, slen, clientVersion, numServices, unknown1)

    local services = string.sub(tns.data, 16, slen+2)
    local pos = 1
    stdnse.print_debug(3, "Service data %s (%d)", stdnse.tohex(services), services:len())

    local serviceinfo = {}

    for i=1,numServices do
      local serviceId, numParameters, unknown2 = string.unpack(">I2I2I4", services, pos)
      pos = pos + 8
      stdnse.print_debug(3, "SNS Handshare service %d %d %x",   serviceId, numParameters, unknown2)

      serviceinfo[serviceId] = {}

      for j=1,numParameters do
        local plen, ptype = string.unpack(">I2I2", services, pos)
        local val = ''
        pdata = string.sub(services, pos + 4, pos + 3 + plen)
        pos = pos + 4 + plen
        stdnse.print_debug(3, "SNS Handshare param %d:%d %d[%d] %s", serviceId, j, ptype, plen, stdnse.tohex(pdata))
        if ( ParameterDecoders[ptype] ) then
          val = ParameterDecoders[ptype](pdata)
        else
          val = pdata
        end
        stdnse.print_debug(3, "SNS Handshare param %d:%d = %s", serviceId, j, val)
        serviceinfo[serviceId][j] = val
      end
    end
    return true, serviceinfo
  end,

  --- Converts the DATA packet to string
  --
  -- @return string containing the packet
  __tostring = function( self )
    local numServices = 4
    local services = ""

    -- supervisor (4)
    services = services .. string.pack(">I2I2I4", 4, 3, 0) .. 
        string.pack(">I2I2I4", 4, 5, self.clientVersion) .. 
        string.pack(">I2I2", 8, 1) .. stdnse.fromhex("0000e2daf91050e1") ..
        string.pack(">I2I2", 0x12,1) .. stdnse.fromhex("deadbeef0003000000040004000100010002")

    -- authentication (1)
    services = services .. string.pack(">I2I2I4", 1, 3, 0) .. 
        string.pack(">I2I2I4", 4, 5, self.clientVersion) .. 
        string.pack(">I2I2I2", 2, 3, 0xe0e1) .. 
        string.pack(">I2I2I2", 2, 6, self.authParm)    

    -- encryption (2)
    services = services .. string.pack(">I2I2I4", 2, 2, 0) .. 
        string.pack(">I2I2I4", 4, 5, self.clientVersion) .. 
        string.pack(">I2I2", self.ealgs:len(), 1) .. self.ealgs 
    
    -- integrity (3)
    services = services .. string.pack(">I2I2I4", 3, 2, 0) .. 
        string.pack(">I2I2I4", 4, 5, self.clientVersion) .. 
        string.pack(">I2I2", self.ialgs:len(), 1) .. self.ialgs 

    
    sns = stdnse.fromhex("deadbeef") ..  string.pack(">I2I4I2B", services:len() + 13, 0, numServices, self.unknown1)  .. services
    stdnse.print_debug(3, "SNS Handshake %s", stdnse.tohex(sns))


    return string.pack(">I2", self.flags) .. sns 
  end,
}


Prober = {
  ialgs = stdnse.fromhex("030104050600"),
  ealgs = stdnse.fromhex("1106100c0f0a0b0802010300"),
  authParam = 0xfcff,
  clientVersion = 0x15001000,

  --- Creates a new Helper instance
  --
  -- @param host table containing the host table as received by action
  -- @param port table containing the port table as received by action
  -- @param instance string containing the instance name
  -- @return o new instance of Helper
  new = function(self, host, port, instance, socket )
    local o = {
      host = host,
      port = port,
      socket = socket or nmap.new_socket(),
      dbinstance = instance or stdnse.get_script_args('tns.sid') 
    }
    o.socket:set_timeout(30000)
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  --- Connects and performs protocol negotiation with the Oracle server
  --
  -- @return true on success, false on failure
  -- @return err containing error message when status is false
  Connect = function( self, params )
    local status, data = self.socket:connect( self.host.ip, self.port.number, "tcp" )
    local conn, packet, res

    if( not(status) ) then 
      sdnse.print_debug(3, "Connection to %s:%d failed", self.host.ip, self.port.number)
      return status, data 
    end

    self.comm = tns.Comm:new( self.socket )

    local con = tns.Packet.Connect:new( self.host.ip, self.port.number, self.dbinstance )
    -- version >= 315 support requires patch to tns.nse
    if con.unknown1 then
      con.version = 318
    end
    con.svc_options = 0x0041
    status, self.version = self.comm:exchTNSPacket( con )

    stdnse.print_debug(3, "Version '%s' %s", status, self.version)
    if ( not(status) ) then 
            return false, self.version 
    end



    if ( self.version < 300 or self.version > 318 ) then
      return false, ("Unsupported Oracle Version (%d)"):format(self.version)
    end
    if ( self.version >= 315 ) then
      self.comm.longfmt = true
    end

    local sns = SNS:new()
    sns.authParam = params.authParam or self.authParam
    sns.ealgs = params.ealgs or self.ealgs
    sns.ialgs = params.ialgs or self.ialgs
    sns.clientVersion = params.clientVersion or self.clientVersion
    stdnse.print_debug(3, "Requesting auth %x enc %s int %s version %x", sns.authParam, stdnse.tohex(sns.ealgs), stdnse.tohex(sns.ialgs), sns.clientVersion)


    status, res = self.comm:exchTNSPacket( sns )
    if ( not(status) ) then
            return false, res 
    end

  
    local encryption = res[2] and res[2][2] and (res[2][2] ~= "\x00")
    local ealg = encryption and find(Encryption, string.unpack("B",res[2][2]))
    local integrity = res[3] and res[3][2] and (res[3][2] ~= "\x00")
    local ialg = integrity and find(Integrity, string.unpack("B", res[3][2]))
    local version = res[3][1] or res[4][1]
    local dhsize = res[3] and res[3][3] or false



    if not dhsize then
        self.socket:set_timeout(2000)
        status, res = self.socket:receive(1)
        stdnse.print_debug(3, "Connection '%s' %s", status, res)
        self.socket:close()
        self.socket = nmap.new_socket()

        if not status and res == "EOF" then
          return false, ("Crypto parameters rejected")
        end
        if not status and res ~= "TIMEOUT" then
          return false, res
        end
    end

    return true, {
        version=version,
        encryption=encryption,
        integrity=integrity,
        dhsize=dhsize,
        ealg=ealg,
        ialg=ialg
    }
  end,


  Close = function ( self )
    self.socket:close()
    return true
  end,

}

local function fail (err) return stdnse.format_output(false, err) end

action = function(host, port)
  local sid = stdnse.get_script_args('tns.sid')

  if ( not(sid) ) then
    return fail("Oracle instance not set (see tns.sid)")
  end

  local prober = Prober:new( host, port, sid )
  local encryption = 'OPTIONAL'
  local integrity = 'OPTIONAL'


  -- connect with default (all algorithms)
  -- servers preferred algorithm is selected
  local status, result = prober:Connect({})
  if ( not(status) ) then
    return fail("Failed to connect to oracle server: " .. result)
  end
  local prefialg = result.ialg
  local prefealg = result.ealg
  local version = result.version
  local dhsize = result.dhsize

  if not prefialg then
      integrity = 'DISABLED'
  end
  if not prefealg then
      encryption = 'DISABLED'
  end

  local allows_weak_crypto = true
  -- client version will be rejected if ALLOW_WEAK_CRYPTO_CLIENTS=FALSE
  local status, result = prober:Connect({clientVersion=0x15000000})
  if ( not(status) ) then
    if result == "Crypto parameters rejected" then
      allows_weak_crypto = false
    else
      return fail("Failed to connect to oracle server: " .. result)
    end
  end


  -- 
  local status, result = prober:Connect({ialgs="\x00"})
  if ( not(status) ) then
    if result == "Crypto parameters rejected" then
      integrity = 'MANDATORY'
    else
      return fail("Failed to connect to oracle server: " .. result)
    end
  end

  local status, result = prober:Connect({ealgs="\x00"})
  if ( not(status) ) then
    if result == "Crypto parameters rejected" then
      encryption = 'MANDATORY'
    else
      return fail("Failed to connect to oracle server: " .. result)
    end
  end


  local allowealgs = {}
  for k,v in pairs(Encryption) do
          local status, result = prober:Connect({ealgs=string.char(v)})
          if ( not(status) and result ~= "Crypto parameters rejected" ) then
            return fail("Failed to connect to oracle server: " .. result)
          end

          if result.ealg == k then
            allowealgs[#allowealgs+1] = k
            stdnse.print_debug(1, "Encryption algorithm '%s' accepted", k)
          else
            stdnse.print_debug(2, "Encryption algorithm '%s' rejected", k)
          end
  end

  local allowialgs = {}
  for k,v in pairs(Integrity) do
          local status, result = prober:Connect({ialgs=string.char(v)})
          if ( not(status) and result ~= "Crypto parameters rejected" ) then
            return fail("Failed to connect to oracle server: " .. result)
        end

          if result.ialg == k then
            allowialgs[#allowialgs+1] = k
            stdnse.print_debug(1, "Integrity algorithm '%s' accepted", k)
          else
            stdnse.print_debug(2, "Integrity algorithm '%s' rejected", k)
          end
  end

  prober:Close()


  local issues = {}
  if integrity ~= "MANDATORY" then
    issues[#issues+1] = "Integrity protection not enforced"
  end
  if encryption ~= "MANDATORY" then
    issues[#issues+1] = "Encryption not enforced"
  end
  if dhsize and dhsize < 2048 then
    if not(tns.Packet.Connect.unknown1) then
      issues[#issues+1] = "Weak (< 2048 bit) DH Key - possible FP - missing tns.lua support"
    else
      issues[#issues+1] = "Weak (< 2048 bit) DH Key"
    end
  end
  local vermin2 = tonumber(string.match(version, "%d+.%d+.(%d+).%d+.%d+"))
  if vermin2 < 1 then
    issues[#issues+1] = "Updated (2021) key derivation not supported, previous versions have known weaknesses"
  end
  if contain_any(allowealgs, WeakEncryption) then
    issues[#issues+1] = "Allows weak encryption algorithm"
  end
  if contain_any(allowialgs, WeakIntegrity) then
    issues[#issues+1] = "Allows weak integrity algorithm (also implies legacy/RC4 key derivation)"
  end
  if vermin2 < 1 or allows_weak_crypto then
    issues[#issues+1] = "Vulnerable to MitM authenticated connection hijacking (CVE-2021-23511)"
  end

  table.sort(allowealgs)
  table.sort(allowialgs)
  local output = stdnse.output_table()
  output["SNS Server Version"]=version
  output["ALLOW_WEAK_CRYPTO_CLIENT"]=allows_weak_crypto
  if dhsize then
    output["DH key size"]=("%d bit"):format(dhsize)
  end
  output["Encryption"]=stdnse.output_table()
  output["Encryption"]["Status"]=encryption
  output["Encryption"]["Preferred"]=prefealg
  output["Encryption"]["Allowed"]=table.concat(allowealgs, ", ")
  output["Integrity"]=stdnse.output_table()
  output["Integrity"]["Status"]=integrity
  output["Integrity"]["Preferred"]=prefialg
  output["Integrity"]["Allowed"]=table.concat(allowialgs, ", ")
  if #issues > 0 then
    output["Issues"]=issues
  end
  return output

end
