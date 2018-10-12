local bits = require "bits"
local brute = require "brute"
local creds = require "creds"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Performs brute force password auditing against the BackOrifice service. The
<code>backorifice-brute.ports</code> script argument is mandatory (it specifies ports to run
the script against).
]]

---
-- @usage
-- nmap -sU --script backorifice-brute <host> --script-args backorifice-brute.ports=<ports>
--
-- @arg backorifice-brute.ports (mandatory) List of UDP ports to run the script against separated with "," ex. "U:31337,25252,151-222", "U:1024-1512"
--
-- This script uses the brute library to perform password guessing. A
-- successful password guess is stored in the nmap registry, under the
-- <code>nmap.registry.credentials.backorifice</code> table for other BackOrifice
-- scripts to use.
--
-- @output
-- PORT       STATE  SERVICE
-- 31337/udp  open   BackOrifice
-- | backorifice-brute:
-- |   Accounts:
-- |     michael => Valid credentials
-- |   Statistics
-- |_    Perfomed 60023 guesses in 467 seconds, average tps: 138
--

-- Summary
-- -------
--   x The Driver class contains the driver implementation used by the brute
--     library
--   x The backorifice class contains the backorifice client implementation
--

author = "Gorjan Petrovski"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}


-- This portrule succeeds only when the open|filtered port is in the port range
-- which is specified by the ports script argument
portrule = function(host, port)

  local ports = stdnse.get_script_args(SCRIPT_NAME .. ".ports")
  if not ports then
    stdnse.verbose1("Skipping '%s' %s, 'ports' argument is missing.",SCRIPT_NAME, SCRIPT_TYPE)
    return false
  end

  -- ensure UDP
  ports = ports:gsub("^[U:]*", "U:")
  return port.protocol == "udp" and shortport.port_range(ports)(host, port) and
    not(shortport.port_is_excluded(port.number,port.protocol))
end

local MAGICSTRING ="*!*QWTY?"
local backorifice =
{
  new = function(self, host, port)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.host = host
    o.port = port
    return o
  end,

  --- Initializes the backorifice object
  --
  initialize = function(self)
    --create socket
    self.socket = nmap.new_socket("udp")
    self.socket:set_timeout(self.host.times.timeout * 1000)
    return true
  end,

  --- Attempts to send an encrypted PING packet to BackOrifice service
  --
  -- @param password string containing password for encryption
  -- @param initial_seed number containing initial encryption seed
  -- @return status, true on success, false on failure
  -- @return err string containing error message on failure
  try_password = function(self, password, initial_seed)
    --initialize BackOrifice PING packet:   |MAGICSTRING|size|packetID|TYPE_PING|arg1|arg_separat|arg2|CRC/disregarded|
    local PING_PACKET = MAGICSTRING .. string.pack("<I4 I4 B zz", 19, 0, 1,  "",  "")
    local seed, status, response, encrypted_ping

    if not(initial_seed) then
      seed = self:gen_initial_seed(password)
    else
      seed = initial_seed
    end

    encrypted_ping = self:BOcrypt(PING_PACKET,seed)

    status, response = self.socket:sendto(self.host, self.port, encrypted_ping)
    if not(status) then
      return false, response
    end
    status, response = self.socket:receive()

    -- The first 8 bytes of both response and sent data are
    -- magicstring = "*!*QWTY?", without the quotes, and since
    -- both are encrypted with the same initial seed, this is
    -- how we verify we are talking to a BackOrifice service.
    -- The statement is optimized so as not to decrypt unless
    -- comparison of encrypted magicstrings succeeds
    if status and response:sub(1,8) == encrypted_ping:sub(1,8)
        and self:BOcrypt(response,seed):match("!PONG!(1%.20)!.*!") then
      local BOversion, BOhostname = self:BOcrypt(response,seed):match("!PONG!(1%.20)!(.*)!")
      self:insert_version_info(BOversion,BOhostname,nil,password)
      return true
    else
      if not(status) then
        return false, response
      else
        return false,"Response not recognized."
      end
    end
  end,

  --- Close the socket
  --
  -- @return status true on success, false on failure
  close = function(self)
    return self.socket:close()
  end,

  --- Generates the initial encryption seed from a password
  --
  -- @param password string containing password
  -- @return seed number containing initial seed
  gen_initial_seed = function(self, password)
    if password == nil then
      return 31337
    else
      local y = #password
      local z = 0

      for x = 1,y do
        local pchar = string.byte(password,x)
        z = z + pchar
      end

      for x=1,y do
        local pchar = string.byte(password,x)
        if (x-1)%2 == 1 then
          z = z - (pchar * (y-(x-1)+1))
        else
          z = z + (pchar * (y-(x-1)+1))
        end
        z = z % 0x7fffffff
      end
      z = (z*y) % 0x7fffffff
      return z
    end
  end,

  --- Generates next encryption seed from given seed
  --
  -- @param seed number containing current seed
  -- @return seed number containing next seed
  gen_next_seed = function(self, seed)
    seed = seed*214013 + 2531011
    seed = seed & 0xffffff
    return seed
  end,

  --- Encrypts/decrypts data using BackOrifice algorithm
  --
  -- @param data binary string containing data to be encrypted/decrypted
  -- @param initial_seed number containing initial encryption seed
  -- @return data binary string containing encrypted/decrypted data
  BOcrypt = function(self, data, initial_seed )
    if data==nil then return end
    local output = {}

    local seed = initial_seed

    for i = 1, #data  do
      local data_byte = string.byte(data,i)

      --calculate next seed
      seed = self:gen_next_seed(seed)
      --calculate encryption key based on seed
      local key = bits.arshift(seed,16) & 0xff

      local crypto_byte = data_byte ~ key
      output[i] = string.char(crypto_byte)
      if i == 256 then break end --ARGSIZE limitation
    end
    return table.concat(output, "")
  end,

  insert_version_info = function(self,BOversion,BOhostname,initial_seed,password)
    if not self.port.version then self.port.version={} end
    if not self.port.version.name then
      self.port.version.name ="BackOrifice"
      self.port.version.name_confidence = 10
    end
    if not self.port.version.product then self.port.version.product ="BackOrifice trojan" end
    if not self.port.version.version then self.port.version.version = BOversion end
    if not self.port.version.extrainfo then
      if not password then
        if not initial_seed then
          self.port.version.extrainfo = "no password"
        else
          self.port.version.extrainfo = "initial encryption seed="..initial_seed
        end
      else
        self.port.version.extrainfo = "password="..password
      end
    end
    self.port.version.hostname = BOhostname
    if not self.port.version.ostype then self.port.version.ostype = "Windows" end
    nmap.set_port_version(self.host, self.port)
    nmap.set_port_state(self.host,self.port,"open")
  end
}

local Driver =
{
  new = function(self, host, port)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.host = host
    o.port = port
    return o
  end,

  connect=function(self)
    --only initialize since BackOrifice service knows no connect()
    self.bo = backorifice:new(self.host,self.port)
    self.bo:initialize()
    return true
  end,

  disconnect = function( self )
    self.bo:close()
  end,

  --- Attempts to send encrypted PING packet to BackOrifice service
  --
  -- @param username string containing username which is disregarded
  -- @param password string containing login password
  -- @return brute.Error object on failure
  --         creds.Account object on success
  login = function( self, username, password )
    local status, msg = self.bo:try_password(password,nil)
    if status then
      if not(nmap.registry['credentials']) then
        nmap.registry['credentials']={}
      end
      if ( not( nmap.registry.credentials['backorifice'] ) ) then
        nmap.registry.credentials['backorifice'] = {}
      end
      table.insert( nmap.registry.credentials.backorifice, { password = password } )
      return true, creds.Account:new("", password, creds.State.VALID)
    else
      -- The only indication that the password is incorrect is a timeout
      local err = brute.Error:new( "Incorrect password" )
      err:setRetry(false)
      return false, err
    end
  end,

}

action = function( host, port )

  local status, result
  local engine = brute.Engine:new(Driver,host,port)

  engine.options.firstonly = true
  engine.options.passonly = true
  engine.options.script_name = SCRIPT_NAME

  status, result = engine:start()

  return result
end
