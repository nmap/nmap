local string = require "string"
local stdnse = require "stdnse"
local shortport = require "shortport"
local brute = require "brute"
local creds = require "creds"
local unpwdb = require "unpwdb"
local drda = require "drda"
local comm = require "comm"

description = [[
z/OS JES Network Job Entry (NJE) 'I record' password brute forcer.

After successfully negotiating an OPEN connection request, NJE requires sending,
what IBM calls, an 'I record'. This initialization record may sometimes require
a password. This script, provided with a valid OHOST/RHOST for the NJE connection,
brute forces the password.

Most systems only have one password, it is recommended to use the
<code>brute.firstonly</code> script argument.
]]


---
-- @usage
-- nmap -sV --script=nje-pass-brute --script-args=ohost='POTATO',rhost='CACTUS' <target>
-- nmap --script=nje-pass-brute --script-args=ohost='POTATO',rhost='CACTUS',sleep=5 -p 175 <target>
--
-- @args nje-pass-brute.ohost The target NJE server OHOST value.
--
-- @args nje-pass-brute.rhost The target NJE server RHOST value.
--
-- @args nje-pass-brute.sleep NJE only allows one connection from a valid OHOST.
--                            The sleep value ensures only one connection is valid
--                            at a time. The default is 1 second.
-- @output
-- PORT    STATE SERVICE VERSION
-- 175/tcp open  nje     IBM Network Job Entry (JES)
-- | nje-pass-brute:
-- |   NJE Password:
-- |     Password:A - Valid credentials
-- |_  Statistics: Performed 8 guesses in 12 seconds, average tps: 0
--
-- @changelog
-- 2016-03-22 - v0.1 - created by Soldier of Fortran

author = "Soldier of Fortran"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}

portrule = shortport.port_or_service({175,2252}, "nje")

local openNJEfmt = "\xd6\xd7\xc5\xd5@@@@%s\0\0\0\0%s\0\0\0\0\0"
local sohenq = "\0\0\0\x12\0\0\0\0\0\0\0\x02\x01\x2d\0\0\0\0"
local dleack = "\0\0\0\x12\0\0\0\0\0\0\0\x02\x10\x70\0\0\0\0"
-- NJE I Record: first %s is RHOST second is password * 2
local iRECfmt = "\0\0\0\x3e\0\0\0\0\0\0\0\x2e\x10\x02\x80\x8f\xcf\xf0\xc9\x29%s\x01\0\0\0\0\0\x64\x80\x00%s\0\x15\0\0\0\0\0\0\0"

Driver = {
  new = function(self, host, port, options)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.host = host
    o.port = port
    o.options = options
    return o
  end,

  connect = function( self )
    -- the high timeout should take delays into consideration
    local s, r, opts, _ = comm.tryssl(self.host, self.port, '', { timeout = 50000 } )
    if ( not(s) ) then
      stdnse.debug("Failed to connect")
      return false, "Failed to connect to server"
    end
    self.socket = s
    return true
  end,

  disconnect = function( self )
    stdnse.sleep(self.options['sleep'])
    return self.socket:close()
  end,

  login = function( self, username, password )
    stdnse.verbose(2,"Trying... %s", password)

    -- Open the connection by sending OPEN NJE packet
    local openNJE = openNJEfmt:format(drda.StringUtil.toEBCDIC(("%-8s"):format(self.options['rhost'])),
                                drda.StringUtil.toEBCDIC(("%-8s"):format(self.options['ohost'])) )
    local status, err = self.socket:send( openNJE )
    if not status then return false, brute.Error:new("Failed to send OPEN") end
    local status, data = self.socket:receive_bytes(33)
    if not status then return false, brute.Error:new("Failed to receive") end
    -- Make sure the response is valid
    if data:sub(-1) ~= "\0" then
      err = brute.Error:new("Invalid OHOST (".. self.options['ohost'] ..") or RHOST (".. self.options['rhost'] ..")")
      err:setAbort(true) -- no point continuing if these aren't correct
      return false, err
    end
    -- Next send SOH & SEQ
    status, err = self.socket:send( sohenq )
    if not status then return false, brute.Error:new("Failed to send SOH/ENQ") end
    status, data = self.socket:receive_bytes(18)
    if not status or data ~= dleack then return false, brute.Error:new("Failed to receive") end
    -- Finally send an I record with the password
    local njePKT = iRECfmt:format( drda.StringUtil.toEBCDIC(("%-8s"):format(self.options['rhost'])),
                                   drda.StringUtil.toEBCDIC(("%-8s"):format(password:upper())):rep(2))
    status, err = self.socket:send( njePKT )
    if not status then return false, brute.Error:new("Failed to send NJE Packet") end
    status, data = self.socket:receive_bytes(19)
    if not status then return false, "Failed to receive" end
    -- When we send an 'I' record, if the password is invalid it will reply with a 'B' record
    -- B in EBCDIC is 0xC2
    if data:sub(19,19) ~= "\xc2" then
      stdnse.verbose(2,"Valid NJE Password: %s", password)
      return true, creds.Account:new("Password", password, creds.State.VALID)
    end
    return false, brute.Error:new( "Invalid Password" )
  end,
}

-- Checks string to see if it follows node naming limitations
local valid_pass = function(x)
  local patt = "[%w@#%$]"
  return (string.len(x) <= 8 and string.match(x,patt))
end

action = function( host, port )
  local r_host = stdnse.get_script_args('nje-pass-brute.rhost') or nil
  local o_host = stdnse.get_script_args('nje-pass-brute.ohost') or nil
  local sleep = stdnse.get_script_args('nje-pass-brute.sleep') or 1
  if not o_host or not r_host then
    return false, "No OHOST or RHOST set. Use --script-args nje-node-brute.rhost=\"<rhost>\",nje-node-brute.ohost=\"<ohost>\""
  end
  stdnse.verbose(2, "Using RHOST / OHOST: %s / %s", r_host:upper(), o_host:upper())
  local options = { rhost = r_host:upper(), ohost = o_host:upper(), sleep = sleep }
  local engine = brute.Engine:new(Driver, host, port, options)
  local passwords = unpwdb.filter_iterator(brute.passwords_iterator(),valid_pass)
  engine.options:setOption("passonly", true )
  engine:setPasswordIterator(passwords)
  -- Unfortunately only one OHOST/RHOST may be connected at once
  engine:setMaxThreads(1)
  engine.options.script_name = SCRIPT_NAME
  engine.options:setTitle("NJE Password")
  local status, result = engine:start()
  return result
end
