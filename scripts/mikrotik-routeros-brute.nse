description = [[
Performs brute force password auditing against Mikrotik RouterOS devices with the API RouterOS interface enabled.

Additional information:
* http://wiki.mikrotik.com/wiki/API
]]

---
-- @usage
-- nmap -p8728 --script mikrotik-routeros-brute <target>
--
-- @output
-- PORT     STATE SERVICE REASON
-- 8728/tcp open  unknown syn-ack
-- | mikrotik-routeros-brute:
-- |   Accounts
-- |     admin:dOsmyvsvJGA967eanX - Valid credentials
-- |   Statistics
-- |_    Performed 60 guesses in 602 seconds, average tps: 0
--
-- @args mikrotik-routeros-brute.threads sets the number of threads. Default: 1
--
---

author = "Paulino Calderon <calderon()websec.mx>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}

local shortport = require "shortport"
local brute = require "brute"
local creds = require "creds"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local openssl = stdnse.silent_require "openssl"

portrule = shortport.portnumber(8728, "tcp")

Driver =
{
  new = function(self, host, port, options )
  local o = { host = host, port = port, options = options }
  setmetatable(o, self)
  self.__index = self
    o.emptypass = true
    return o
  end,

  connect = function( self )
    self.s = brute.new_socket()
    self.s:set_timeout(self.options['timeout'])
    return self.s:connect(self.host, self.port, "tcp")
  end,

  login = function( self, username, password )
   local status, data, try
    data = string.pack("s1x", "/login")

    --Connect to service and obtain the challenge response
    try = nmap.new_try(function() return false end)
    try(self.s:send(data))
    data = try(self.s:receive_bytes(50))
    stdnse.debug1("Response #1:%s", data)
    local _, _, ret = string.find(data, '!done%%=ret=(.+)')

    --If we find the challenge value we continue the connection process
    if ret then
        stdnse.debug1("Challenge value found:%s", ret)
        local md5str = "\0" .. password .. stdnse.fromhex(ret) --appends pwd and challenge
        local chksum = stdnse.tohex(openssl.md5(md5str))
        local login_pkt = string.pack("s1s1s1x", "/login", "=name="..username, "=response=00"..chksum)
        try(self.s:send(login_pkt))
        data = try(self.s:receive_bytes(50))
        stdnse.debug1("Response #2:%s", data)
        if data then
          if string.find(data, "message=cannot") == nil then
            local c = creds.Credentials:new(SCRIPT_NAME, self.host, self.port )
            c:add(username, password, creds.State.VALID )
          end
        end
    end
    return false, brute.Error:new( "Incorrect password" )
  end,

  disconnect = function( self )
    return self.s:close()
  end
}

action = function(host, port)
  local thread_num = tonumber(stdnse.get_script_args(SCRIPT_NAME..".threads")) or 1
  local options = {timeout = 5000}
  local bengine = brute.Engine:new(Driver, host, port, options)

  bengine:setMaxThreads(thread_num)
  bengine.options.script_name = SCRIPT_NAME
  local _, result = bengine:start()
  return result
end
