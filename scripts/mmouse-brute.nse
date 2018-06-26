local brute = require "brute"
local creds = require "creds"
local match = require "match"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Performs brute force password auditing against the RPA Tech Mobile Mouse
servers.

The Mobile Mouse server runs on OS X, Windows and Linux and enables remote
control of the keyboard and mouse from an iOS device. For more information:
http://mobilemouse.com/
]]

---
-- @usage
-- nmap --script mmouse-brute -p 51010 <host>
--
-- @output
-- PORT      STATE SERVICE
-- 51010/tcp open  unknown
-- | mmouse-brute:
-- |   Accounts
-- |     vanilla - Valid credentials
-- |   Statistics
-- |_    Performed 1199 guesses in 23 seconds, average tps: 47
--
-- @args mmouse-brute.timeout socket timeout for connecting to Mobile Mouse (default 5s)

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}


local arg_timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME .. ".timeout"))
arg_timeout = (arg_timeout or 5) * 1000

portrule = shortport.port_or_service(51010, "mmouse", "tcp")

Driver = {

  new = function(self, host, port)
    local o = { host = host, port = port }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  connect = function( self )
    self.socket = brute.new_socket()
    self.socket:set_timeout(arg_timeout)
    return self.socket:connect(self.host, self.port)
  end,

  login = function( self, username, password )
    local devid = "0123456789abcdef0123456789abcdef0123456"
    local devname = "Lord Vaders iPad"
    local suffix = "2".."\30".."2".."\04"
    local auth = ("CONNECT\30%s\30%s\30%s\30%s"):format(password, devid, devname, suffix)

    local status = self.socket:send(auth)
    if ( not(status) ) then
      local err = brute.Error:new( "Failed to send data to server" )
      err:setRetry( true )
      return false, err
    end

    local status, data = self.socket:receive_buf(match.pattern_limit("\04", 2048), true)

    if (data:match("^CONNECTED\30([^\30]*)") == "NO" ) then
      return false, brute.Error:new( "Incorrect password" )
    elseif ( data:match("^CONNECTED\30([^\30]*)") == "YES" ) then
      return true, creds.Account:new("", password, creds.State.VALID)
    end

    local err = brute.Error:new("An unexpected error occurred, retrying ...")
    err:setRetry(true)
    return false, err
  end,

  disconnect = function(self)
    self.socket:close()
  end,

}

local function hasPassword(host, port)
  local driver = Driver:new(host, port)
  if ( not(driver:connect()) ) then
    error("Failed to connect to server")
  end
  local status = driver:login(nil, "nmap")
  driver:disconnect()

  return not(status)
end


action = function(host, port)

  if ( not(hasPassword(host, port)) ) then
    return "\n  Server has no password"
  end

  local status, result
  local engine = brute.Engine:new(Driver, host, port )

  engine.options.script_name = SCRIPT_NAME
  engine.options.firstonly = true
  engine.options:setOption( "passonly", true )

  -- mouse server does not behave well when multiple threads are guessing
  engine:setMaxThreads(1)

  status, result = engine:start()

  return result
end
