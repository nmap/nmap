local brute = require "brute"
local creds = require "creds"
local mysql = require "mysql"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

local openssl = stdnse.silent_require "openssl"

description = [[
Performs password guessing against MySQL.
]]

---
-- @see mysql-empty-password.nse
--
-- @usage
-- nmap --script=mysql-brute <target>
--
-- @output
-- 3306/tcp open  mysql
-- | mysql-brute:
-- |   Accounts
-- |     root:root - Valid credentials
--
-- @args mysql-brute.timeout socket timeout for connecting to MySQL (default 5s)

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}

-- Version 0.5
-- Created 01/15/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 01/23/2010 - v0.2 - revised by Patrik Karlsson, changed username, password loop, added credential storage for other mysql scripts, added timelimit
-- Revised 01/23/2010 - v0.3 - revised by Patrik Karlsson, fixed bug showing account passwords detected twice
-- Revised 09/09/2011 - v0.4 - revised by Tom Sellers, changed account status text to be more consistent with other *-brute scripts
-- Revised 05/25/2012 - v0.5 - revised by Aleksandar Nikolic, rewritten to use brute lib

portrule = shortport.port_or_service(3306, "mysql")

local arg_timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME .. ".timeout"))
arg_timeout = (arg_timeout or 5) * 1000

Driver = {

  new = function(self, host, port)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.host = host
    o.port = port
    return o
  end,

  connect = function( self )
    self.socket = brute.new_socket()
    local status, err = self.socket:connect(self.host, self.port)
    self.socket:set_timeout(arg_timeout)
    if(not(status)) then
      return false, brute.Error:new( "Couldn't connect to host: " .. err )
    end
    return true
  end,

  login = function (self, user, pass)
    local status, response = mysql.receiveGreeting(self.socket)
    if(not(status)) then
      return false,brute.Error:new(response)
    end
    stdnse.debug1( "Trying %s/%s ...", user, pass )
    status, response = mysql.loginRequest( self.socket, { authversion = "post41", charset = response.charset }, user, pass, response.salt )
    if status then
      -- Add credentials for other mysql scripts to use
      if nmap.registry.mysqlusers == nil then
        nmap.registry.mysqlusers = {}
      end
      nmap.registry.mysqlusers[user]=pass
      return true, creds.Account:new( user, pass, creds.State.VALID)
    end
    return false,brute.Error:new( "Incorrect password" )
  end,

  disconnect = function( self )
    self.socket:close()
    return true
  end

}

action = function( host, port )

  local status, result
  local engine = brute.Engine:new(Driver, host, port)
  engine.options.script_name = SCRIPT_NAME

  status, result = engine:start()

  return result
end
