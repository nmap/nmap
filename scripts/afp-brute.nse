local afp = require "afp"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local unpwdb = require "unpwdb"
local creds = require "creds"
local brute = require "brute"

-- we don't really need openssl here, but let's attempt to load it as a way
-- to simply prevent the script from running, in case we don't have it
local openssl = stdnse.silent_require("openssl")

description = [[
Performs password guessing against Apple Filing Protocol (AFP).
]]

---
-- @usage
-- nmap -p 548 --script afp-brute <host>
--
-- @output
-- PORT    STATE SERVICE
-- 548/tcp open  afp
-- | afp-brute:
-- |_  admin:KenSentMe => Valid credentials

-- Information on AFP implementations
--
-- Snow Leopard
-- ------------
-- - Delay 10 seconds for accounts with more than 5 incorrect login attempts (good)
-- - Instant response if password is successful
--
-- Netatalk
-- --------
-- - Netatalk responds with a "Parameter error" when the username is invalid
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}


-- Version 0.3
-- Created 01/15/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 03/09/2010 - v0.2 - changed so that passwords are iterated over users
--                           - this change makes better sense as guessing is slow
-- Revised 09/09/2011 - v0.3 - changed account status text to be more consistent with other *-brute scripts

portrule = shortport.port_or_service(548, "afp")

Driver = {

  new = function(self, host, port)
    local o = { helper = afp.Helper:new(host, port) }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  connect = function( self )
    return self.helper:connect()
  end,

  login = function( self, username, password )
    local status, resp = self.helper:Login( username, password )

    if status then
      -- Add credentials for other afp scripts to use via brute
      if password:len()>0
        return true, creds.Account:new(username, password, creds.State.VALID)
      else
        return true, creds.Account:new(username, "", creds.State.VALID)
        end
      break
    else
      local err = brute.Error:new( response.data )
      err:setRetry( true )
      helper:CloseSession()
      return true, err
    end
  end,

  disconnect = function(self)
    return self.helper:close()
  end,

}

local function validateAuth(host, port)
  local result, response, status = {}, nil, nil
  local valid_accounts = {}
  local helper
  local usernames, passwords

  status, usernames = unpwdb.usernames()
  if not status then return end

  status, passwords = unpwdb.passwords()
  if not status then return end

  for password in passwords do
    for username in usernames do
      if ( not(found_users[username]) ) then

        helper = afp.Helper:new()
        status, response = helper:OpenSession( host, port )

        if ( not(status) ) then
          stdnse.debug1("OpenSession failed")
          return 
        end

        stdnse.debug1("Trying %s/%s ...", username, password)
        status, result = helper:login()
        if ( status ) then
          return true, "Brute Successful"
        else
          return false, "Brute Unsuccessful"
        end
        return status, result
      end
    end
  end
end

action = function(host, port)

  local status, result = validateAuth(host, port)
  if ( not(status) ) then
    return result
  end

  local engine = brute.Engine:new(Driver, host, port )

  engine.options.script_name = SCRIPT_NAME
  engine.options.firstonly = true

  local result
  status, result = engine:start()
  return result
end
