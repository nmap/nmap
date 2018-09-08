local brute = require "brute"
local comm = require "comm"
local creds = require "creds"
local match = require "match"
local irc = require "irc"
local stdnse = require "stdnse"
local rand = require "rand"

description=[[
Performs brute force password auditing against IRC (Internet Relay Chat) servers.
]]

---
-- @usage
-- nmap --script irc-brute -p 6667 <ip>
--
-- @output
-- PORT     STATE SERVICE
-- 6667/tcp open  irc
-- | irc-brute:
-- |   Accounts
-- |     password - Valid credentials
-- |   Statistics
-- |_    Performed 1927 guesses in 36 seconds, average tps: 74
--

--
-- Version 0.1
-- Created 26/10/2011 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
--


author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories={"brute","intrusive"}

portrule = irc.portrule

Driver = {

  new = function(self, host, port, opts)
    local o = { host = host, port = port, opts = opts or {} }
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  connect = function(self)
    -- the high timeout should take delays from ident into consideration
    local s, r, opts, _ = comm.tryssl(self.host,
      self.port,
      '',
      { timeout = self.opts.timeout or 10000 } )
    if ( not(s) ) then
      return false, "Failed to connect to server"
    end
    self.socket = s
    return true
  end,

  login = function(self, _, password)
    local msg = ("PASS %s\r\nNICK nmap_brute\r\nUSER anonymous 0 * :Nmap brute\r\n"):format(password)
    local status, data = self.socket:send(msg)
    local success = false

    if ( not(status) ) then
      local err = brute.Error:new( data )
      -- This might be temporary, set the retry flag
      err:setRetry( true )
      return false, err
    end

    repeat
      local status, response = self.socket:receive_buf(match.pattern_limit("\r?\n", 2048), false)
      -- we check for the RPL_WELCOME message, if we don't see it,
      -- we failed to authenticate
      if ( status and response:match("^:.-%s(%d*)%s") == "001" ) then
        success = true
      end
    until(not(status))

    if (success) then
      return true, creds.Account:new("", password, creds.State.VALID)
    end
    return false, brute.Error:new("Incorrect password")
  end,

  disconnect = function(self) return self.socket:close() end,
}

local function needsPassword(host, port)
  local msg = ("NICK %s\r\nUSER anonymous 0 * :Nmap brute\r\n"):format(rand.random_alpha(9))
  local s, r, opts, _ = comm.tryssl(host, port, msg, { timeout = 15000 } )
  local err, code

  repeat
    local status, response = s:receive_buf(match.pattern_limit("\r?\n", 2048), false)
    if ( status ) then
      code = tonumber(response:match("^:.-%s(%d*)%s"))
      -- break after first code
      if (code == 001 ) then
        err = "The IRC service does not require authentication"
        break
      elseif( code ) then
        break
      end
    end
  until(not(status))
  if (code == 464) then
    return true
  end
  if ( code ) then
    return false, ("Failed to check password requirements, unknown code (%d)"):format(code)
  else
    return false, "Failed to check password requirements"
  end
end


action = function(host, port)

  local status, err = needsPassword(host, port)
  if ( not(status) ) then
    return stdnse.format_output(false, err)
  end

  local engine = brute.Engine:new(Driver, host, port)
  engine.options.script_name = SCRIPT_NAME
  engine.options.firstonly = true
  engine.options.passonly = true
  local result
  status, result = engine:start()

  return result

end
