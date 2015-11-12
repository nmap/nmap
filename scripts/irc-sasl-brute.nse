local base64 = require "base64"
local brute = require "brute"
local comm = require "comm"
local creds = require "creds"
local sasl = require "sasl"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description=[[
Performs brute force password auditing against IRC (Internet Relay Chat) servers supporting SASL authentication.
]]

-- You can read more about sasl here:
-- https://github.com/atheme/charybdis/blob/master/doc/sasl.txt
-- http://www.leeh.co.uk/draft-mitchell-irc-capabilities-02.html
-- the first link also explains the meaning of constants used in
-- this script.

---
-- @usage
-- nmap --script irc-sasl-brute -p 6667 <ip>
--
-- @output
-- PORT     STATE SERVICE REASON
-- 6667/tcp open  irc     syn-ack
-- | irc-sasl-brute:
-- |   Accounts
-- |     root:toor - Valid credentials
-- |   Statistics
-- |_    Performed 60 guesses in 29 seconds, average tps: 2
--
-- @args irc-sasl-brute.threads the number of threads to use while brute-forcing.
--       Defaults to 2.



author = "Piotr Olma"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories={"brute","intrusive"}

portrule = shortport.port_or_service({6666,6667,6697,6679},{"irc","ircs"})

local dbg = stdnse.debug

-- some parts of the following class are taken from irc-brute written by Patrik
Driver = {

  new = function(self, host, port, saslencoder)
    local o = { host = host, port = port, saslencoder = saslencoder}
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  connect = function(self)
    -- the high timeout should take delays from ident into consideration
    local s, r, opts, _ = comm.tryssl(self.host,
      self.port,
      "CAP REQ sasl\r\n",
      { timeout = 10000 } )
    if ( not(s) ) then
      return false, "Failed to connect to server"
    end
    if string.find(r:lower(), "throttled") then
      -- we were reconnecting too fast
      dbg(2, "throttled.")
      return false, "We got throttled."
    end
    local status, _ = s:send("CAP END\r\n")
    if not status then return false, "Send failed." end
    local response
    repeat
      status, response = s:receive_lines(1)
      if not status then return false, "Receive failed." end
      if string.find(response, "ACK") then status = false end
    until (not status)
    self.socket = s
    return true
  end,

  login = function(self, username, password)
    self.socket:send("AUTHENTICATE ".. self.saslencoder:get_mechanism() .."\r\n")
    local status, response, challenge
    repeat
      status, response = self.socket:receive_lines(1)
      if not status then
        local err = brute.Error:new(response)
        err:setRetry(true)
        return false, err
      end
      challenge = string.match(response, "AUTHENTICATE (.*)")
      dbg(3, "challenge found: %s", tostring(challenge))
      if challenge then status = false end
    until (not status)
    local msg = self.saslencoder:encode(username, password, challenge)

    -- SASL PLAIN is supposed to be plaintext, but freenode actually wants it to be base64 encoded
    if self.saslencoder:get_mechanism() == "PLAIN" then
      msg = base64.enc(msg)
    end

    local status, data = self.socket:send("AUTHENTICATE "..msg.."\r\n")
    local success = false

    if ( not(status) ) then
      local err = brute.Error:new( data )
      -- This might be temporary, set the retry flag
      err:setRetry( true )
      return false, err
    end

    repeat
      status, response = self.socket:receive_lines(1)
      if ( status and string.find(response, "90[45]") ) then
        status = false
      end
      if ( status and string.find(response, "90[03]") ) then
        success = true
        status = false
      end
    until (not status)

    if (success) then
      return true, creds.Account:new(username, password, creds.State.VALID)
    end
    return false, brute.Error:new("Incorrect username or password")
  end,

  disconnect = function(self) return self.socket:close() end,
}

-- checks if server supports sasl authentication and if it does, also checks for supported
-- mechanisms
local function check_sasl(host, port)
  local s, r, opts, _ = comm.tryssl(host, port, "CAP REQ sasl\r\n", { timeout = 15000 } )

  repeat
    local status, lines = s:receive_lines(1)
    if string.find(lines, "ACK") then status = false end
    if string.find(lines, "NAK") then
      s:close()
      return false
    end
  until (not status)

  -- we know that sasl is supported, now check which mechanisms can be used
  local to_check = {"PLAIN", "DH-BLOWFISH", "NTLM", "CRAM-MD5", "DIGEST-MD5"}
  local supported = {}
  for _,m in ipairs(to_check) do
    s:send("AUTHENTICATE "..m.."\r\n")
    dbg(3, "checking mechanism %s", m)
    repeat
      local status, lines = s:receive_lines(1)
      if string.find(lines, "AUTHENTICATE") then
        s:send("AUTHENTICATE abort\r\n") -- it's not a real command, just to break the process
        -- wait till we get a message indicating failed authentication
        repeat
          status, lines = s:receive_lines(1)
          if string.find(lines, "90[45]") then status = false end
        until (not status)
        table.insert(supported, m)
        status = false
      elseif string.find(lines, "90[45]") then
        status = false
        break
      end
    until (not status)
  end
  s:close()
  return true, supported
end

action = function(host, port)
  local sasl_supported, mechs = check_sasl(host, port)
  if not sasl_supported then
    return stdnse.format_output(false, "Server doesn't support SASL authentication.")
  end

  local saslencoder = sasl.Helper:new()
  local sasl_mech

  -- check if the library supports any of the mechanisms we identified
  for _,m in ipairs(mechs) do
    if saslencoder:set_mechanism(m) then
      sasl_mech = m
      dbg(2, "supported mechanism found: %s", m)
      break
    end
  end
  local engine = brute.Engine:new(Driver, host, port, saslencoder)
  engine.options.script_name = SCRIPT_NAME
  engine.options.firstonly = true
  -- irc servers seem to be restrictive about too many connection attempts
  -- in a short time thus we need to limit the number of threads
  local threads = stdnse.get_script_args(("%s.threads"):format(SCRIPT_NAME))
  threads = tonumber(threads) or 2
  engine:setMaxThreads(threads)
  local status, accounts = engine:start()
  return accounts
end


