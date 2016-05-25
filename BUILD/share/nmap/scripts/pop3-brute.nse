local brute = require "brute"
local comm = require "comm"
local creds = require "creds"
local nmap = require "nmap"
local pop3 = require "pop3"
local shortport = require "shortport"
local string = require "string"

description = [[
Tries to log into a POP3 account by guessing usernames and passwords.
]]

---
-- @args pop3loginmethod The login method to use: <code>"USER"</code>
-- (default), <code>"SASL-PLAIN"</code>, <code>"SASL-LOGIN"</code>,
-- <code>"SASL-CRAM-MD5"</code>, or <code>"APOP"</code>. Defaults to <code>"USER"</code>,
--
-- @output
-- PORT    STATE SERVICE
-- 110/tcp open  pop3
-- | pop3-brute-ported:
-- | Accounts:
-- |  user:pass => Login correct
-- | Statistics:
-- |_ Performed 8 scans in 1 seconds, average tps: 8

author = "Philip Pickering, Piotr Olma"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"intrusive", "brute"}

Driver = {
  new = function(self, host, port, login_function, is_apop)
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.port = port
    o.host = host
    o.login_function = login_function
    o.is_apop = is_apop
    return o
  end,

  -- Attempts to connect to the POP server
  -- @return true on success
  -- @return false, brute.Error object on failure
  connect = function(self)

    self.socket = nmap.new_socket()
    local opts = {timeout=10000, recv_before=true}
    local best_opt, line, _
    self.socket, _, best_opt, line = comm.tryssl(self.host, self.port, "" , opts)

    if not self.socket then
      local err = brute.Error:new("Failed to connect.")
      err:setAbort(true)
      return false, err
    end --no connection
    if not pop3.stat(line) then
      local err = brute.Error:new("Failed to make a pop-connection.")
      err:setAbort(true)
      return false, err
    end -- no pop-connection

    if self.is_apop then
      self.additional = string.match(line, "<[%p%w]+>") --apop challenge
    end
    return true
  end, --connect

  -- Attempts to login to the POP server
  --
  -- @param username string containing the login username
  -- @param password string containing the login password
  -- @return status, true on success, false on failure
  -- @return brute.Error object on failure
  --         creds.Account object on success
  login = function(self, username, password)
    local pstatus
    local perror
    pstatus, perror = self.login_function(self.socket, username, password, self.additional)
    if pstatus then
      return true, creds.Account:new(username, password, creds.State.VALID)
    elseif (perror == pop3.err.pwError) then
      return false, brute.Error:new("Wrong password.")
    elseif (perror == pop3.err.userError) then
      return false, brute.Error:new("Wrong username.")
    end
    return false, brute.Error:new("Login failed.")
  end, --login

  disconnect = function(self)
    self.socket:close()
  end, --disconnect

  check = function(self)
    return true
  end, --check
}

portrule = shortport.port_or_service({110, 995}, {"pop3","pop3s"})

action = function(host, port)
  local pMeth = nmap.registry.args.pop3loginmethod
  if (not pMeth) then pMeth = nmap.registry.pop3loginmethod end
  if (not pMeth) then pMeth = "USER" end

  --determine function we will use to login to server
  local is_apop = false
  local login_function
  if (pMeth == "USER") then
    login_function = pop3.login_user
  elseif (pMeth == "SASL-PLAIN") then
    login_function = pop3.login_sasl_plain
  elseif (pMeth == "SASL-LOGIN") then
    login_function = pop3.login_sasl_login
  elseif (pMeth == "SASL-CRAM-MD5") then
    login_function = pop3.login_sasl_crammd5
  elseif (pMeth == "APOP") then
    login_function = pop3.login_apop
    is_apop = true
  else
    login_function = pop3.login_user
  end

  local engine = brute.Engine:new(Driver, host, port, login_function, is_apop)
  engine.options.script_name = SCRIPT_NAME
  local status, accounts = engine:start()
  return accounts
end
