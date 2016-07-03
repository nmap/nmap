local shortport = require "shortport"
local stdnse = require "stdnse"
local brute = require "brute"
local creds = require "creds"

local libssh2 = stdnse.silent_require "libssh2"

description = [[
Performs brute-force password guessing against ssh servers.
]]

---
-- @usage
--   nmap -p 22 --script ssh-brute --script-args userdb=users.lst,passdb=pass.lst \
--       --script-args ssh-brute.timeout=4s <target>
--
-- @output
-- 22/ssh open  ssh
-- | ssh-brute:
-- |  Accounts
-- |    username:password
-- |  Statistics
-- |_   Performed 32 guesses in 25 seconds.
--
-- @args ssh-brute.timeout    Connection timeout (default: "5s")

author = "Devin Bjelland"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {'brute', 'intrusive'}

portrule = shortport.port_or_service(22, 'ssh')

local arg_timeout = stdnse.get_script_args(SCRIPT_NAME .. ".timeout") or "5s"

Driver = {
  new = function(self, host, port, options)
    stdnse.debug(2, "creating brute driver")
    local o = {}
    setmetatable(o, self)
    self.__index = self
    o.host = host
    o.port = port
    o.options = options
    return o
  end,

  connect = function (self)
    stdnse.debug(2, "connecting to %s:%d", self.host.ip, self.port.number)
    local status, session, err = pcall(libssh2.session_open, self.host, self.port.number)
    if not status then
      stdnse.debug(2, "libssh2 error: %s", session)
      local err = brute.Error:new(session)
      err:setAbort(true)
      return false, err
    elseif not session then
      stdnse.debug(2, "failure to connect: %s", err);
      local err = brute.Error:new(err)
      err:setAbort(true)
      return false, err
    else
      self.ssh_session = session
      libssh2.set_timeout(self.ssh_session, self.options.ssh_timeout)
      return true
    end
  end,

  disconnect = function(self)
    stdnse.debug(2, "disconnecting from %s:%d", self.host.ip, self.port.number);
    local status, err = pcall(libssh2.session_close, self.ssh_session)
    if not status then
      stdnse.debug(2, "libssh2 error: %s", ok)
    end
  end,

  login = function(self, username, password)
    stdnse.verbose(2, "Trying username/password pair: %s:%s", username, password)
    local status, ok = pcall(libssh2.userauth_password, self.ssh_session, username, password)
    if not status then
      stdnse.debug(2, "libssh2 error: %s", ok)
      return false, brute.Error:new(ok)
    elseif not ok then
      stdnse.debug(2, "login failed for %s:%s", username, password)
      return false, brute.Error:new("login failed")
    else
      stdnse.verbose(1, "Found working Credentials: %s:%s", username, password)
      return true, creds.Account:new(username, password, "OPEN")
    end
  end,
}

password_auth_allowed = function (host, port)
  local status, ssh_session = pcall(libssh2.session_open, host, port.number)
  if status and ssh_session then
    local status, methods = pcall(libssh2.userauth_list, ssh_session, "root")
    if status then
      for _, value in pairs(methods) do
        if value == "password" then
            return true
        end  
      end
    end
  end
  return false
end

action = function (host, port)
  local timems = stdnse.parse_timespec(arg_timeout) --todo: use this!
  local ssh_timeout = 1000 * timems
  if password_auth_allowed(host, port) then 
    local options = {ssh_timeout = ssh_timeout}  
    local engine = brute.Engine:new(Driver, host, port, options)
    engine.options.script_name = SCRIPT_NAME
    local _, result = engine:start()
    return result
  else
    return "Password authenication not allowed" 
  end
end

