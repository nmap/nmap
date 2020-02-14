local shortport = require "shortport"
local stdnse = require "stdnse"
local brute = require "brute"
local creds = require "creds"

local libssh2_util = require "libssh2-utility"

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
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {
  'brute',
  'intrusive',
}

portrule = shortport.ssh

local arg_timeout = stdnse.get_script_args(SCRIPT_NAME .. ".timeout") or "5s"

Driver = {
  new = function (self, host, port, options)
    stdnse.debug(2, "creating brute driver")
    local o = {
      helper = libssh2_util.SSHConnection:new(),
    }
    setmetatable(o, self)
    self.__index = self
    o.host = host
    o.port = port
    o.options = options
    return o
  end,

  connect = function (self)
    local status, err = self.helper:connect_pcall(self.host, self.port)
    if not status then
      stdnse.debug(2, "libssh2 error: %s", self.helper.session)
      local err = brute.Error:new(self.helper.session)
      err:setReduce(true)
      return false, err
    elseif not self.helper.session then
      stdnse.debug(2, "failure to connect: %s", err)
      local err = brute.Error:new(err)
      err:setAbort(true)
      return false, err
    else
      self.helper:set_timeout(self.options.ssh_timeout)
      return true
    end
  end,

  login = function (self, username, password)
    stdnse.verbose(1, "Trying username/password pair: %s:%s", username, password)
    local status, resp = self.helper:password_auth(username, password)
    if status then
      return true, creds.Account:new(username, password, creds.State.VALID)
    end
    return false, brute.Error:new "Incorrect password"
  end,

  disconnect = function (self)
    return self.helper:disconnect()
  end,
}

local function password_auth_allowed (host, port)
  local helper = libssh2_util.SSHConnection:new()
  if not helper:connect(host, port) then
    return "Failed to connect to ssh server"
  end
  local methods = helper:list "root"
  if methods then
    for _, value in pairs(methods) do
      if value == "password" then
        return true
      end
    end
  end
  return false
end

function action (host, port)
  local timems = stdnse.parse_timespec(arg_timeout) --todo: use this!
  local ssh_timeout = 1000 * timems
  if password_auth_allowed(host, port) then
    local options = {
      ssh_timeout = ssh_timeout,
    }
    local engine = brute.Engine:new(Driver, host, port, options)
    engine.options.script_name = SCRIPT_NAME
    local _, result = engine:start()
    return result
  else
    return "Password authentication not allowed"
  end
end
