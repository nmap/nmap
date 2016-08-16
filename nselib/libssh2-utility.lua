-- Provides helper class for the libssh2 binding that abstracts away details of
-- running remote commands
local stdnse = require "stdnse"

local libssh2 = stdnse.silent_require "libssh2"

SSHConnection = {}

function SSHConnection:new()
  local o = {}
  setmetatable(o, self)
  self.__index = self
  return o
end

function SSHConnection:connect(host, port)
  self.session = libssh2.session_open(host, port.number)
  if self.session then
    return true
  end
end

function SSHConnection:run_remote(cmd)
  if not (self.session and self.authenticated) then
    return false
  end  
  local channel = libssh2.open_channel(self.session)
  libssh2.channel_exec(self.session, channel, cmd) 
  libssh2.channel_send_eof(self.session, channel)
  local buff = ""
  local data = ""
  while not libssh2.channel_eof(channel) do
    data = libssh2.channel_read(self.session, channel)
    if data then
      buff = buff .. data
    end
  end
  return buff
end

function SSHConnection:password_auth(username, password)
  if not self.session then
    return false
  end
  if libssh2.userauth_password(self.session, username, password) then
    self.authenticated = true
    return true
  else
    return false
  end
end

function SSHConnection:publickey_auth(username, privatekey_file, passphrase)
  if not passphrase then
    local passphrase = ""
  end
  if libssh2.userauth_publickey(self.session, username, privatekey_file, passphrase) then
    self.authenticated = true
    return true
  end
end

function SSHConnection:disconnect()
  if self.session then
    libssh2.session_close(self.session)
  end
end

return _ENV;

