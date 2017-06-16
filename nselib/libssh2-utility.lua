---
-- Utility functions for libssh2.
--
-- Provides helper class for the libssh2 binding that abstracts away 
-- details of running remote commands.
--
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
-- @class module
-- @name libssh2-utility

local stdnse = require "stdnse"

local libssh2 = stdnse.silent_require "libssh2"

SSHConnection = {}

---
-- Returns a new connection object.
--
-- @return A connection object.
function SSHConnection:new()
  local o = {}
  setmetatable(o, self)
  self.__index = self
  return o
end

---
-- Sets up a connection with a server.
--
-- @param host A host to connect to.
-- @param port A port to connect to.
-- @return true on success or nil on failure
function SSHConnection:connect(host, port)
  self.session = libssh2.session_open(host, port.number)
  if self.session then
    return true
  end
end


---
-- Sets up a connection with a server.
--
-- @param host A host to connect to.
-- @param port A port to connect to.
-- @return true on success or nil on failure
function SSHConnection:connect_pcall(host, port)
  local status, err 
  status, self.session, err = pcall(libssh2.session_open, host, port.number)
  return status, err
end

---
-- Runs a shell command on the remote host.
--
-- @param cmd A command to run.
-- @return The command output.
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

---
-- Attempts to authenticate using provided credentials.
--
-- @param username A username to authenticate as.
-- @param password A password to authenticate as.
-- @return true on success or false on failure.
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
  -- if not session then
  --   return false
  -- end
  -- if libssh2.userauth_password(session, username, password) then
  --   self.authenticated = true
  --   return true
  -- else
  --   return false
  -- end
end

---
-- Attempts to authenticate using provided publickey.
--
-- @param username A username to authenticate as.
-- @param privatekey_file A path to a privatekey.
-- @param passphrase A passphrase for the privatekey.
-- @return true on success or false on failure.
function SSHConnection:publickey_auth(username, privatekey_file, passphrase)
  if not passphrase then
    local passphrase = ""
  end
  if not self.session then
    return false
  end
  print(self.session)
  print(username)
  print(privatekey_file)
  if libssh2.userauth_publickey(self.session, username, privatekey_file, passphrase) then
    self.authenticated = true
    return true
  else
    return false
  end
end

---
-- Closes connection.
function SSHConnection:disconnect()
  if self.session then
    libssh2.session_close(self.session)
  end
end

---
-- Sends ssh timeout
function SSHConnection:set_timeout(ssh_timeout)
  if self.session then
    libssh2.set_timeout(self.session, ssh_timeout)
  end
end


function SSHConnection:list(username)
  if not self.session then
    return false
  end
  local status, methods = pcall(libssh2.userauth_list, self.session, username)
  if status then
    return methods
  end
  return false
end


function SSHConnection:read_publickey(publickey)
  local status, result  = pcall(libssh2.read_publickey, publickey)
  return status, result
end


function SSHConnection:publickey_canauth(username, result)
  if self.session then
  libssh2.publickey_canauth(self.session, username, result)
  end
end

return _ENV;


