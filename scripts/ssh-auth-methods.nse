local shortport = require "shortport"
local stdnse = require "stdnse"
local libssh2_util = require "libssh2-utility"
local rand = require "rand"

description = [[
Returns authentication methods that a SSH server supports.

This is in the "intrusive" category because it starts an authentication with a
username which may be invalid. The abandoned connection will likely be logged.
]]

---
-- @usage
--  nmap -p 22 --script ssh-auth-methods --script-args="ssh.user=<username>" <target>
--
-- @output
-- 22/tcp open  ssh     syn-ack
-- | ssh-auth-methods:
-- |   Supported authentication methods:
-- |     publickey
-- |_    password

author = "Devin Bjelland"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"auth", "intrusive"}

local username = stdnse.get_script_args("ssh.user") or rand.random_alpha(5)
portrule = shortport.ssh

function action (host, port)
  local result = stdnse.output_table()
  local helper = libssh2_util.SSHConnection:new()
  if not helper:connect(host, port) then
    return "Failed to connect to ssh server"
  end

  local authmethods = helper:list(username)

  result["Supported authentication methods"] = authmethods

  return result
end
