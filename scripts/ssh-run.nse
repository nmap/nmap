local stdnse = require "stdnse"
local shortport = require "shortport"
local libssh2_util = require "libssh2_util"

description = [[
Runs remote command on ssh server and returns command output.
]]

---
-- @usage nmap -p 22 -v -d --script=ssh-run --datadir=./ \
-- --script-args="ssh-run.cmd=ls -l /, ssh-run.username=myusername, ssh-run.password=mypassword" <target>
--
-- @output 
-- 22/tcp open  ssh     syn-ack 0
-- | run-remote: 
-- |   output: 
-- |     total 124
-- | drwxr-xr-x   2 root       root        4096 Jun 23 09:34 bin
-- | drwxr-xr-x   3 root       root        4096 Jun 19 12:42 boot
-- | drwxr-xr-x   2 root       root        4096 Feb  6  2013 cdrom
-- | drwxr-xr-x  16 root       root        4340 Jul 17 13:37 dev
-- | drwxr-xr-x 162 root       root       12288 Jul 20 12:10 etc
-- | drwxr-xr-x  15 root       root        4096 Jun 23 15:20 home
-- | ...
-- |_drwxr-xr-x  14 root       root        4096 Jun  6 14:58 var
--
-- @args ssh-run.username    Username to authenticate as
-- @args ssh-run.password    Password to use if using password authentication
-- @args ssh-run.privatekey    Privatekeyfile to use if using publickey authentication
-- @args ssh-run.passphrase    Passphrase for privatekey if using publickey authentication
-- @args ssh-run.cmd   Command to run on remote server


author = "Devin Bjelland"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {'intrusive'}

portrule = shortport.port_or_service(22, 'ssh')

local username = stdnse.get_script_args('ssh-run.username')
local cmd = stdnse.get_script_args('ssh-run.cmd')
local password = stdnse.get_script_args('ssh-run.password')
local privatekey = stdnse.get_script_args('ssh-run.privatekey')
local passphrase = stdnse.get_script_args('ssh-run.passphrase')

action = function (host, port)
  local conn = libssh2_util.SSHConnection:new()
  if not conn:connect(host, port) then
    return "Failed to connect to ssh server"
  end
  if username and password and cmd then
    if not conn:password_auth(username, password) then
      conn:disconnect()
      stdnse.verbose("Failed to authenticate")
      return "Authentication Failed"
    else
      stdnse.verbose("Authenticated")
    end
  elseif username and privatekey and cmd then
    if not conn:publickey_auth(username, privatekey, passphrase) then
      conn:disconnect()
      stdnse.verbose("Failed to authenticate")
      return "Authentication Failed"
    else
      stdnse.verbose("Authenticated")
    end

  else
    stdnse.verbose("Failed to specify credentials and command to run.")
    return "Failed to specify credentials and command to run."
  end
  stdnse.verbose("Running command: " .. cmd)
  local output,err_output = conn:run_remote(cmd)
  stdnse.verbose("Output of command: " .. output)
  local result = stdnse.output_table()
  result.output = {}
  table.insert(result.output, output)
  conn:disconnect()  
  return result
end
