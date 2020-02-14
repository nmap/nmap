local stdnse = require "stdnse"
local shortport = require "shortport"
local stringaux = require "stringaux"
local table = require "table"
local libssh2_util = require "libssh2-utility"

description = [[
Runs remote command on ssh server and returns command output.
]]

---
-- @usage nmap -p 22 --script=ssh-run \
-- --script-args="ssh-run.cmd=ls -l /, ssh-run.username=myusername, ssh-run.password=mypassword" <target>
--
-- @output
-- 22/tcp open  ssh
-- | ssh-run:
-- |   output:
-- |     total 91
-- |     drwxr-xr-x   2 root root  4096 Jun  5 11:56 bin
-- |     drwxr-xr-x   4 root root  3072 Jun  5 12:42 boot
-- |     drwxrwxr-x   2 root root  4096 Jun 22  2017 cdrom
-- |     drwxr-xr-x  20 root root  4060 Jun 23 10:26 dev
-- |     drwxr-xr-x 127 root root 12288 Jun  5 11:56 etc
-- |     drwxr-xr-x   3 root root  4096 Jun 22  2017 home
-- ....
-- |_    drwxr-xr-x  13 root root  4096 Jul 20  2016 var
--
-- @xmloutput
-- <elem key="output">total 91\x0D&#xa;drwxr-xr-x   2 root root  4096 Jun  5 11:56 bin\x0D&#xa;drwxr-xr-x   4 root root  3072 Jun  5 12:42 boot\x0D&#xa;drwxrwxr-x   2 root root  4096 Jun 22  2017 cdrom\x0D&#xa;drwxr-xr-x  20 root root  4060 Jun 23 10:26 dev\x0D&#xa;drwxr-xr-x 127 root root 12288 Jun  5 11:56 etc\x0D&#xa;drwxr-xr-x   3 root root  4096 Jun 22  2017 home\x0D&#xa;....\x0D&#xa;drwxr-xr-x  13 root root  4096 Jul 20  2016 var\x0D&#xa;</elem>
--
-- @args ssh-run.username    Username to authenticate as
-- @args ssh-run.password    Password to use if using password authentication
-- @args ssh-run.privatekey    Privatekeyfile to use if using publickey authentication
-- @args ssh-run.passphrase    Passphrase for privatekey if using publickey authentication
-- @args ssh-run.cmd   Command to run on remote server


author = "Devin Bjelland"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {
  'intrusive',
}

portrule = shortport.ssh

local username = stdnse.get_script_args 'ssh-run.username'
local cmd = stdnse.get_script_args 'ssh-run.cmd'
local password = stdnse.get_script_args 'ssh-run.password'
local privatekey = stdnse.get_script_args 'ssh-run.privatekey'
local passphrase = stdnse.get_script_args 'ssh-run.passphrase'

local function remove_tabs (str, tabsize)
tabsize = tabsize or 8
local out = str:gsub("(.-)\t", function (s)
                                 return s .. (" "):rep(tabsize - #s % tabsize)
                               end)
  return out
end

function action (host, port)
  local conn = libssh2_util.SSHConnection:new()
  if not conn:connect(host, port) then
    return "Failed to connect to ssh server"
  end
  if username and password and cmd then
    if not conn:password_auth(username, password) then
      conn:disconnect()
      stdnse.verbose "Failed to authenticate"
      return "Authentication Failed"
    else
      stdnse.verbose "Authenticated"
    end
  elseif username and privatekey and cmd then
    if not conn:publickey_auth(username, privatekey, passphrase) then
      conn:disconnect()
      stdnse.verbose "Failed to authenticate"
      return "Authentication Failed"
    else
      stdnse.verbose "Authenticated"
    end

  else
    stdnse.verbose "Failed to specify credentials and command to run."
    return "Failed to specify credentials and command to run."
  end
  stdnse.verbose("Running command: " .. cmd)
  local output, err_output = conn:run_remote(cmd)
  stdnse.verbose("Output of command: " .. output)

  local out = stdnse.output_table()
  out.output = output

  local txtout = {}
  for _, line in ipairs(stringaux.strsplit("\r?\n", output:gsub("\r?\n$", ""))) do
    local str = line:gsub("[^\t\x20-\x7f]", "")
    table.insert(txtout, remove_tabs(str))
  end
  txtout.name = "output:"

  return out, stdnse.format_output(true, {txtout})
end
