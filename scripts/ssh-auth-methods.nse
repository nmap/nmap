local shortport = require "shortport"
local stdnse = require "stdnse"
local libssh2 = require "libssh2"

description = [[
Returns authenication methods a ssh server supports.
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
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

local username = stdnse.get_script_args("ssh.user") or stdnse.generate_random_string(5)
portrule = shortport.port_or_service(22, 'ssh')

action = function (host, port)
  local result = stdnse.output_table()
  
  local session = libssh2.session_open(host, port.number)
  local authmethods = libssh2.userauth_list(session, username)
  
  result["Supported authentication methods"] = authmethods  

  return result
end
