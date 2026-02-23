local mysql = require "mysql"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Dumps the password hashes from an MySQL server in a format suitable for
cracking by tools such as John the Ripper.  Appropriate DB privileges (root) are required.

The <code>username</code> and <code>password</code> arguments take precedence
over credentials discovered by the mysql-brute and mysql-empty-password
scripts.
]]

---
-- @usage
-- nmap -p 3306 <ip> --script mysql-dump-hashes --script-args='username=root,password=secret'
--
-- @output
-- PORT     STATE SERVICE
-- 3306/tcp open  mysql
-- | mysql-dump-hashes:
-- |   root:*9B500343BC52E2911172EB52AE5CF4847604C6E5
-- |   debian-sys-maint:*92357EE43977D9228AC9C0D60BB4B4479BD7A337
-- |_  toor:*14E65567ABDB5135D0CFD9A70B3032C179A49EE7
--
-- @args username the username to use to connect to the server
-- @args password the password to use to connect to the server
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"auth", "discovery", "safe"}


dependencies = {"mysql-empty-password", "mysql-brute"}

portrule = shortport.port_or_service(3306, "mysql")

local arg_username = stdnse.get_script_args(SCRIPT_NAME .. ".username")
local arg_password = stdnse.get_script_args(SCRIPT_NAME .. ".password") or ""

local function getCredentials()
  -- first, let's see if the script has any credentials as arguments?
  if arg_username then
    return { [arg_username] = arg_password }
  -- next, let's see if mysql-brute or mysql-empty-password brought us anything
  elseif nmap.registry.mysqlusers then
    -- do we have root credentials?
    if nmap.registry.mysqlusers['root'] then
      return { ['root'] = nmap.registry.mysqlusers['root'] }
    else
      -- we didn't have root, so let's make sure we loop over them all
      return nmap.registry.mysqlusers
    end
  -- last, no dice, we don't have any credentials at all
  end
end


action = function (host, port)
  local creds = getCredentials()
  if not creds then
    socket:close()
    stdnse.debug2("No credentials were supplied, aborting ...")
    return
  end

  for username, password in pairs(creds) do
    local socket = nmap.new_socket()
    if not socket:connect(host, port) then
      socket:close()
      return stdnse.format_output(false, "Failed to connect to server")
    end

    local status, response = mysql.receiveGreeting(socket)
    if status then
      status = mysql.loginRequest(socket, {authversion = "post41", charset = response.charset}, username, password, response.salt)
    end
    if status then
      local auth_field = "authentication_string"
      -- the 'authentication_string' field was called 'password' in MySQL 5.6, and earlier
      if tonumber(response.version:sub(1, 3)) <= 5.6 then
        auth_field = "password"
      end
      local query = "SELECT DISTINCT CONCAT(user, ':', " .. auth_field .. ") FROM mysql.user WHERE " .. auth_field .. " <> ''"
      local status, rows = mysql.sqlQuery( socket, query )
      if status then
        socket:close()
        return stdnse.format_output(true, mysql.formatResultset(rows, {noheaders = true}))
      end
    end
    socket:close()
  end
end
