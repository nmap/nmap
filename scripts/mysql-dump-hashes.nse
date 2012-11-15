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
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"auth", "discovery", "safe"}


dependencies = {"mysql-empty-password", "mysql-brute"}

portrule = shortport.port_or_service(3306, "mysql")

local arg_username = stdnse.get_script_args(SCRIPT_NAME .. ".username")
local arg_password = stdnse.get_script_args(SCRIPT_NAME .. ".password") or ""

local function fail(err) return ("\n  ERROR: %s"):format(err or "") end

local function getCredentials()
	-- first, let's see if the script has any credentials as arguments?
	if ( arg_username ) then
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

local function mysqlLogin(socket, username, password)
	local status, response = mysql.receiveGreeting( socket )
	if ( not(status) ) then
		return response
	end
	return mysql.loginRequest( socket, { authversion = "post41", charset = response.charset }, username, password, response.salt )
end
	

action = function(host, port)
	local creds = getCredentials()
	if ( not(creds) ) then
		stdnse.print_debug(2, "No credentials were supplied, aborting ...")
		return
	end

	local result = {}
	for username, password in pairs(creds) do
		local socket = nmap.new_socket()
		if ( not(socket:connect(host, port)) ) then
			return fail("Failed to connect to server")
		end
		
		local status, response = mysqlLogin(socket, username, password)
		if ( status ) then
			local query = "SELECT DISTINCT CONCAT(user, ':', password) FROM mysql.user WHERE password <> ''"
			local status, rows = mysql.sqlQuery( socket, query )
			socket:close()
			if ( status ) then
				result = mysql.formatResultset(rows, { noheaders = true })
				break
			end
		else
			socket:close()
		end
	end
	
	if ( result ) then
		return stdnse.format_output(true, result)
	end
end
