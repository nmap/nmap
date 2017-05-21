local mysql = require "mysql"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Runs a query against a MySQL database and returns the results as a table.
]]

---
-- @usage
-- nmap -p 3306 <ip> --script mysql-query --script-args='query="<query>"[,username=<username>,password=<password>]'
--
-- @output
-- PORT     STATE SERVICE
-- 3306/tcp open  mysql
-- | mysql-query:
-- |   host       user
-- |   127.0.0.1  root
-- |   localhost  debian-sys-maint
-- |   localhost  root
-- |   ubu1110    root
-- |
-- |   Query: SELECT host, user FROM mysql.user
-- |_  User: root
--
-- @args mysql-query.query the query for which to return the results
-- @args mysql-query.username (optional) the username used to authenticate to the database server
-- @args mysql-query.password (optional) the password used to authenticate to the database server
-- @args mysql-query.noheaders do not display column headers (default: false)
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"auth", "discovery", "safe"}


dependencies = {"mysql-empty-password", "mysql-brute"}

portrule = shortport.port_or_service(3306, "mysql")

local arg_username  = stdnse.get_script_args(SCRIPT_NAME .. ".username")
local arg_password  = stdnse.get_script_args(SCRIPT_NAME .. ".password") or ""
local arg_query     = stdnse.get_script_args(SCRIPT_NAME .. ".query")
local arg_noheaders = stdnse.get_script_args(SCRIPT_NAME .. ".noheaders") or false

local function fail(err) return stdnse.format_output(false, err) end

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
  if ( not(arg_query) ) then
    stdnse.debug2("No query was given, aborting ...")
    return
  end

  local creds = getCredentials()
  if ( not(creds) ) then
    stdnse.debug2("No credentials were supplied, aborting ...")
    return
  end

  if ( arg_noheaders == '1' or arg_noheaders == 'true' ) then
    arg_noheaders = true
  else
    arg_noheaders = false
  end

  local result = {}
  local last_error

  for username, password in pairs(creds) do
    local socket = nmap.new_socket()
    if ( not(socket:connect(host, port)) ) then
      return fail("Failed to connect to server")
    end
    local status, response = mysqlLogin(socket, username, password)
    if ( status ) then
      local status, rs = mysql.sqlQuery( socket, arg_query )
      socket:close()
      if ( status ) then
        result = mysql.formatResultset(rs, { noheaders = arg_noheaders })
        result = ("%s\nQuery: %s\nUser: %s"):format(result, arg_query, username)
        last_error = nil
        break
      else
        last_error = rs
      end
    else
      socket:close()
    end
  end
  return stdnse.format_output(not last_error, last_error or result)
end
