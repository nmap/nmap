local mysql = require "mysql"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Checks for MySQL servers with an empty password for <code>root</code> or
<code>anonymous</code>.
]]

---
-- @see mysql-brute.nse
--
-- @output
-- 3306/tcp open  mysql
-- | mysql-empty-password:
-- |   anonymous account has empty password
-- |_  root account has empty password

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "auth"}


-- Version 0.3
-- Created 01/15/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 01/23/2010 - v0.2 - revised by Patrik Karlsson, added anonymous account check
-- Revised 01/23/2010 - v0.3 - revised by Patrik Karlsson, fixed abort bug due to try of loginrequest

portrule = shortport.port_or_service(3306, "mysql")

action = function( host, port )

  local socket = nmap.new_socket()
  local result = {}
  local users = {"", "root"}

  -- set a reasonable timeout value
  socket:set_timeout(5000)

  for _, v in ipairs( users ) do
    local status, response = socket:connect(host, port)
    if( not(status) ) then return stdnse.format_output(false, "Failed to connect to mysql server") end

    status, response = mysql.receiveGreeting( socket )
    if ( not(status) ) then
      stdnse.debug3("%s", SCRIPT_NAME)
      socket:close()
      return response
    end

    status, response = mysql.loginRequest( socket, { authversion = "post41", charset = response.charset }, v, nil, response.salt )
    if response.errorcode == 0 then
      table.insert(result, string.format("%s account has empty password", ( v=="" and "anonymous" or v ) ) )
      if nmap.registry.mysqlusers == nil then
        nmap.registry.mysqlusers = {}
      end
      nmap.registry.mysqlusers[v=="" and "anonymous" or v] = ""
    end
    socket:close()
  end

  return stdnse.format_output(true, result)

end
