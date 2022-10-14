local _G = require "_G"
local mysql = require "mysql"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Audits MySQL database server security configuration against parts of
the CIS MySQL v1.0.2 benchmark (the engine can be used for other MySQL
audits by creating appropriate audit files).
]]


---
-- @usage
-- nmap -p 3306 --script mysql-audit --script-args "mysql-audit.username='root', \
--   mysql-audit.password='foobar',mysql-audit.filename='nselib/data/mysql-cis.audit'"
--
-- @args mysql-audit.username the username with which to connect to the database
-- @args mysql-audit.password the password with which to connect to the database
-- @args mysql-audit.filename the name of the file containing the audit rulebase, "mysql-cis.audit" by default
--
-- @output
-- PORT     STATE SERVICE
-- 3306/tcp open  mysql
-- | mysql-audit:
-- |   CIS MySQL Benchmarks v1.0.2
-- |       3.1: Skip symbolic links => PASS
-- |       3.2: Logs not on system partition => PASS
-- |       3.2: Logs not on database partition => PASS
-- |       4.1: Supported version of MySQL => REVIEW
-- |         Version: 5.1.54-1ubuntu4
-- |       4.4: Remove test database => PASS
-- |       4.5: Change admin account name => FAIL
-- |       4.7: Verify Secure Password Hashes => PASS
-- |       4.9: Wildcards in user hostname => FAIL
-- |         The following users were found with wildcards in hostname
-- |           root
-- |           super
-- |           super2
-- |       4.10: No blank passwords => PASS
-- |       4.11: Anonymous account => PASS
-- |       5.1: Access to mysql database => REVIEW
-- |         Verify the following users that have access to the MySQL database
-- |           user              host
-- |           root              localhost
-- |           root              patrik-11
-- |           root              127.0.0.1
-- |           debian-sys-maint  localhost
-- |           root              %
-- |           super             %
-- |       5.2: Do not grant FILE privileges to non Admin users => REVIEW
-- |         The following users were found having the FILE privilege
-- |           super
-- |           super2
-- |       5.3: Do not grant PROCESS privileges to non Admin users => REVIEW
-- |         The following users were found having the PROCESS privilege
-- |           super
-- |       5.4: Do not grant SUPER privileges to non Admin users => REVIEW
-- |         The following users were found having the SUPER privilege
-- |           super
-- |       5.5: Do not grant SHUTDOWN privileges to non Admin users => REVIEW
-- |         The following users were found having the SHUTDOWN privilege
-- |           super
-- |       5.6: Do not grant CREATE USER privileges to non Admin users => REVIEW
-- |         The following users were found having the CREATE USER privilege
-- |           super
-- |       5.7: Do not grant RELOAD privileges to non Admin users => REVIEW
-- |         The following users were found having the RELOAD privilege
-- |           super
-- |       5.8: Do not grant GRANT privileges to non Admin users => PASS
-- |       6.2: Disable Load data local => FAIL
-- |       6.3: Disable old password hashing => PASS
-- |       6.4: Safe show database => FAIL
-- |       6.5: Secure auth => FAIL
-- |       6.6: Grant tables => FAIL
-- |       6.7: Skip merge => FAIL
-- |       6.8: Skip networking => FAIL
-- |       6.9: Safe user create => FAIL
-- |       6.10: Skip symbolic links => FAIL
-- |
-- |_      The audit was performed using the db-account: root

-- Version 0.1
-- Created 05/29/2011 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}


portrule = shortport.port_or_service(3306, "mysql")
local TEMPLATE_NAME, ADMIN_ACCOUNTS = "", ""

local function fail (err) return stdnse.format_output(false, err) end

local function loadAuditRulebase( filename )
  local rules = {}

  local env = setmetatable({
    test = function(t) table.insert(rules, t) end;
  }, {__index = _G})

  filename = nmap.fetchfile("nselib/data/" .. filename) or filename
  stdnse.debug(1, "Loading rules from: %s", filename)
  local file, err = loadfile(filename, "t", env)

  if ( not(file) ) then
    return false, fail(("Failed to load rulebase:\n%s"):format(err))
  end


  file()
  TEMPLATE_NAME = env.TEMPLATE_NAME
  ADMIN_ACCOUNTS = env.ADMIN_ACCOUNTS
  return true, rules
end

action = function( host, port )

  local username = stdnse.get_script_args("mysql-audit.username")
  local password = stdnse.get_script_args("mysql-audit.password")
  local filename = stdnse.get_script_args("mysql-audit.filename") or "mysql-cis.audit"

  if ( not(username) ) then
    return fail("No username was supplied (see mysql-audit.username)")
  end

  local status, tests = loadAuditRulebase( filename )
  if( not(status) ) then return tests end

  local socket = nmap.new_socket()
  status = socket:connect(host, port)

  local response
  status, response = mysql.receiveGreeting( socket )
  if ( not(status) ) then return response end

  status, response = mysql.loginRequest( socket, { authversion = "post41", charset = response.charset }, username, password, response.salt )

  if ( not(status) ) then return fail("Failed to authenticate") end
  local results = {}

  for _, test in ipairs(tests) do
    local queries = ( "string" == type(test.sql) ) and { test.sql } or test.sql
    local rowstab = {}

    for _, query in ipairs(queries) do
      local row
      status, row = mysql.sqlQuery( socket, query )
      if ( not(status) ) then
        table.insert( results, { ("%s: ERROR: Failed to execute SQL statement"):format(test.id) } )
      else
        table.insert(rowstab, row)
      end
    end

    if ( #rowstab > 0 ) then
      local result_part = {}
      local res = test.check(rowstab)
      local status, data = res.status, res.result
      status = ( res.review and "REVIEW" ) or (status and "PASS" or "FAIL")

      table.insert( result_part, ("%s: %s => %s"):format(test.id, test.desc, status) )
      if ( data ) then
        table.insert(result_part, { data } )
      end
      table.insert( results, result_part )
    end
  end

  socket:close()
  results.name = TEMPLATE_NAME

  table.insert(results, "")
  table.insert(results, {name = "Additional information", ("The audit was performed using the db-account: %s"):format(username),
    ("The following admin accounts were excluded from the audit: %s"):format(table.concat(ADMIN_ACCOUNTS, ","))
  })

return stdnse.format_output(true, { results })
end
