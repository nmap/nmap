local smb = require "smb"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local math = require "math"
local os = require "os"

description = [[
Attempts to determine the operating system, computer name, domain, workgroup, and current
time over the SMB protocol (ports 445 or 139).
This is done by starting a session with the anonymous 
account (or with a proper user account, if one is given; it likely doesn't make
a difference); in response to a session starting, the server will send back all this
information.

The following fields may be included in the output, depending on the 
cirumstances (e.g. the workgroup name is mutually exclusive with domain and forest
names) and the information available:
* OS
* Computer name
* Domain name
* Forest name
* FQDN
* NetBIOS computer name
* NetBIOS domain name
* Workgroup
* System time

Some systems, like Samba, will blank out their name (and only send their domain). 
Other systems (like embedded printers) will simply leave out the information. Other
systems will blank out various pieces (some will send back 0 for the current
time, for example). 

Retrieving the name and operating system of a server is a vital step in targeting
an attack against it, and this script makes that retrieval easy. Additionally, if
a penetration tester is choosing between multiple targets, the time can help identify
servers that are being poorly maintained (for more information/random thoughts on
using the time, see http://www.skullsecurity.org/blog/?p=76. 

Although the standard <code>smb*</code> script arguments can be used, 
they likely won't change the outcome in any meaningful way. However, <code>smbnoguest</code>
will speed up the script on targets that do not allow guest access.
]]

---
--@usage
-- nmap --script smb-os-discovery.nse -p445 127.0.0.1
-- sudo nmap -sU -sS --script smb-os-discovery.nse -p U:137,T:139 127.0.0.1
--
--@output
-- Host script results:
-- | smb-os-discovery:
-- |   OS: Windows Server (R) 2008 Standard 6001 Service Pack 1 (Windows Server (R) 2008 Standard 6.0)
-- |   Computer name: Sql2008
-- |   NetBIOS computer name: SQL2008
-- |   Domain name: lab.test.local
-- |   Forest name: test.local
-- |   FQDN: Sql2008.lab.test.local
-- |   NetBIOS domain name: LAB
-- |_  System time: 2011-04-20T13:34:06-05:00
--
--@xmloutput
-- <elem key="os">Windows Server (R) 2008 Standard 6001 Service Pack 1</elem>
-- <elem key="lanmanager">Windows Server (R) 2008 Standard 6.0</elem>
-- <elem key="domain">LAB</elem>
-- <elem key="server">SQL2008</elem>
-- <elem key="date">2011-04-20T13:34:06-05:00</elem>
-- <elem key="fqdn">Sql2008.lab.test.local</elem>
-- <elem key="domain_dns">lab.test.local</elem>
-- <elem key="forest_dns">test.local</elem>

author = "Ron Bowes"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}
dependencies = {"smb-brute"}


--- Check whether or not this script should be run.
hostrule = function(host)
	return smb.get_port(host) ~= nil
end

--- Converts numbered Windows version strings (<code>"Windows 5.0"</code>, <code>"Windows 5.1"</code>) to names (<code>"Windows 2000"</code>, <code>"Windows XP"</code>). 
--@param os The numbered OS version.
--@return The actual name of the OS (or the same as the <code>os</code> parameter if no match was found).
function get_windows_version(os)

	if(os == "Windows 5.0") then
		return "Windows 2000"
	elseif(os == "Windows 5.1")then
		return "Windows XP"
	end

	return os

end

function add_to_output(output_table, label, value)
	if value then
		table.insert(output_table, string.format("%s: %s", label, value))
	end
end

action = function(host)
	local response = stdnse.output_table()
	local status, result = smb.get_os(host)

	if(status == false) then
		return stdnse.format_output(false, result)
	end
	
	-- Collect results.
	response.os = result.os
	response.lanmanager = result.lanmanager
	response.domain = result.domain
	response.server = result.server
	if result.time and result.timezone then
		response.date = stdnse.format_timestamp(result.time, result.timezone * 60 * 60)
	end
	response.fqdn = result.fqdn
	response.domain_dns = result.domain_dns
	response.forest_dns = result.forest_dns
	response.workgroup = result.workgroup
	
	-- Build normal output.
	local output_lines = {}
	if response.os and response.lanmanager then
		add_to_output(output_lines, "OS", string.format("%s (%s)", get_windows_version(response.os), response.lanmanager))
	else
		add_to_output(output_lines, "OS", "Unknown")
	end
	if response.fqdn then
		-- Pull the first part of the FQDN as the computer name.
		add_to_output(output_lines, "Computer name", string.match(response.fqdn, "^([^.]+)%.?"))
	end
	add_to_output(output_lines, "NetBIOS computer name", result.server)
	if response.fqdn and response.domain_dns and response.fqdn ~= response.domain_dns then
		-- If the FQDN doesn't match the domain name, the target is a domain member.
		add_to_output(output_lines, "Domain name", response.domain_dns)
		add_to_output(output_lines, "Forest name", response.forest_dns)
		add_to_output(output_lines, "FQDN", response.fqdn)
		add_to_output(output_lines, "NetBIOS domain name", response.domain)
	else
		add_to_output(output_lines, "Workgroup", response.workgroup or response.domain)
	end
	add_to_output(output_lines, "System time", response.date or "Unknown")

	return response, stdnse.format_output(true, output_lines)
end




