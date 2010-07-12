description = [[
Attempts to determine the operating system, computer name, domain, and current
time over the SMB protocol (ports 445 or 139).
This is done by starting a session with the anonymous 
account (or with a proper user account, if one is given; it likely doesn't make
a difference); in response to a session starting, the server will send back all this
information. 

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
they likely won't change the outcome in any meaningful way. 
]]

---
--@usage
-- nmap --script smb-os-discovery.nse -p445 127.0.0.1
-- sudo nmap -sU -sS --script smb-os-discovery.nse -p U:137,T:139 127.0.0.1
--
--@output
-- Host script results:
-- |  smb-os-discovery:
-- |  |  OS: Windows 2000 (Windows 2000 LAN Manager)
-- |  |  Name: WORKGROUP\RON-WIN2K-TEST
-- |_ |_ System time: 2009-11-09 14:33:39 UTC-6
-----------------------------------------------------------------------

author = "Ron Bowes"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}
dependencies = {"smb-brute"}

require 'smb'
require 'stdnse'

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

action = function(host)
	local response = {}
	local status, result = smb.get_os(host)

	if(status == false) then
		return stdnse.format_output(false, result)
	end

	table.insert(response, string.format("OS: %s (%s)", get_windows_version(result['os']), result['lanmanager']))
	table.insert(response, string.format("Name: %s\\%s", result['domain'], result['server']))
	table.insert(response, string.format("System time: %s %s", result['date'], result['timezone_str']))

	return stdnse.format_output(true, response)
end




