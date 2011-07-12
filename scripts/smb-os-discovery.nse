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
-- |   Domain name: lab.test.local
-- |   Forest name: test.local
-- |   FQDN: Sql2008.lab.test.local
-- |   NetBIOS computer name: SQL2008
-- |   NetBIOS domain name: LAB
-- |_  System time: 2011-04-20 13:34:06 UTC-5
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

function add_to_output(output_table, label, value, value_if_nil)
	if (value == nil and value_if_nil ~= nil) then
		value = value_if_nil
	end
	
	if (value ~= nil) then
		table.insert(output_table, string.format("%s: %s", label, value) )
	end
end

action = function(host)
	local response = {}
	local status, result = smb.get_os(host)

	if(status == false) then
		return stdnse.format_output(false, result)
	end
	
	local hostname_dns, is_domain_member, os_string, time_string
	if (result[ "fqdn" ]) then
		-- Pull the first part of the FQDN as the computer name
		hostname_dns = string.match( result[ "fqdn" ], "^([^.]+)%.?" )
		
		if (result[ "domain_dns" ]) then
			-- If the computer name doesn't match the domain name, the target is a domain member
			is_domain_member = ( result[ "fqdn" ] ~= result[ "domain_dns" ] )
		end
	end
	
	if (result['os'] and result['lanmanager']) then
		os_string = string.format( "%s (%s)", get_windows_version( result['os'] ), result['lanmanager'] )
	end
	if (result['date'] and result['timezone_str']) then
		time_string = string.format("%s %s", result['date'], result['timezone_str'])
	end
	
	
	add_to_output( response, "OS", os_string, "Unknown" )
	add_to_output( response, "Computer name", hostname_dns )
	
	if ( is_domain_member ) then
		add_to_output( response, "Domain name", result[ "domain_dns" ] )
		add_to_output( response, "Forest name", result[ "forest_dns" ] )
		add_to_output( response, "FQDN", result[ "fqdn" ] )
	end
	
	add_to_output( response, "NetBIOS computer name", result[ "server" ] )
	
	if ( is_domain_member ) then
		add_to_output( response, "NetBIOS domain name", result[ "domain" ] )
	else
		add_to_output( response, "Workgroup", result[ "workgroup" ], result[ "domain" ] )
	end
	
	add_to_output( response, "System time", time_string, "Unknown" )

	return stdnse.format_output(true, response)
end




