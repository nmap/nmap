description = [[
Attempts to determine the operating system over the SMB protocol (ports 445 and
139).

Although the standard <code>smb*</code> script arguments can be used, 
they likely won't change the outcome in any meaningful way. 
]]

---
--@usage
-- nmap --script smb-os-discovery.nse -p445 127.0.0.1
-- sudo nmap -sU -sS --script smb-os-discovery.nse -p U:137,T:139 127.0.0.1
--
--@output
-- |  smb-os-discovery: Windows 2000
-- |  LAN Manager: Windows 2000 LAN Manager
-- |  Name: WORKGROUP\TEST1
-- |_ System time: 2008-09-09 20:55:55 UTC-5
-- 
-- @args smb* This script supports the <code>smbusername</code>,
-- <code>smbpassword</code>, <code>smbhash</code>, <code>smbguest</code>, and
-- <code>smbtype</code> script arguments of the <code>smb</code> module.
-----------------------------------------------------------------------

author = "Ron Bowes"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

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

	local state
	local status, err

	-- Start up SMB
	status, state = smb.start(host)

	if(status == false) then
		if(nmap.debugging() > 0) then
			return "ERROR: " .. state
		else
			return nil
		end
	end

	-- Negotiate protocol
	status, err = smb.negotiate_protocol(state)

	if(status == false) then
		stdnse.print_debug(2, "Negotiate session failed")
		smb.stop(state)
		if(nmap.debugging() > 0) then
			return "ERROR: " .. err
		else
			return nil
		end
	end

	-- Start a session
	status, err = smb.start_session(state, "")
	if(status == false) then
		smb.stop(state)
		if(nmap.debugging() > 0) then
			return "ERROR: " .. err
		else
			return nil
		end
	end

	-- Kill SMB
	smb.stop(state)

	return string.format("%s\nLAN Manager: %s\nName: %s\\%s\nSystem time: %s %s\n", get_windows_version(state['os']), state['lanmanager'], state['domain'], state['server'], state['date'], state['timezone_str'])
end


