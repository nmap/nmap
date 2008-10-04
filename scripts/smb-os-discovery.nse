--- Attempts to determine the operating system over SMB protocol (ports 445 and 139). 
--  See nselib/smb.lua for more information on this protocol. 
--
--@usage
-- nmap --script smb-os-discovery.nse -p445 127.0.0.1\n
-- sudo nmap -sU -sS --script smb-os-discovery.nse -p U:137,T:139 127.0.0.1\n
--
--@output
-- |  OS from SMB: Windows 2000\n
-- |  LAN Manager: Windows 2000 LAN Manager\n
-- |  Name: WORKGROUP\TEST1\n
-- |_ System time: 2008-09-09 20:55:55 UTC-5\n
-- 
-----------------------------------------------------------------------

id = "OS from SMB"
description = "Attempts to determine the operating system over the SMB protocol (ports 445 and 139)."
author = "Ron Bowes"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}

require 'smb'
require 'stdnse'

--- Check whether or not this script should be run.
hostrule = function(host)

	local port = smb.get_port(host)

	if(port == nil) then
		return false
	else
		return true
	end

end

--- Converts numbered Windows versions (5.0, 5.1) to the names (Windows 2000, Windows XP). 
--@param os The name of the OS
--@return The actual name of the OS (or the same as the 'os' parameter)
function get_windows_version(os)

	if(os == "Windows 5.0") then
		return "Windows 2000"
	elseif(os == "Windows 5.1")then
		return "Windows XP"
	end

	return os

end

action = function(host)

	-- Start up SMB
	status, socket = smb.start(host)
	if(status == false) then
		return "Error: " .. socket
	end

	-- Negotiate protocol
	status, negotiate_result = smb.negotiate_protocol(socket)
	if(status == false) then
		stdnse.print_debug(2, "Negotiate session failed")
		smb.stop(socket)
		return "Error: " .. negotiate_result
	end

	-- Start a session
	status, session_result = smb.start_session(socket, "", negotiate_result['session_key'], negotiate_result['capabilities'])
	if(status == false) then
		smb.stop(socket)
		return "Error: " .. session_result
	end

	-- Kill SMB
	smb.stop(socket, session_result['uid'])

	return string.format("%s\nLAN Manager: %s\nName: %s\\%s\nSystem time: %s %s\n", get_windows_version(session_result['os']), session_result['lanmanager'], negotiate_result['domain'], negotiate_result['server'], negotiate_result['date'], negotiate_result['timezone_str'])
end


