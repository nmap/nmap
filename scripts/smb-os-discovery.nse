id = "OS from SMB"
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
-- |  OS from SMB: Windows 2000
-- |  LAN Manager: Windows 2000 LAN Manager
-- |  Name: WORKGROUP\TEST1
-- |_ System time: 2008-09-09 20:55:55 UTC-5
-- 
--@args  smbusername The SMB username to log in with. The forms "DOMAIN\username" and "username@DOMAIN"
--                   are not understood. To set a domain, use the <code>smbdomain</code> argument. 
--@args  smbdomain   The domain to log in with. If you aren't in a domained environment, then anything
--                   will (should?) be accepted by the server. 
--@args  smbpassword The password to connect with. Be cautious with this, since some servers will lock
--                   accounts if the incorrect password is given. Although it's rare that the
--                   Administrator account can be locked out, in the off chance that it can, you could
--                   get yourself in trouble. 
--@args  smbhash     A password hash to use when logging in. This is given as a single hex string (32
--                   characters) or a pair of hex strings (both 32 characters, optionally separated by a 
--                   single character). These hashes are the LanMan or NTLM hash of the user's password,
--                   and are stored on disk or in memory. They can be retrieved from memory
--                   using the fgdump or pwdump tools. 
--@args  smbguest    If this is set to <code>true</code> or <code>1</code>, a guest login will be attempted if the normal one 
--                   fails. This should be harmless, but I thought I would disable it by default anyway
--                   because I'm not entirely sure of any possible consequences. 
--@args  smbtype     The type of SMB authentication to use. These are the possible options:
-- * <code>v1</code>: Sends LMv1 and NTLMv1.
-- * <code>LMv1</code>: Sends LMv1 only.
-- * <code>NTLMv1</code>: Sends NTLMv1 only (default).
-- * <code>v2</code>: Sends LMv2 and NTLMv2.
-- * <code>LMv2</code>: Sends LMv2 only.
--                   The default, <code>NTLMv1</code>, is a pretty
--                   decent compromise between security and compatibility. If you are paranoid, you might 
--                   want to use <code>v2</code> or <code>lmv2</code> for this. (Actually, if you're paranoid, you should be 
--                   avoiding this protocol altogether :P). If you're using an extremely old system, you 
--                   might need to set this to <code>v1</code> or <code>lm</code>, which are less secure but more compatible. 
-----------------------------------------------------------------------

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


