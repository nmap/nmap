description = [[
Checks if a host is vulnerable to MS08-067, a Windows RPC vulnerability that
can allow remote code execution. This script is intended to check for more
vulnerabilities in the future.

WARNING: These checks are dangerous, and are very likely to bring down a server. 
These should not be run in a production environment unless you (and, more importantly,
the business) understand the risks! 

If you set the script parameter 'unsafe', then scripts will run that are almost 
(or totally) guaranteed to crash a vulnerable system; do NOT specify <code>unsafe</code>
in a production environment! And that isn't to say that non-unsafe scripts will 
not crash a system, they're just less likely to. 

MS08-067 -- Checks if a host is vulnerable to MS08-067, a Windows RPC vulnerability that
can allow remote code execution.  Checking for MS08-067 is very dangerous, as the check 
is likelyto crash systems. On a fairly wide scan conducted by Brandon Enright, we determined
that on average, a vulnerable system is more likely to crash than to survive
the check. Out of 82 vulnerable systems, 52 crashed. 

At the same time, MS08-067 is extremely critical to fix. Metasploit has a working and
stable exploit for it, and any system vulnerable can very easily be compromised. 

regsvc DoS -- Checks if a host is vulnerable to a crash in regsvc, caused 
by a null pointer dereference. I inadvertently discovered this crash while working
on <code>smb-enum-sessions</code>, and discovered that it was repeatable. It's been 
reported to Microsoft (case #MSRC8742). 

This check WILL crash the service, if it's vulnerable, and requires a guest account
or higher to work. It is considered <code>unsafe</code>. 

(Note: if you have other SMB/MSRPC vulnerability checks you'd like to see added, and
you can show me a tool with a license that is compatible with Nmap's, post a request 
on the Nmap-dev mailing list and I'll add it to my list [Ron Bowes]). 
]]
-- Currently, this script checks if a host is vulnerable to ms08-067. I'd like to add
-- checks for more vulnerabilities, but I'm worried about licensing/copyright issues
-- (since I'd be basing them on non-free tools). 

---
--@usage
-- nmap --script smb-check-vulns.nse -p445 <host>
-- sudo nmap -sU -sS --script smb-check-vulns.nse -p U:137,T:139 <host>
--
--@output
-- Host script results:
-- |  smb-check-vulns:
-- |  MS08-067: FIXED
-- |_ regsvc DoS: VULNERABLE
--
-- @args unsafe If set, this script will run checks that, if the system isn't
--       patched, are basically guaranteed to crash something. Remember that
--       non-unsafe checks aren't necessarily safe either)
-----------------------------------------------------------------------

author = "Ron Bowes"
copyright = "Ron Bowes"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive"}
-- Set the runlevel to >2 so this runs last (so if it DOES crash something, it doesn't
-- till other scans have had a chance to run)
runlevel = 2

require 'msrpc'
require 'smb'
require 'stdnse'

hostrule = function(host)
	return smb.get_port(host) ~= nil
end

local VULNERABLE = 1
local PATCHED    = 2
local UNKNOWN    = 3
local NOTRUN     = 4

---Check if the server is patched for MS08-067. This is done by calling NetPathCompare with an 
-- illegal string. If the string is accepted, then the server is vulnerable; if it's rejected, then
-- you're safe (for now). 
--
-- Based on a packet cap of this script, thanks go out to the author:
-- http://labs.portcullis.co.uk/download/ms08-067_check.py 
--
-- If there's a licensing issue, please let me (Ron Bowes) know so I can 
--
-- NOTE: This CAN crash stuff (ie, crash svchost and force a reboot), so beware! In about 20 
-- tests I did, it crashed once. This is not a guarantee. 
--
--@param host The host object. 
--@return (status, result) If status if alse, result is an error code; otherwise, result is either 
--        <code>VULNERABLE</code> for vulnerable, <code>PATCHED</code> for not vulnerable, or
--        <code>UNKNOWN</code> if there was an error (likely vulnerable). 
function check_ms08_067(host)
	local status, smbstate
	local bind_result, netpathcompare_result

	-- Create the SMB session
	status, smbstate = msrpc.start_smb(host, "\\\\BROWSER")
	if(status == false) then
		return false, smbstate
	end

	-- Bind to SRVSVC service
	status, bind_result = msrpc.bind(smbstate, msrpc.SRVSVC_UUID, msrpc.SRVSVC_VERSION, nil)
	if(status == false) then
		msrpc.stop_smb(smbstate)
		return false, bind_result
	end

	-- Call netpathcanonicalize
--	status, netpathcanonicalize_result = msrpc.srvsvc_netpathcanonicalize(smbstate, host.ip, "\\a", "\\test\\")
	
	local path1 = "\\AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\\..\\n"
	local path2 = "\\n"
	status, netpathcompare_result = msrpc.srvsvc_netpathcompare(smbstate, host.ip, path1, path2, 1, 0)

	-- Stop the SMB session
	msrpc.stop_smb(smbstate)

	if(status == false) then
		if(string.find(netpathcompare_result, "INVALID_NAME") == nil) then
			return true, UNKNOWN
		else
			return true, PATCHED
		end
	end


	return true, VULNERABLE
end

---While writing <code>smb-enum-sessions</code> I discovered a repeatable null-pointer dereference 
-- in regsvc. I reported it to Microsoft, but because it's a simple DoS (and barely even that, because
-- the service automatically restarts), and because it's only in Windows 2000, it isn't likely that they'll
-- fix it. This function checks for that crash (by crashing the process). 
--
-- The crash occurs when the string sent to winreg_enumkey() function is null. 
--
--@param host The host object. 
--@return (status, result) If status if alse, result is an error code; otherwise, result is either 
--        <code>VULNERABLE</code> for vulnerable or <code>PATCHED</code> for not vulnerable. If the check
--        was skipped, <code>NOTRUN</code> is returned. 
function check_winreg_Enum_crash(host)
	local i, j
	local elements = {}

	if(nmap.registry.args.unsafe == nil) then
		return true, NOTRUN
	end

	-- Create the SMB session
	status, smbstate = msrpc.start_smb(host, msrpc.WINREG_PATH)
	if(status == false) then
		return false, smbstate
	end

	-- Bind to WINREG service
	status, bind_result = msrpc.bind(smbstate, msrpc.WINREG_UUID, msrpc.WINREG_VERSION, nil)
	if(status == false) then
		msrpc.stop_smb(smbstate)
		return false, bind_result
	end

	status, openhku_result = msrpc.winreg_openhku(smbstate)
	if(status == false) then
		msrpc.stop_smb(smbstate)
		return false, openhku_result
	end

	-- Loop through the keys under HKEY_USERS and grab the names
	status, enumkey_result = msrpc.winreg_enumkey(smbstate, openhku_result['handle'], 0, nil)
	msrpc.stop_smb(smbstate)

	if(status == false) then
		return true, VULNERABLE
	end

	return true, PATCHED
end


action = function(host)

	local status, result
	local response = " \n"
	local found = false

	-- Check for ms08-067
	status, result = check_ms08_067(host)
	if(status == false) then
		if(nmap.debugging() > 0) then
			return "MS08-067: ERROR: " .. result
		else
			return nil
		end
	end
	if(result == VULNERABLE) then
		response = response .. "MS08-067: VULNERABLE\n"
		found = true
	elseif(result == UNKNOWN) then
		response = response .. "MS08-067: LIKELY VULNERABLE (host stopped responding)\n"
	else
		if(nmap.verbosity() > 0) then
			response = response .. "MS08-067: FIXED\n"
		end
	end

	-- Check for a winreg_Enum crash
	status, result = check_winreg_Enum_crash(host)
	if(status == false) then
		if(nmap.debugging() > 0) then
			return response .. "regsvc DoS: ERROR: " .. result
		else
			return nil
		end
	end
	if(result == VULNERABLE) then
		response = response .. "regsvc DoS: VULNERABLE\n"
		found = true
	elseif(result == NOTRUN) then
		if(nmap.verbosity() > 0) then
			response = response .. "regsvc DoS: NOT RUN (add --script-args=unsafe=1 to run)\n"
		end
	else
		if(nmap.verbosity() > 0) then
			response = response .. "regsvc DoS: FIXED\n"
		end
	end

	-- Don't show a response if we aren't verbose and we found nothing
	if(nmap.verbosity() == 0 and found == false) then
		response = nil
	end

	return response
end



