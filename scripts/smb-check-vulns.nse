id = "MSRPC: Check vulnerabilities"
description = [[
Checks if a host is vulnerable to MS08-067, a Windows RPC vulnerability that
can allow remote code execution. This script is intended to check for more
vulnerabilities in the future.

Checking for MS08-067 is very dangerous, as the check is likely
to crash systems. On a fairly wide scan conducted by Brandon Enright, we determined
that on average, a vulnerable system is more likely to crash than to survive
the check. Out of 82 vulnerable systems, 52 crashed. As such, great care should be 
taken when using this check. 

You have the option to supply a username and password, but
it shouldn't be necessary for a default configuration. 
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
-- |_ smb-check-vulns: This host is vulnerable to MS08-067
--
-- @args smb* This script supports the <code>smbusername</code>,
-- <code>smbpassword</code>, <code>smbhash</code>, <code>smbguest</code>, and
-- <code>smbtype</code> script arguments of the <code>smb</code> module.
-----------------------------------------------------------------------

author = "Ron Bowes"
copyright = "Ron Bowes"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive"}

require 'msrpc'
require 'smb'
require 'stdnse'

hostrule = function(host)
	return smb.get_port(host) ~= nil
end

local VULNERABLE = 1
local PATCHED    = 2
local UNKNOWN    = 3

---Check if the server is patched for MS08-067. This is done by calling NetPathCompare with an 
-- illegal string. If the string is accepted, then the server is vulnerable; if it's rejected, then
-- you're safe (for now). 
--
-- Based on a packet cap of this script, thanks go out to the author:
-- http://labs.portcullis.co.uk/download/ms08-067_check.py 
--
-- If there's a licensing issue, please let me (Ron Bowes) know so I can 
--
-- NOTE: This CAN crash stuff (ie, crash svchost.exe and force a reboot), so beware! In about 20 
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
--    status, netpathcanonicalize_result = msrpc.srvsvc_netpathcanonicalize(smbstate, host.ip, "\\a", "\\test\\")
	
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


action = function(host)
	local status, result

	status, result = check_ms08_067(host)

	if(status == false) then
		if(nmap.debugging() > 0) then
			return "ERROR: " .. result
		else
			return nil
		end
	end

	if(result == VULNERABLE) then
		response = "This host is vulnerable to MS08-067"
	elseif(result == UNKNOWN) then
		response = "This host is likely vulnerable to MS08-067 (it stopped responding during the test)"
	else
		if(nmap.verbosity() > 0) then
			response = "This host is patched for MS08-067"
		else
			response = nil
		end
	end

	return response
end



