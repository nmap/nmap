description = [[
Attempts to grab the server's statistics over SMB and MSRPC, which uses TCP
ports 445 or 139. 

An administrator account is required to pull these statistics on most versions
of Windows, and Vista and above require UAC to be turned down. 

Some of the numbers returned here don't feel right to me, but they're definitely 
the numbers that Windows returns. Take the values here with a grain of salt. 

These statistics are found using a single call to a SRVSVC function, 
<code>NetServerGetStatistics</code>. This packet is parsed incorrectly by Wireshark,
up to version 1.0.3 (and possibly higher). 
]]

---
-- @usage
-- nmap --script smb-server-stats.nse -p445 <host>
-- sudo nmap -sU -sS --script smb-server-stats.nse -p U:137,T:139 <host>
--
-- @output
-- Host script results:
-- |  smb-server-stats:
-- |  Server statistics collected since 2008-10-17 09:32:41 (4d0h24m29s):
-- |  |_ Traffic 133467 bytes (0.38b/s) sent, 167696 bytes (0.48b/s) received
-- |  |_ Failed logins: 5
-- |  |_ Permission errors: 1, System errors: 0
-- |  |_ Print jobs spooled: 0
-- |_ |_ Files opened (including pipes): 18
-----------------------------------------------------------------------

author = "Ron Bowes"
copyright = "Ron Bowes"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery","intrusive"}

require 'msrpc'
require 'smb'
require 'stdnse'

hostrule = function(host)
	return smb.get_port(host) ~= nil
end

action = function(host)

	local result, stats
	local response = " \n"

	result, stats = msrpc.get_server_stats(host)

	if(result == false) then
		if(nmap.debugging() > 0) then
			return "ERROR: " .. stats
		else
			return nil
		end
	end

	response = response .. string.format("Server statistics collected since %s (%s):\n", stats['start_str'], stats['period_str'])
	response = response .. string.format("|_ Traffic %d bytes (%.2f b/s) sent, %d bytes (%.2f b/s) received\n", stats['bytessent'], stats['bytessentpersecond'], stats['bytesrcvd'], stats['bytesrcvdpersecond'])
	response = response .. string.format("|_ Failed logins: %d\n", stats['pwerrors'])
	response = response .. string.format("|_ Permission errors: %d, System errors: %d\n", stats['permerrors'], stats['syserrors'])
	response = response .. string.format("|_ Print jobs spooled: %s\n", stats['jobsqueued'])
	response = response .. string.format("|_ Files opened (including pipes): %d\n", stats['fopens'])

	return response
end


