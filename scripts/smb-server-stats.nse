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
-- |  Server statistics collected since 2008-12-12 14:53:27 (89d17h37m48s):
-- |  |_ 22884718 bytes (2.95 b/s) sent, 28082489 bytes (3.62 b/s) received
-- |_ |_ 5759 failed logins, 16 permission errors, 0 system errors, 0 print jobs, 1273 files opened
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
	response = response .. string.format("|_ %d bytes (%.2f b/s) sent, %d bytes (%.2f b/s) received\n", stats['bytessent'], stats['bytessentpersecond'], stats['bytesrcvd'], stats['bytesrcvdpersecond'])
	response = response .. string.format("|_ %d failed logins, %d permission errors, %d system errors, %d print jobs, %d files opened\n", stats['pwerrors'], stats['permerrors'], stats['syserrors'], stats['jobsqueued'], stats['fopens'])

	return response
end


