description = [[
Attempts to grab the server's statistics over SMB and MSRPC, which uses TCP
ports 445 or 139. 

An administrator account is required to pull these statistics on most versions
of Windows, and Vista doesn't seem to let even the administrator account pull them.

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
-- 
-- @args smb* This script supports the <code>smbusername</code>,
-- <code>smbpassword</code>, <code>smbhash</code>, and <code>smbtype</code>
-- script arguments of the <code>smb</code> module.
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

	-- Create the SMB session
	status, smbstate = msrpc.start_smb(host, msrpc.SRVSVC_PATH)
	if(status == false) then
		if(nmap.debugging() > 0) then
			return "ERROR: " .. smbstate
		else
			return nil
		end
	end

	-- Bind to SRVSVC service
	status, bind_result = msrpc.bind(smbstate, msrpc.SRVSVC_UUID, msrpc.SRVSVC_VERSION, nil)
	if(status == false) then
		smb.stop(smbstate)
		if(nmap.debugging() > 0) then
			return "ERROR: " .. bind_result
		else
			return nil
		end
	end

	-- Call netservergetstatistics for 'server'
	status, netservergetstatistics_result = msrpc.srvsvc_netservergetstatistics(smbstate, host.ip)
	if(status == false) then
		smb.stop(smbstate)
		if(nmap.debugging() > 0) then
			return "ERROR: " .. netservergetstatistics_result
		else
			return nil
		end
	end

	-- Stop the session
	smb.stop(smbstate)

	-- Build the response	
	local stats = netservergetstatistics_result['stat']
	local response = " \n"
	local period = os.time() - stats['start']
	local period_str

	-- Fix a couple values
	stats['bytessent'] = bit.bor(bit.lshift(stats['bytessent_high'], 32), stats['bytessent_low'])
	stats['bytesrcvd'] = bit.bor(bit.lshift(stats['bytesrcvd_high'], 32), stats['bytesrcvd_low'])

	if(period == 0) then
		period = 1
	end

	if(period > 60 * 60 * 24) then
		period_str = string.format("%dd%dh%02dm%02ds", period / (60*60*24), (period % (60*60*24)) / 3600, (period % 3600) / 60, period % 60)
	elseif(period > 60 * 60) then
		period_str = string.format("%dh%02dm%02ds", period / 3600, (period % 3600) / 60, period % 60)
	else
		period_str = string.format("%02dm%02ds", period / 60, period % 60)
	end

	response = response .. string.format("Server statistics collected since %s (%s):\n", os.date("%Y-%m-%d %H:%M:%S", stats['start']), period_str)
	response = response .. string.format("|_ Traffic %d bytes (%.2f b/s) sent, %d bytes (%.2f b/s) received\n", stats['bytessent'], stats['bytessent'] / period, stats['bytesrcvd'], stats['bytesrcvd'] / period)
	response = response .. string.format("|_ Failed logins: %d\n", stats['pwerrors'])
	response = response .. string.format("|_ Permission errors: %d, System errors: %d\n", stats['permerrors'], stats['syserrors'])
	response = response .. string.format("|_ Print jobs spooled: %s\n", stats['jobsqueued'])
	response = response .. string.format("|_ Files opened (including pipes): %d\n", stats['fopens'])

	return response
end


