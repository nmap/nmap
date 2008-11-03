id = "MSRPC: Server statistics"
description = [[
Attempts to grab the server's statistics over SMB + MSRPC, which uses TCP
ports 445 or 139. 

An administrative account is required to pull these statistics on most versions
of Windows, and Vista doesn't seem to let even the administrator account pull them.

Some of the numbers returned here don't feel right to me, but they're definitely 
the numbers that Windows returns. Take the values here with a grain of salt. 
]]

---
-- @usage
-- nmap --script smb-serverstats.nse -p445 <host>
-- sudo nmap -sU -sS --script smb-serverstats.nse -p U:137,T:139 <host>
--
-- @output
-- Host script results:
-- |  MSRPC: Server statistics:
-- |  Server statistics collected since 2008-10-17 09:32:41 (4d0h24m29s):
-- |  |_ Traffic 133467 bytes (0.38b/s) sent, 167696 bytes (0.48b/s) received
-- |  |_ Failed logins: 5
-- |  |_ Permission errors: 1, System errors: 0
-- |  |_ Print jobs spooled: 0
-- |_ |_ Files opened (including pipes): 18
--
--@args  smbusername The SMB username to log in with. The form DOMAIN\username and username@DOMAIN
--                   are NOT understood. To set a domain, use the smbdomain argument. 
--@args  smbdomain   The domain to log in with. If you aren't in a domained environment, then anything
--                   will (should?) be accepted by the server. 
--@args  smbpassword The password to connect with. Be cautious with this, since some servers will lock
--                   accounts if the incorrect password is given (although it's rare for the 
--                   'administrator' account to be lockoutable, in the off chance that it is, you could
--                   get yourself in trouble). 
--@args  smbhash     A password hash to use when logging in. This is given as a single hex string (32
--                   characters) or a pair of hex strings (2 x 32 characters, optionally separated by a 
--                   single character). These hashes are the Lanman or NTLM hash of the user's password,
--                   and are stored by systems, on the harddrive or memory. They can be retrived from memory
--                   using the fgdump or pwdump tools. 
--@args  smbguest    If this is set to 'true' or '1', a 'guest' login will be attempted if the normal one 
--                   fails. This should be harmless, but I thought I would disable it by default anyway
--                   because I'm not entirely sure of any possible consequences. 
--@args  smbtype     The type of SMB authentication to use. By default, NTLMv1 is used, which is a pretty
--                   decent compromise between security and compatibility. If you are paranoid, you might 
--                   want to use 'v2' or 'lmv2' for this (actually, if you're paranoid, you should be 
--                   avoiding this protocol altogether :P). If you're using an extremely old system, you 
--                   might need to set this to 'v1' or 'lm', which are less secure but more compatible. 
--
--                   If you want finer grained control, these are the possible options:
--                       * v1 -- Sends LMv1 and NTLMv1
--                       * LMv1 -- Sends LMv1 only
--                       * NTLMv1 -- Sends NTLMv1 only (default)
--                       * v2 -- Sends LMv2 and NTLMv2
--                       * LMv2 -- Sends LMv2 only
--
-----------------------------------------------------------------------

author = "Ron Bowes"
copyright = "Ron Bowes"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery","intrusive"}

require 'msrpc'
require 'smb'
require 'stdnse'

hostrule = function(host)

	local port = smb.get_port(host)

	if(port == nil) then
		return false
	else
		return true
	end

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
	local response = " \n"
	local period = os.time() - netservergetstatistics_result['start']
	local period_str

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

stats = netservergetstatistics_result
	response = response .. string.format("Server statistics collected since %s (%s):\n", netservergetstatistics_result['start_date'], period_str)
	response = response .. string.format("|_ Traffic %d bytes (%.2fb/s) sent, %d bytes (%.2fb/s) received\n", stats['bytessent'], stats['bytessent'] / period, stats['bytesrcvd'], stats['bytesrcvd'] / period)
	response = response .. string.format("|_ Failed logins: %d\n", stats['pwerrors'])
	response = response .. string.format("|_ Permission errors: %d, System errors: %d\n", stats['permerrors'], stats['syserrors'])
	response = response .. string.format("|_ Print jobs spooled: %s\n", stats['jobsqueued'])
	response = response .. string.format("|_ Files opened (including pipes): %d\n", stats['fopens'])

	return response
end


