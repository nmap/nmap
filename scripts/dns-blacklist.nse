local dnsbl = require "dnsbl"
local ipOps = require "ipOps"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Checks target IP addresses against multiple DNS anti-spam and open
proxy blacklists and returns a list of services for which an IP has been flagged.  Checks may be limited by service category (eg: SPAM,
PROXY) or to a specific service name.  ]]

---
-- @usage
-- nmap --script dns-blacklist --script-args='dns-blacklist.ip=<ip>'
-- or
-- nmap -sn <ip> --script dns-blacklist 
--
-- @output
-- Pre-scan script results:
-- | dns-blacklist: 
-- | 1.2.3.4
-- |   PROXY
-- |     dnsbl.ahbl.org - PROXY
-- |     dnsbl.tornevall.org - PROXY
-- |       IP marked as "abusive host".
-- |       Proxy is working
-- |       Proxy has been scanned
-- |   SPAM
-- |     dnsbl.inps.de - SPAM
-- |       Spam Received See: http://www.sorbs.net/lookup.shtml?1.2.3.4
-- |     l2.apews.org - SPAM
-- |     list.quorum.to - SPAM
-- |     bl.spamcop.net - SPAM
-- |_    spam.dnsbl.sorbs.net - SPAM
--
-- Supported blacklist list mode (--script-args dns-blacklist.list):
-- | dns-blacklist: 
-- |   PROXY
-- |     dnsbl.ahbl.org
-- |     socks.dnsbl.sorbs.net
-- |     http.dnsbl.sorbs.net
-- |     misc.dnsbl.sorbs.net
-- |     dnsbl.tornevall.org
-- |   SPAM
-- |     dnsbl.ahbl.org
-- |     dnsbl.inps.de
-- |     bl.nszones.com
-- |     l2.apews.org
-- |     list.quorum.to
-- |     all.spamrats.com
-- |     bl.spamcop.net
-- |     spam.dnsbl.sorbs.net
-- |_    sbl.spamhaus.org
--
-- @args dns-blacklist.ip string containing the IP to check only needed if
--       running the script as a prerule.
--
-- @args dns-blacklist.mode string containing either "short" or "long"
--       long mode can sometimes provide additional information to why an IP
--       has been blacklisted. (default: long)
--
-- @args dns-blacklist.list lists all services that are available for a
--       certain category.
--
-- @args dns-blacklist.services string containing a comma-separated list of
--       services to query. (default: all)
--
-- @args dns-blacklist.category string containing the service category to query
--       eg. spam or proxy (default: all)
--
--

author = "Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"external", "safe"}


-- The script can be run either as a host- or pre-rule
hostrule = function() return true end
prerule = function() return true end

local arg_IP   		= stdnse.get_script_args(SCRIPT_NAME .. ".ip")
local arg_mode 		= stdnse.get_script_args(SCRIPT_NAME .. ".mode") or "long"
local arg_list 		= stdnse.get_script_args(SCRIPT_NAME .. ".list")
local arg_services	= stdnse.get_script_args(SCRIPT_NAME .. ".services")
local arg_category  = stdnse.get_script_args(SCRIPT_NAME .. ".category") or "all"

local function listServices()
	local result = {}
	if ( "all" == arg_category ) then
		for cat in pairs(dnsbl.SERVICES) do
			local helper = dnsbl.Helper:new(cat, arg_mode)
			local cat_res= helper:listServices()
			cat_res.name = cat
			table.insert(result, cat_res)
		end
	else
		result = dnsbl.Helper:new(arg_category, arg_mode):listServices()
	end
	return stdnse.format_output(true, result)
end

local function formatResult(result)
	local output = {}
	for _, svc in ipairs(result) do
		if ( svc.result.details ) then
			svc.result.details.name = ("%s - %s"):format(svc.name, svc.result.state)
			table.insert(output, svc.result.details)
		else
			table.insert(output, ("%s - %s"):format(svc.name, svc.result.state))
		end
	end
	return output
end

dnsblAction = function(host)
		
	local helper
	if ( arg_services and ( not(arg_category) or "all" == arg_category:lower() ) ) then
		return "\n  ERROR: A service filter can't be used without a specific category"
	elseif( "all" ~= arg_category ) then
		helper = dnsbl.Helper:new(arg_category, arg_mode)
		helper:setFilter(arg_services)
		local status, err = helper:validateFilter()
		if ( not(status) ) then
			return ("\n  ERROR: %s"):format(err)
		end
	end

	local output = {}
	if ( helper ) then
		local result = helper:checkBL(host.ip)
		if ( #result == 0 ) then return end
		output = formatResult(result)
	else
		for cat in pairs(dnsbl.SERVICES) do
			helper = dnsbl.Helper:new(cat, arg_mode)
			local result = helper:checkBL(host.ip)
			local out_part = formatResult(result)
			if ( #out_part > 0 ) then
				out_part.name = cat
				table.insert(output, out_part)
			end
		end
		if ( #output == 0 ) then return end
	end
	
	if ( "prerule" == SCRIPT_TYPE ) then
		output.name = host.ip
	end
	
	return stdnse.format_output(true, output)
end


-- execute the action function corresponding to the current rule
action = function(...)

	if ( arg_mode ~= "short" and arg_mode ~= "long" ) then
		return "\n  ERROR: Invalid argument supplied, mode should be either 'short' or 'long'"
	end
	
	if ( arg_IP and not(ipOps.todword(arg_IP)) ) then
		return "\n  ERROR: Invalid IP address was supplied"
	end
	
	-- if the list argument was given, just list the services and abort
	if ( arg_list ) then
		return listServices()
	end
	
	if ( arg_IP and "prerule" == SCRIPT_TYPE ) then
		return dnsblAction( { ip = arg_IP } )
	elseif ( "hostrule" == SCRIPT_TYPE ) then
		return dnsblAction(...)
	end

end
