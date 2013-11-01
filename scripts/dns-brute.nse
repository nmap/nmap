local coroutine = require "coroutine"
local dns = require "dns"
local io = require "io"
local math = require "math"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local target = require "target"

description = [[
Attempts to enumerate DNS hostnames by brute force guessing of common subdomains.
]]
-- 2011-01-26

---
-- @usage
-- nmap --script dns-brute --script-args dns-brute.domain=foo.com,dns-brute.threads=6,dns-brute.hostlist=./hostfile.txt,newtargets -sS -p 80
-- nmap --script dns-brute www.foo.com
-- @args dns-brute.hostlist The filename of a list of host strings to try.
-- @args dns-brute.threads Thread to use (default 5).
-- @args dns-brute.srv Perform lookup for SRV records
-- @args dns-brute.domain Domain name to brute force if no host is specified
-- @args newtargets Add discovered targets to nmap scan queue
-- @output
-- Pre-scan script results:
-- | dns-brute:
-- |   DNS Brute-force hostnames
-- |     www.foo.com - 127.0.0.1
-- |     mail.foo.com - 127.0.0.2
-- |     blog.foo.com - 127.0.1.3
-- |     ns1.foo.com - 127.0.0.4
-- |_    admin.foo.com - 127.0.0.5
-- @xmloutput
-- <table key="DNS Brute-force hostnames">
--   <table>
--     <elem key="address">127.0.0.1</elem>
--     <elem key="hostname">www.foo.com</elem>
--   </table>
--   <table>
--     <elem key="address">127.0.0.2</elem>
--     <elem key="hostname">mail.foo.com</elem>
--   </table>
--   <table>
--     <elem key="address">127.0.1.3</elem>
--     <elem key="hostname">blog.foo.com</elem>
--   </table>
--   <table>
--     <elem key="address">127.0.0.4</elem>
--     <elem key="hostname">ns1.foo.com</elem>
--   </table>
--   <table>
--     <elem key="address">127.0.0.5</elem>
--     <elem key="hostname">admin.foo.com</elem>
--   </table>
-- </table>
-- <table key="SRV results"></table>

author = "Cirrus"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"intrusive", "discovery"}

prerule = function()
    if not stdnse.get_script_args("dns-brute.domain") then
      stdnse.print_debug(1,
        "Skipping '%s' %s, 'dns-brute.domain' argument is missing.",
        SCRIPT_NAME, SCRIPT_TYPE)
      return false
    end
    return true
end

hostrule = function(host)
	return true
end

local SRV_LIST = {
	'_afpovertcp._tcp', '_ssh._tcp', '_autodiscover._tcp', '_caldav._tcp',
	'_client._smtp', '_gc._tcp', '_h323cs._tcp', '_h323cs._udp', '_h323ls._tcp',
	'_h323ls._udp', '_h323rs._tcp', '_h323rs._tcp', '_http._tcp', '_iax.udp',
	'_imap._tcp', '_imaps._tcp', '_jabber-client._tcp', '_jabber._tcp',
	'_kerberos-adm._tcp', '_kerberos._tcp', '_kerberos._tcp.dc._msdcs',
	'_kerberos._udp', '_kpasswd._tcp', '_kpasswd._udp', '_ldap._tcp',
	'_ldap._tcp.dc._msdcs', '_ldap._tcp.gc._msdcs', '_ldap._tcp.pdc._msdcs',
	'_msdcs', '_mysqlsrv._tcp', '_ntp._udp', '_pop3._tcp', '_pop3s._tcp',
	'_sip._tcp', '_sip._tls', '_sip._udp', '_sipfederationtls._tcp',
	'_sipinternaltls._tcp', '_sips._tcp', '_smtp._tcp', '_stun._tcp',
	'_stun._udp', '_tcp', '_tls', '_udp', '_vlmcs._tcp', '_vlmcs._udp',
	'_wpad._tcp', '_xmpp-client._tcp', '_xmpp-server._tcp',
}

local function guess_domain(host)
	local name

	name = stdnse.get_hostname(host)
	if name and name ~= host.ip then
		return string.match(name, "%.([^.]+%..+)%.?$") or string.match(name, "^([^.]+%.[^.]+)%.?$")
	else
		return nil
	end
end

-- Single DNS lookup, returning all results. dtype should be e.g. "A", "AAAA".
local function resolve(host, dtype)
	local status, result = dns.query(host, {dtype=dtype,retAll=true})
	return status and result or false
end

local function array_iter(array, i, j)
	return coroutine.wrap(function ()
		while i <= j do
			coroutine.yield(array[i])
			i = i + 1
		end
	end)
end

local function thread_main(domainname, results, name_iter)
	local condvar = nmap.condvar( results )
	for name in name_iter do
		for _, dtype in ipairs({"A", "AAAA"}) do
			local res = resolve(name..'.'..domainname, dtype)
			if(res) then
				for _,addr in ipairs(res) do
					local hostn = name..'.'..domainname
					if target.ALLOW_NEW_TARGETS then
						stdnse.print_debug("Added target: "..hostn)
						local status,err = target.add(hostn)
					end
					stdnse.print_debug("Hostname: "..hostn.." IP: "..addr)
					local record = { hostname=hostn, address=addr }
					setmetatable(record, {
						__tostring = function(t)
							return string.format("%s - %s", t.hostname, t.address)
						end
					})
					results[#results+1] = record
				end
			end
		end
	end
	condvar("signal")
end

local function srv_main(domainname, srvresults, srv_iter)
	local condvar = nmap.condvar( srvresults )
	for name in srv_iter do
		local res = resolve(name..'.'..domainname, "SRV")
		if(res) then
			for _,addr in ipairs(res) do
				local hostn = name..'.'..domainname
				addr = stdnse.strsplit(":",addr)
				for _, dtype in ipairs({"A", "AAAA"}) do
					local srvres = resolve(addr[4], dtype)
					if(srvres) then
						for srvhost,srvip in ipairs(srvres) do
							if target.ALLOW_NEW_TARGETS then
								stdnse.print_debug("Added target: "..srvip)
								local status,err = target.add(srvip)
							end
							stdnse.print_debug("Hostname: "..hostn.." IP: "..srvip)
							local record = { hostname=hostn, address=srvip }
							setmetatable(record, {
								__tostring = function(t)
									return string.format("%s - %s", t.hostname, t.address)
								end
							})
							srvresults[#srvresults+1] = record
						end
					end
				end
			end
		end
	end
	condvar("signal")
end

action = function(host)
	local domainname = stdnse.get_script_args('dns-brute.domain')
	if not domainname then
		domainname = guess_domain(host)
	end
	if not domainname then
		return string.format("Can't guess domain of \"%s\"; use %s.domain script argument.", stdnse.get_hostname(host), SCRIPT_NAME)
	end

	if not nmap.registry.bruteddomains then
		nmap.registry.bruteddomains = {}
	end

	if nmap.registry.bruteddomains[domainname] then
		stdnse.print_debug("Skipping already-bruted domain %s", domainname)
		return nil
	end

	nmap.registry.bruteddomains[domainname] = true
	stdnse.print_debug("Starting dns-brute at: "..domainname)
	local max_threads = stdnse.get_script_args('dns-brute.threads') and tonumber( stdnse.get_script_args('dns-brute.threads') ) or 5
	local dosrv = stdnse.get_script_args("dns-brute.srv") or false
	stdnse.print_debug("THREADS: "..max_threads)
	-- First look for dns-brute.hostlist
	local fileName = stdnse.get_script_args('dns-brute.hostlist')
	-- Check fetchfile locations, then relative paths
	local commFile = (fileName and nmap.fetchfile(fileName)) or fileName
	-- Finally, fall back to vhosts-default.lst
	commFile = commFile or nmap.fetchfile("nselib/data/vhosts-default.lst")
	local hostlist = {}
	if commFile then
		for l in io.lines(commFile) do
			if not l:match("#!comment:") then
				table.insert(hostlist, l)
			end
		end
	else
		stdnse.print_debug(1, "%s: Cannot find hostlist file, quitting", SCRIPT_NAME)
		return
	end
	local srvlist = SRV_LIST

	local threads, results, srvresults = {}, {}, {}
	local condvar = nmap.condvar( results )
	local i = 1
	local howmany = math.floor(#hostlist/max_threads)+1
	stdnse.print_debug("Hosts per thread: "..howmany)
	repeat
		local j = math.min(i+howmany, #hostlist)
		local name_iter = array_iter(hostlist, i, j)
		threads[stdnse.new_thread(thread_main, domainname, results, name_iter)] = true
		i = j+1
	until i > #hostlist
	local done
	-- wait for all threads to finish
	while( not(done) ) do
		done = true
		for thread in pairs(threads) do
			if (coroutine.status(thread) ~= "dead") then done = false end
		end
		if ( not(done) ) then
			condvar("wait")
		end
	end

	if(dosrv) then
		i = 1
		threads = {}
		howmany = math.floor(#srvlist/max_threads)+1
		condvar = nmap.condvar( srvresults )
		stdnse.print_debug("SRV's per thread: "..howmany)
		repeat
			local j = math.min(i+howmany, #srvlist)
			local name_iter = array_iter(srvlist, i, j)
			threads[stdnse.new_thread(srv_main, domainname, srvresults, name_iter)] = true
			i = j+1
		until i > #srvlist
		local done
		-- wait for all threads to finish
		while( not(done) ) do
			done = true
			for thread in pairs(threads) do
				if (coroutine.status(thread) ~= "dead") then done = false end
			end
			if ( not(done) ) then
				condvar("wait")
			end
		end
	end

	local response = stdnse.output_table()
	if(#results==0) then
		setmetatable(results, { __tostring = function(t) return "No results." end })
	end
	response["DNS Brute-force hostnames"] = results
	if(dosrv) then
		if(#srvresults==0) then
			setmetatable(srvresults, { __tostring = function(t) return "No results." end })
		end
		response["SRV results"] = srvresults
	end
	return response
end

