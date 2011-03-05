description = [[
Attempts to find an DNS hostnames by brute force guessing.
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
-- @args newtargets Add discovered targets to nmap scan queue (only applies when dns-brute.domain has been set). 
-- @output
-- Pre-scan script results:
-- | dns-brute: 
-- | Result:
-- |   DNS Brute-force hostnames:
-- |   www.foo.com - 127.0.0.1
-- |   mail.foo.com - 127.0.0.2
-- |   blog.foo.com - 127.0.1.3
-- |   ns1.foo.com - 127.0.0.4
-- |_  admin.foo.com - 127.0.0.5

author = "cirrus"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"intrusive", "discovery"}

prerule = function()
	if nmap.registry.args['dns-brute.domain'] then
		local name = nmap.registry.args['dns-brute.domain']
		if(name:match("^(%d*)%.(%d*)%.(%d*)%.(%d*)$")) then
			return false
		else
			return true
		end
	else
		return false
	end
end

hostrule = function(host)
	return true
end


require 'dns'
require 'stdnse'
require 'target'

local HOST_LIST = {
	'www', 'mail', 'blog', 'ns0', 'ns1', 'mail2', 'mail3', 'admin', 'ads', 'ssh',
	'voip', 'sip', 'dns', 'ns2', 'ns3', 'dns0', 'dns1', 'dns2', 'eshop', 'shop',
	'forum', 'ftp', 'ftp0', 'host', 'log', 'mx0', 'mx1', 'mysql', 'sql', 'news',
	'noc', 'ns', 'auth', 'administration', 'adserver', 'alerts', 'alpha', 'ap',
	'app', 'apache', 'apps' , 'appserver', 'gw', 'backup', 'beta', 'cdn', 'chat',
	'citrix', 'cms', 'erp', 'corp', 'intranet', 'crs', 'svn', 'cvs', 'git', 'db',
	'database', 'demo', 'dev', 'devsql', 'dhcp', 'dmz', 'download', 'en', 'f5',
	'fileserver', 'firewall', 'help', 'http', 'id', 'info', 'images', 'internal',
	'internet', 'lab', 'ldap', 'linux', 'local', 'log', 'ipv6', 'syslog',
	'mailgate', 'main', 'manage', 'mgmt', 'monitor', 'mirror', 'mobile', 'mssql',
	'oracle', 'exchange', 'owa', 'mta', 'mx', 'mx0', 'mx1', 'ntp', 'ops', 'pbx',
	'whois', 'ssl', 'secure', 'server', 'smtp', 'squid', 'stage', 'stats', 'test',
	'upload', 'vm', 'vnc', 'vpn', 'wiki', 'xml',
}

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

--- Parse a hostname and try to return a domain name
--@param host Hostname to parse
--@return Domain name
local function parse_domain(host)
	local domainname = ''
	if(string.find(host,'%.')) then
		remove = string.sub(host,string.find(host,'%.')+1,string.len(host))
	else
		remove = host
	end
	if(string.find(remove,'%.')) then
		domainname = string.sub(host,string.find(host,'%.')+1,string.len(host))
	else
		domainname = host
	end
	return domainname
end

--- Check if an element is inside a table
--@param table Table to check
--@param element Element to find in table
--@return boolean Element was found or not
function table.contains(table, element)
	if(type(table) == "table") then
		for _, value in pairs(table) do
			if value == element then
				return true
			end
		end
	end
	return false
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
					if nmap.registry.args['dns-brute.domain'] and target.ALLOW_NEW_TARGETS then
						stdnse.print_debug("Added target: "..hostn)
						local status,err = target.add(hostn)
					end
					stdnse.print_debug("Hostname: "..hostn.." IP: "..addr)
					results[#results+1] = { hostname=hostn, address=addr }
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
							stdnse.print_debug("Hostname: "..hostn.." IP: "..srvip)
							srvresults[#srvresults+1] = { hostname=hostn, address=srvip }
							if nmap.registry.args['dns-brute.domain'] and target.ALLOW_NEW_TARGETS then
								stdnse.print_debug("Added target: "..srvip)
								local status,err = target.add(srvip)
							end
						end
					end
				end
			end
		end
	end
	condvar("signal")
end

action = function(host)
	local domainname

	if nmap.registry.args['dns-brute.domain'] then
		domainname = nmap.registry.args['dns-brute.domain']
	else
		domainname = parse_domain(stdnse.get_hostname(host))
	end
	if not nmap.registry.bruteddomains then
		nmap.registry.bruteddomains = {}
	end
	if(not table.contains(nmap.registry.bruteddomains,domainname)) then
		table.insert(nmap.registry.bruteddomains, domainname)
		stdnse.print_debug("Starting dns-brute at: "..domainname)
		local max_threads = nmap.registry.args['dns-brute.threads'] and tonumber( nmap.registry.args['dns-brute.threads'] ) or 5
		dosrv = stdnse.get_script_args("dns-brute.srv") or false
		stdnse.print_debug("THREADS: "..max_threads)
		local fileName = nmap.registry.args['dns-brute.hostlist']
		local commFile = fileName and nmap.fetchfile(fileName)
		local hostlist
		if commFile then
			local file = io.open(commFile)
			if file then
				hostlist = {}
				while true do
					local l = file:read()
					if not l then
						break
					end
					if not l:match("#!comment:") then
						table.insert(hostlist, l)
					end
				end
				file:close()
			end
		else
			if fileName then
				print("dns-brute: Hostlist file not found. Will use default list.")
			end
		end
		if (not hostlist) then hostlist = HOST_LIST end
		local srvlist = SRV_LIST

		local threads, results, revresults, srvresults = {}, {}, {}, {}
		results['name'] = "Result:"
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
			condvar("wait")
			done = true
			for thread in pairs(threads) do
				if (coroutine.status(thread) ~= "dead") then done = false end
			end
		end

		if(dosrv) then
			local i = 1
			local threads = {}
			local howmany_ip = math.floor(#srvlist/max_threads)+1
			local condvar = nmap.condvar( srvresults )
			stdnse.print_debug("SRV's per thread: "..howmany_ip)
			repeat
				local j = math.min(i+howmany_ip, #srvlist)	
				local name_iter = array_iter(srvlist, i, j)
				threads[stdnse.new_thread(srv_main, domainname, srvresults, name_iter)] = true
				i = j+1
			until i > #srvlist
			local done
			-- wait for all threads to finish
			while( not(done) ) do
				condvar("wait")
				done = true
				for thread in pairs(threads) do
					if (coroutine.status(thread) ~= "dead") then done = false end
				end
			end
		end

		response = {}
		response['name'] = "Result:"
		table.insert(response,"DNS Brute-force hostnames:")
		if(#results==0) then
			table.insert(response,"No results.")
		end
		for _, res in ipairs(results) do
			table.insert(response, res['hostname'].." - "..res['address'])
		end
		if(dosrv) then
			table.insert(response,"SRV results:")
			if(#srvresults==0) then
				table.insert(response,"No results.")
			end
			for _, res in ipairs(srvresults) do
				table.insert(response, res['hostname'].." - "..res['address'])
			end
		end
		return stdnse.format_output(true, response)
	end
end

