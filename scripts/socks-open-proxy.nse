description=[[
Checks if an open socks proxy is running on the target.

The script attempts to connect to a proxy server and send socks4 and
socks5 payloads. It is considered an open proxy if the script receives
a Request Granted response from the target port.

The payloads try to open a connection to www.google.com port 80.  A
different test host can be passed as openproxy.host (note the table
syntax in the example) argument, as described below.
]]

---
--@args openproxy.host Host that will be requested to the proxy
--@output
-- Interesting ports on scanme.nmap.org (64.13.134.52):
-- PORT     STATE  SERVICE
-- 1080/tcp open   socks
-- |  proxy-open-socks: Potentially OPEN proxy.
-- |_ Versions succesfully tested: Socks4 Socks5
--@usage
-- nmap --script=socks-open-proxy \
--		--script-args openproxy={host=<host>}

author = "Joao Correa <joao@livewire.com.br>"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "external", "intrusive"}

require "shortport"
require "bin"
require "nmap"
require "stdnse"
require "dns"

--- Function that resolves IP address for hostname and
--- returns it as hex values
--@param hostname Hostname to resolve
--@return Ip address of hostname in hex
function hex_resolve(hostname)
	local a, b, c, d;
	local t, err = ipOps.get_parts_as_number(dns.query(hostname))
	if t and not err
		then a, b, c, d = unpack(t)
		else return false
	end	
	sip = string.format("%.2x ", a) .. string.format("%.2x ", b) .. string.format("%.2x ", c) .. string.format("%.2x ",d)
	return true, sip
end

portrule = shortport.port_or_service({1080},{"socks","socks4","socks5"})

action = function(host, port)
	local response
	local retval
	local supported_versions = "\nVersions succesfully tested: "
	local fstatus = false
	local test_host = "www.google.com"

	-- If arg open-proxy.host exists, query dns for IP number and convert it to hex
	if (nmap.registry.args.openproxy and nmap.registry.args.openproxy.host) then test_host = nmap.registry.args.openproxy.host end
	local status, sip = hex_resolve(test_host)
	if not status then
		stdnse.print_debug("Failed to resolve IP Address")
		return
	end

	-- Attempting Socks 4 connection	
	-- Socks 4 payload: Version, Command, Null, Port, Ip Address, User (nmap), Null
	-- Default port is always 80, different ports means different services, with different results
	paystring = '04 01 00 50 ' .. sip .. ' 6e 6d 61 70 00'
	payload = bin.pack("H",paystring)

	local socket = nmap.new_socket()
	socket:set_timeout(10000)
	try = nmap.new_try(function() socket:close() end)
	try(socket:connect(host.ip, port.number))
	try(socket:send(payload))
	response = try(socket:receive())
	request_status = string.byte(response, 2)

	-- Send Socks4 payload to estabilish connection
	-- If did not receive Request Granted byte from server, skip next test
	if(request_status == 0x5b) then 
		stdnse.print_debug("Socks4: Received \"Request rejected or failed\" from proxy server")
	elseif (request_status == 0x5c) then 
		stdnse.print_debug("Socks4: Received \"request failed because client is not running identd\" from proxy server")
	elseif (request_status == 0x5d) then 
		stdnse.print_debug("Socks4: Received \"request failed because client's identd could not confirm the user ID string in the request\n from proxy server")

	-- If received Request Granted byte from server, proxy is considered open
	elseif (request_status == 0x5a) then
		stdnse.print_debug("Socks4: Received \"Request Granted\" from proxy server")
		supported_versions = supported_versions .. "Socks4 "			
		fstatus = true
	end
	socket:close()

	-- Attempting Socks 5 connection
	-- Socks5 payload: Version, Auths Length, Auths methods required
	payload = bin.pack("H",'05 01 00')

	-- Send first Socks5 payload to estabilish connection without authentication
	local socket2 = nmap.new_socket()
	socket2:set_timeout(10000)
	try = nmap.new_try(function() socket2:close() end)
	try(socket2:connect(host.ip, port.number))
	try(socket2:send(payload))
	auth = try(socket2:receive())
	r2 = string.byte(auth,2)
	
	-- If Auth is required, proxy is closed, skip next test
	if(r2 ~= 0x00) then 
		stdnse.print_debug("Socks5: Authentication required")

	-- If no Auth is required, try to estabilish connection
	else
		stdnse.print_debug("Socks5: No authentication required")

		-- Socks5 second payload: Version, Command, Null, Address type, Ip-Address, Port number	
		paystring = '05 01 00 01 ' .. sip .. '00 50'
		payload = bin.pack("H",paystring)	
		try(socket2:send(payload))
		z = try(socket2:receive())	
		request_status = string.byte(z, 2)
	
		-- If did not received Request Granted byte from server, skip next test
		if(request_status == 0x01) then 
			stdnse.print_debug("Socks5: Received \"General failure\" from proxy server")
		elseif (request_status == 0x02) then 
			stdnse.print_debug("Socks5: Received \"Connection not allowed by ruleset\" from proxy server")
		elseif (request_status == 0x03) then 
			stdnse.print_debug("Socks5: Received \"Network unreachable\" from proxy server")
		elseif (request_status == 0x04) then 
			stdnse.print_debug("Socks5: Received \"Host unreachable\" from proxy server")
		elseif (request_status == 0x05) then 
			stdnse.print_debug("Socks5: Received \"Connection refused by destination host\" from proxy server")
		elseif (request_status == 0x06) then 
			stdnse.print_debug("Socks5: Received \"TTL Expired\" from proxy server")
		elseif (request_status == 0x07) then
			stdnse.print_debug("Socks5: Received \"command not supported / protocol error\" from proxy server")
		elseif (request_status == 0x08) then
			stdnse.print_debug("Socks5: Received \"Address type not supported\" from proxy server")

		-- If received request granted byte from server, the proxy is considered open
		elseif (request_status == 0x00) then
			stdnse.print_debug("Socks5: Received \"Request granted\" from proxy server")
			supported_versions = supported_versions .. "Socks5"
			fstatus = true
		end
	end
	socket2:close()	

	-- show results
	if fstatus then
		retval = "Potentially OPEN proxy." .. supported_versions
		return retval
	end
	return
end
