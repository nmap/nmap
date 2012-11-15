local coroutine = require "coroutine"
local math = require "math"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local comm = require "comm"
local vulns = require "vulns"
local http = require "http"


description = [[
Tests a web server for vulnerability to the Slowloris DoS attack without actually launching a DoS attack.

Slowloris was described at Defcon 17 by RSnake
(see http://ha.ckers.org/slowloris/).

This script opens two connections to the server, each without 
the final CRLF. After 10 seconds, second connection sends 
additional header. Both connections then wait for server timeout.
If second connection gets a timeout 10 or more seconds after the
first one, we can conclude that sending additional header prolonged
it's timeout and that the server is vulnerable to slowloris DoS attack.

You can specify custom http User-agent field with <code>http.useragent</code>
script argument.

Idea from Qualys blogpost:
 * https://community.qualys.com/blogs/securitylabs/2011/07/07/identifying-slow-http-attack-vulnerabilities-on-web-applications
 
]]

---
-- @usage
-- nmap --script http-slowloris-check  <target>
--
-- @args http.useragent Specifies custom user agent string.
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-slowloris-check:
-- |   VULNERABLE:
-- |   Slowloris DOS attack
-- |     State: VULNERABLE
-- |     Description:
-- |       Slowloris tries to keep many connections to the target web server open and hold them open as long as possible.
-- |       It accomplishes this by opening connections to the target web server and sending a partial request. By doing
-- |       so, it starves the http server's resources causing Denial Of Service.
-- |
-- |     Disclosure date: 2009-09-17
-- |     References:
-- |_      http://ha.ckers.org/slowloris/

author = "Aleksandar Nikolic"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}


portrule = shortport.http

local HalfHTTP
local Bestopt
local TimeWithout -- time without additional headers
local TimeWith 	  -- time with additional headers

-- does a half http request and waits until timeout 
local function slowThread1(host,port)
	-- if no response was received when determining SSL
	if ( Bestopt == "none" ) then
		return
	end
	local socket,status
	local catch = function()
		TimeWithout = nmap.clock()
	end
	local try = nmap.new_try(catch)	
	socket = nmap.new_socket()
	socket:set_timeout(500 * 1000)
	socket:connect(host.ip, port, Bestopt)
	socket:send(HalfHTTP)
	try(socket:receive())
	TimeWithout = nmap.clock()
end

-- does a half http request but sends another 
-- header value after 10 seconds
local function slowThread2(host,port)
	-- if no response was received when determining SSL
	if ( Bestopt == "none" ) then
		return
	end
	local socket,status
	local catch = function()
		-- note the time the socket timedout
		TimeWith = nmap.clock()
		stdnse.print_debug("2 try")
	end
	local try = nmap.new_try(catch)	
	socket = nmap.new_socket()
	socket:set_timeout(500 * 1000)
	socket:connect(host.ip, port, Bestopt)
	socket:send(HalfHTTP)
	stdnse.sleep(10)	
	socket:send("X-a: b\r\n")	
	try(socket:receive())
	TimeWith = nmap.clock()
end

action = function(host,port)

	local slowloris  = {
		title = "Slowloris DOS attack",
		description = [[
Slowloris tries to keep many connections to the target web server open and hold them open as long as possible.
It accomplishes this by opening connections to the target web server and sending a partial request. By doing 
so, it starves the http server's resources causing Denial Of Service. 
		]],
		references = {
		  'http://ha.ckers.org/slowloris/',
		},
		dates = {
		  disclosure = {year = '2009', month = '09', day = '17'},
		},
		exploit_results = {},
	}	
	
	local report = vulns.Report:new(SCRIPT_NAME, host, port)
	slowloris.state = vulns.STATE.NOT_VULN

	local _
	_, _, Bestopt = comm.tryssl(host, port, "GET / \r\n\r\n", {}) -- first determine if we need ssl
	HalfHTTP = "POST /" .. tostring(math.random(100000, 900000)) .. " HTTP/1.1\r\n" ..
	                  "Host: " .. host.ip .. "\r\n" ..
	                  "User-Agent: " .. http.USER_AGENT .. "\r\n; " ..
	                  "Content-Length: 42\r\n"
	-- both threads run at the same time
	local thread1 = stdnse.new_thread(slowThread1, host, port)
	local thread2 = stdnse.new_thread(slowThread2, host, port)
	while true do -- wait for both threads to die 
		if coroutine.status(thread1) == "dead" and  coroutine.status(thread2) == "dead" then
			break
		end
		stdnse.sleep(1)
	end
	-- compare times
	if ( not(TimeWith) or not(TimeWithout) ) then
		return
	end
	local diff = TimeWith - TimeWithout 
	stdnse.print_debug("Time difference is: %d",diff)
	-- if second connection died 10 or more seconds after the first 
	-- it means that sending additional data prolonged the connection's time 
	-- and the server is vulnerable to slowloris attack
	if diff >= 10	then 
		stdnse.print_debug("Difference is greater or equal to 10 seconds.")
		slowloris.state = vulns.STATE.VULN
	end
	return report:make_output(slowloris)
end
