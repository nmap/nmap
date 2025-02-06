local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Queries Apache Zookeeper on port 2181 to get information about the instance.
]]

---
-- @usage
-- nmap --script zookeeper-info [--script-args command=<Custom Command>] <target>
-- @args command The custom command to run on Zookeeper instance ( e.g : stat,dump,cons,wchs,wchc,wchp)
-- @output
-- Host script results:
--| zookeeper: 
--| Config Values: clientPort=2181
--| dataDir=/var/lib/zookeeper/version-2
--| dataLogDir=/var/lib/zookeeper/version-2
--| tickTime=2000
--| maxClientCnxns=60
--| minSessionTimeout=4000
--| maxSessionTimeout=40000
--| serverId=0
--| 
--| Enviroment Variables: Environment:
--| zookeeper.version=3.4.10-3--1
--| host.name=zookeeper
--| java.version=1.8.0_201
--| java.vendor=Oracle Corporation
--| java.home=/usr/lib/jvm/java-8-oracle/jre
--| java.class.path=/etc/zookeeper/conf:/usr/share/java/jline.jar:/usr/share/java/log4j-1.2.jar:/usr/share/java/xercesImpl.jar:/usr/share/java/xmlParserAPIs.jar:/usr/share/java/netty.jar:/usr/share/java/slf4j-api.jar:/usr/share/java/slf4j-log4j12.jar:/usr/share/java/zookeeper.jar
--| java.library.path=/usr/java/packages/lib/amd64:/usr/lib64:/lib64:/lib:/usr/lib
--| java.io.tmpdir=/tmp
--| java.compiler=<NA>
--| os.name=Linux
--| os.arch=amd64
--| os.version=4.15.0-72-generic
--| user.name=zookeeper
--| user.home=/var/lib/zookeeper
--| user.dir=/


author = "Kürşat Çetin"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery","safe"}

portrule = function(host, port)
	local auth_port = { number=2181, protocol="tcp" }
	local identd = nmap.get_port_state(host, auth_port)

	return identd ~= nil
		and identd.state == "open"
		and port.protocol == "tcp"
		and port.state == "open"
end

local function run_command(host,port,command)
  local socket = nmap.new_socket()
  local status, err = socket:connect(host, port)
  if not status then
      return string.format("Can't connect: %s", err)
  end
  local status, response = socket:send(command)
  if not status then
    socket:close()
    return false, response
  end
  status, response = socket:receive()
  if not status then
    socket:close()
    return false, response
  end
  socket:close()
  return response
end

local function query_zoo(host, port,customCommand)
  local conf = run_command(host,port,"conf")
  local env = run_command(host,port,"envi")
  local result = stdnse.output_table()
  result["Config Values"] = conf
  result["Enviroment Variables"] = env

  if customCommand then
    local custCommand = run_command(host,port,customCommand)
    result["Custom Command"] = custCommand
  end

  return result

end 

action = function(host, port)
        local customCommand = stdnse.get_script_args(SCRIPT_NAME..".command") or nil
        local out = query_zoo(host, port,customCommand)
        return out
end