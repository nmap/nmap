local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Opens a connection to a NetBus server and extracts information about
the host and the NetBus service itself.

The extracted host information includes a list of running
applications, and the hosts sound volume settings. 

The extracted service information includes it's access control list
(acl), server information, and setup. The acl is a list of IP
addresses permitted to access the service. Server information
contains details about the server installation path, restart
persistence, user account that the server is running on, and the
amount of connected NetBus clients. The setup information contains
configuration details, such as the services TCP port number, traffic
logging setting, password, an email address for receiving login
notifications, an email address used for sending the notifications,
and an smtp-server used for notification delivery.
]]

---
-- @usage
-- nmap -p 12345 --script netbus-info <target> --script-args netbus-info.password=<password>
--
-- @output
-- 12345/tcp open  netbus
-- | netbus-info:   
-- |   ACL
-- |     127.0.0.1
-- |   APPLICATIONS
-- |     PuTTY Configuration
-- |   INFO
-- |     Program Path: Z:\home\joeuser\Desktop\Patch.exe
-- |     Restart persistent: Yes
-- |     Login ID: joeuser
-- |     Clients connected to this host: 1
-- |   SETUP
-- |     TCP-port: 12345
-- |     Log traffic: 1
-- |     Password: password123
-- |     Notify to: admin@example.com
-- |     Notify from: spoofed@example.org
-- |     SMTP-server: smtp.example.net
-- |   VOLUME
-- |     Wave: 0
-- |     Synth: 0
-- |_    Cd: 0
--
-- @args netbus-info.password The password used for authentication

author = "Toni Ruottu"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}


dependencies = {"netbus-version", "netbus-brute"}

portrule = shortport.port_or_service (12345, "netbus", {"tcp"})

local function format_acl(acl)
	if acl == nil then
		return {}
	end
	local payload = string.sub(acl, 9) --skip header
	local fields = stdnse.strsplit("|", payload)
	table.remove(fields, (# fields))
	fields["name"] = "ACL"
	return fields
end

local function format_apps(apps)
	if apps == nil then
		return {}
	end
	local payload = string.sub(apps, 10) --skip header
	local fields = stdnse.strsplit("|", payload)
	table.remove(fields, (# fields))
	fields["name"] = "APPLICATIONS"
	return fields
end

local function format_info(info)
	if info == nil then
		return {}
	end
	local payload = string.sub(info, 6) --skip header
	local fields = stdnse.strsplit("|", payload)
	fields["name"] = "INFO"
	return fields
end

local function format_setup(setup)
	local formatted = {}
	if setup == nil then
		return formatted
	end
	local fields = stdnse.strsplit(";", setup)
	if # fields < 7 then
		return formatted
	end
	formatted["name"] = "SETUP"
	table.insert(formatted, string.format("TCP-port: %s", fields[2]))
	table.insert(formatted, string.format("Log traffic: %s", fields[3]))
	table.insert(formatted, string.format("Password: %s", fields[4]))
	table.insert(formatted, string.format("Notify to: %s", fields[5]))
	table.insert(formatted, string.format("Notify from: %s", fields[6]))
	table.insert(formatted, string.format("SMTP-server: %s", fields[7]))
	return formatted
end

local function format_volume(volume)
	local formatted = {}
	if volume == nil then
		return formatted
	end
	local fields = stdnse.strsplit(";", volume)
	if # fields < 4 then
		return formatted
	end
	formatted["name"] = "VOLUME"
	table.insert(formatted, string.format("Wave: %s", fields[2]))
	table.insert(formatted, string.format("Synth: %s", fields[3]))
	table.insert(formatted, string.format("Cd: %s", fields[4]))
	return formatted
end

action = function( host, port )
	local password = nmap.registry.args[SCRIPT_NAME .. ".password"]
	if not password and nmap.registry.netbuspasswords then
		local key = string.format("%s:%d", host.ip, port.number)
		password = nmap.registry.netbuspasswords[key]
	end
	if not password then
		password = ""
	end
	local socket = nmap.new_socket()
	socket:set_timeout(5000)
	local status, err = socket:connect(host.ip, port.number)
	local buffer, err = stdnse.make_buffer(socket, "\r")
	local _ = buffer()
	socket:send(string.format("Password;1;%s\r", password))
	local gotin = buffer()
	if gotin == "Access;0" then
		return
	end

	socket:send("GetInfo\r")
	local info = buffer()
	socket:send("GetSetup\r")
	local setup = buffer()
	socket:send("GetACL\r")
	local acl = buffer()
	socket:send("GetApps\r")
	local apps = buffer()
	socket:send("GetVolume\r")
	local volume = buffer()
	socket:close()

	local response = {}
	table.insert(response, format_acl(acl))
	table.insert(response, format_apps(apps))
	table.insert(response, format_info(info))
	table.insert(response, format_setup(setup))
	table.insert(response, format_volume(volume))

	return stdnse.format_output(true, response)
end


