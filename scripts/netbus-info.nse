local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local stringaux = require "stringaux"
local table = require "table"

description = [[
Opens a connection to a NetBus server and extracts information about
the host and the NetBus service itself.

The extracted host information includes a list of running
applications, and the hosts sound volume settings.

The extracted service information includes its access control list
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
-- @xmloutput
-- <table key="ACL">
--   <elem>127.0.0.1</elem>
-- </table>
-- <table key="APPLICATIONS">
--   <elem>PuTTY Configuration</elem>
-- </table>
-- <table key="INFO">
--   <elem key="Program Path">Z:\home\joeuser\Desktop\Patch.exe</elem>
--   <elem key="Restart persistent">Yes</elem>
--   <elem key="Login ID">joeuser</elem>
--   <elem key="Clients connected to this host">1</elem>
-- </table>
-- <table key="SETUP">
--   <elem key="TCP-port">12345</elem>
--   <elem key="Log traffic">1</elem>
--   <elem key="Password">password123</elem>
--   <elem key="Notify to">admin@example.com</elem>
--   <elem key="Notify from">spoofed@example.org</elem>
--   <elem key="SMTP-server">smtp.example.net</elem>
-- </table>
-- <table key="VOLUME">
--   <elem key="Wave">0</elem>
--   <elem key="Synth">0</elem>
--   <elem key="Cd">0</elem>
-- </table>
--
-- @args netbus-info.password The password used for authentication

author = "Toni Ruottu"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "discovery", "safe"}


dependencies = {"netbus-version", "netbus-brute"}

portrule = shortport.port_or_service (12345, "netbus", {"tcp"})

local function format_acl(acl)
  if acl == nil then
    return nil
  end
  local payload = string.sub(acl, 9) --skip header
  local fields = stringaux.strsplit("|", payload)
  table.remove(fields, (# fields))
  return fields
end

local function format_apps(apps)
  if apps == nil then
    return nil
  end
  local payload = string.sub(apps, 10) --skip header
  local fields = stringaux.strsplit("|", payload)
  table.remove(fields, (# fields))
  return fields
end

local function format_info(info)
  if info == nil then
    return nil
  end
  local payload = string.sub(info, 6) --skip header
  local fields = stringaux.strsplit("|", payload)
  return fields
end

local function format_setup(setup)
  if setup == nil then
    return nil
  end
  local fields = stringaux.strsplit(";", setup)
  if # fields < 7 then
    return nil
  end
  local formatted = stdnse.output_table()
  formatted["TCP-port"] = fields[2]
  formatted["Log traffic"] = fields[3]
  formatted["Password"] = fields[4]
  formatted["Notify to"] = fields[5]
  formatted["Notify from"] = fields[6]
  formatted["SMTP-server"] = fields[7]
  return formatted
end

local function format_volume(volume)
  if volume == nil then
    return nil
  end
  local fields = stringaux.strsplit(";", volume)
  if # fields < 4 then
    return nil
  end
  local formatted = stdnse.output_table()
  formatted["Wave"] = fields[2]
  formatted["Synth"] = fields[3]
  formatted["Cd"] = fields[4]
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
  local status, err = socket:connect(host, port)
  local buffer, err = stdnse.make_buffer(socket, "\r")
  local _ = buffer()
  if not (_ and _:match("^NetBus")) then
    stdnse.debug1("Not NetBus")
    return nil
  end
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

  local response = stdnse.output_table()
  response["ACL"] = format_acl(acl)
  response["APPLICATIONS"] = format_apps(apps)
  response["INFO"] = format_info(info)
  response["SETUP"] = format_setup(setup)
  response["VOLUME"] = format_volume(volume)

  return response
end


