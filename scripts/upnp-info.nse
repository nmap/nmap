local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local upnp = require "upnp"

description = [[
Attempts to extract system information from the UPnP service.
]]

---
-- @usage
-- nmap -sU -p 1900 --script=upnp-info <target>
-- @output
-- |  upnp-info:  System/1.0 UPnP/1.0 IGD/1.0
-- |_ Location: http://192.168.1.1:80/UPnP/IGD.xml
--
-- @args upnp-info.override Controls whether we override the IP address information
--                          returned by the UPNP service for the location of the XML
--                          file that describes the device.  Defaults to true for
--                          unicast hosts.

-- 2010-10-05 - add prerule support <patrik@cqure.net>
-- 2010-10-10 - add newtarget support <patrik@cqure.net>
-- 2010-10-29 - factored out all of the code to upnp.lua <patrik@cqure.net>

author = "Thomas Buchanan"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "discovery", "safe"}


---
-- Runs on UDP port 1900
portrule = shortport.portnumber(1900, "udp", {"open", "open|filtered"})

---
-- Sends UPnP discovery packet to host,
-- and extracts service information from results
action = function(host, port)
  local override = stdnse.get_script_args("upnp-info.override")
  local helper = upnp.Helper:new( host, port )
  if ( override ~= nil ) and ( string.lower(override) == "false" ) then
    helper:setOverride( false )
  else
    helper:setOverride( true )
  end
  local status, result = helper:queryServices()

  if ( status ) then
    nmap.set_port_state(host, port, "open")
    return stdnse.format_output(true, result)
  end
end
