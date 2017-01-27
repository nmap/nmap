local comm = require "comm"
local nmap = require "nmap"
local shortport = require "shortport"
local string = require "string"

description = [[
Detects the UDP IAX2 service.

The script sends an Inter-Asterisk eXchange (IAX) Revision 2 Control Frame POKE
request and checks for a proper response.  This protocol is used to enable VoIP
connections between servers as well as client-server communication.
]]

---
-- @usage
-- nmap -sU -sV -p 4569 <target>
-- @output
-- PORT     STATE  SERVICE VERSION
-- 4569/udp closed iax2

author = "Ferdy Riphagen"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"version"}


portrule = shortport.version_port_or_service(4569, nil, "udp")

action = function(host, port)
  -- see http://www.cornfed.com/iax.pdf for all options.
  local poke = "\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x06\x1e"

  local status, recv = comm.exchange(host, port, poke, {timeout=10000})

  if not status then
    return
  end

  if (#recv) == 12 then
    local byte11 = string.byte(recv, 11)
    local byte12 = string.byte(recv, 12)

    -- byte11 must be \x06 IAX Control Frame
    -- and byte12 must be \x03 or \x04
    if ((byte11 == 6) and
      (byte12 == 3 or byte12 == 4))
    then
      nmap.set_port_state(host, port, "open")
      port.version.name = "iax2"
      nmap.set_port_version(host, port)
    end

  end
end
