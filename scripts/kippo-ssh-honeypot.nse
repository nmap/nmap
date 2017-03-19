local shortport = require "shortport"
local comm = require "comm"
local string = require "string"
local nmap = require "nmap"

description = [[Kippo is a medium-interaction SSH honeypot written in Python.
It is used to log brute force attacks and the entire shell interaction
performed by an attacker.
]]

-- References:
-- http://x42.obscurechannel.com/?p=11


author = "Dylan Webb, Fabrizio Siciliano"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "version"}

portrule = shortport.port_or_service(22, "ssh")

action = function(host, port)

  local try = nmap.new_try()
  local response = try(comm.exchange(host,port, "/\r\n\r\n\r\n\r\n\r\n\r\n\r\n", {lines = 100, proto = port.protocol,timeout=5000}))
  local unpatched = string.find(response,"bad packet length")

  if (unpatched) then
    return ("HONEYPOT DETECTED\r\nAppears to be a Kippo SSH Honeypot.")
  end
end
