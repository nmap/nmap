local nmap = require "nmap"
local shortport = require "shortport"
local sip = require "sip"
local stdnse = require "stdnse"
local stringaux = require "stringaux"

description = [[
Enumerates a SIP Server's allowed methods (INVITE, OPTIONS, SUBSCRIBE, etc.)

The script works by sending an OPTION request to the server and checking for
the value of the Allow header in the response.
]]

---
-- @usage
-- nmap --script=sip-methods -sU -p 5060 <targets>
--
--@output
-- 5060/udp open  sip
-- | sip-methods:
-- |_  INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE, NOTIFY, INFO
--
-- @xmloutput
-- <elem>INVITE</elem>
-- <elem>ACK</elem>
-- <elem>CANCEL</elem>
-- <elem>OPTIONS</elem>
-- <elem>BYE</elem>
-- <elem>REFER</elem>
-- <elem>SUBSCRIBE</elem>
-- <elem>NOTIFY</elem>
-- <elem>INFO</elem>


author = "Hani Benhabiles"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "safe", "discovery"}


portrule = shortport.port_or_service(5060, "sip", {"tcp", "udp"})

action = function(host, port)
  local status, session, response
  session = sip.Session:new(host, port)
  status = session:connect()
  if not status then
    return stdnse.format_output(false, "Failed to connect to the SIP server.")
  end

  status, response = session:options()
  if status then
    -- If port state not set to open, set it to open.
    if nmap.get_port_state(host, port) ~= "open" then
      nmap.set_port_state(host, port, "open")
    end

    -- Check if allow header exists in response
    local allow = response:getHeader("allow")
    if allow then
      return stringaux.strsplit(",%s*", allow), allow
    end
  end
end
