local nmap = require "nmap"
local shortport = require "shortport"
local sip = require "sip"
local stdnse = require "stdnse"
local lpeg_utility = require "lpeg-utility"

description = [[
Obtains the version information of a SIP server from the User-Agent
response header.
]]

---
-- @usage
-- nmap -sV -p 5060 --script sip-useragent <target>
--
-- @output
-- PORT     STATE SERVICE VERSION
-- 5060/tcp open  sip     VidyoGateway-3.1.4.18 (SIP end point; Status: 200 OK)
-- |_sip-useragent: VidyoGateway-3.1.4.18
---

author = "Steve Benson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"version"}

portrule = shortport.port_or_service(5060, "sip", {"tcp", "udp"})

action = function(host, port)
  local user_agent

  if port.version.service_fp and lpeg_utility.get_response(port.version.service_fp, "SIPOptions") then
    stdnse.debug1("OPTIONS request sent via probes. Extracting User-Agent from that.")
    user_agent = string.match(
      lpeg_utility.get_response(port.version.service_fp, "SIPOptions"),
      "\n[Uu][Ss][Ee][Rr][-][Aa][Gg][Ee][Nn][Tt]:[ \t]*(.-)\r?\n"
    )
  else
    stdnse.debug1("No OPTIONS request was sent. Doing one now.")
    local session = sip.Session:new(host, port)
    if session:connect() then
      local status, response = session:options()
      if status then
        user_agent = response:getHeader('User-Agent')
      end 
    end
  end


  if port.version.product == nil then
    port.version.product = user_agent
    nmap.set_port_version(host, port, "softmatched")
  end

  return user_agent
end
