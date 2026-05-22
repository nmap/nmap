description = [[
Looks for webvpn cookies that could denote a Cisco ASA SSL VPN WebVPN Service
is enabled on a port. This may also apply to a Cisco IOS based router
running the Client SSLVPN Service which is rare but possible.
]]

local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

---
-- @usage
-- nmap -p <port> --script http-bigip-cookie <target>
--
-- @output
-- PORT    STATE SERVICE
-- 443/tcp  open  http
-- | http-cisco-webvpn-cookie:
-- |   webvpn:
-- |     Potential Cisco SSLVPN Cookie Found
-- |   webvpn_as:
-- |_    Potential Cisco SSLVPN Cookie Found
--
-- @xmloutput
-- <table key="webvpn">
--   <table key="webvpn">
--     <elem key="message">Potential Cisco SSLVPN Cookie Found</elem>
--   </table>
-- </table>
--
-- @args http-cisco-webvpn-cookie.path The URL path to request. The default path is "/".

author = "mosesrenegade"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "discovery", "safe" }

portrule = shortport.http

action = function(host, port,redirect_ok)
  local path = stdnse.get_script_args(SCRIPT_NAME..".path") or "/"
  local response = http.get(host, port, path, { redirect_ok = false })
  if not response then
    return
  end

  if not response.cookies then
    return
  end

  local output = stdnse.output_table()

  for _, cookie in ipairs(response.cookies) do
    if cookie.name:find("webvpn") then
      local host, port = cookie.value:match("webvpn")
        if http.response_contains("+CSCOE+") then
          local result = {"Potential SSLVPN Cookie Found"}
          output[cookie.name] = result
      end
    end
  end

  if #output > 0 then
    return output
  end
end
