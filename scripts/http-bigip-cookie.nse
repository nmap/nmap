description = [[
Decodes any unencrypted F5 BIG-IP cookies in the HTTP response.
BIG-IP cookies contain information on backend systems such as
internal IP addresses and port numbers.
See here for more info: https://support.f5.com/csp/article/K6917
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
-- 80/tcp  open  http
-- | http-bigip-cookie:
-- |   BIGipServer<pool_name>:
-- |     address:
-- |       host: 10.1.1.100
-- |       type: ipv4
-- |_    port: 8080
--
-- @xmloutput
-- <table key="BIGipServer<pool_name>">
--   <table key="address">
--     <elem key="host">10.1.1.100</elem>
--     <elem key="type">ipv4</elem>
--   </table>
--   <elem key="port">8080</elem>
-- </table>
--
-- @args http-bigip-cookie.path The URL path to request. The default path is "/".

author = "Seth Jackson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = { "discovery", "safe" }

portrule = shortport.http

action = function(host, port)
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
    if cookie.name:find("BIGipServer") then
      local host, port = cookie.value:match("^(%d+)%.(%d+)%.")

      if host and tonumber(host) < 0x100000000 and tonumber(port) < 0x10000 then
        host = table.concat({("BBBB"):unpack(("<I4"):pack(host))}, ".", 1, 4)
        port = (">I2"):unpack(("<I2"):pack(port))

        local result = {
          address = {
            host = host,
            type = "ipv4"
          },
          port = port
        }

        output[cookie.name] = result
      end
    end
  end

  if #output > 0 then
    return output
  end
end
