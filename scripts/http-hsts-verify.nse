local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
This script verify if the HTTP Strict Transport Security (HSTS) (RFC 6797) is enable in a web service.
]]

---
-- @usage
-- nmap -p <port> --script=http-hsts-verify.nse <target>
--
-- @output
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- | http-hsts-verify:
-- |   HTTP Strict-Transport-Security (RFC 6797) forces the browser to send all communications over HTTPS.
-- |   References: https://www.owasp.org/index.php/HTTP_Strict_Transport_Security_Cheat_Sheet
-- |   Banner: Strict-Transport-Security: max-age=31536000
-- |_  State: HSTS is configured. (ENABLED)

author = "Icaro Torres"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}

portrule = shortport.http

local function fail (err) return stdnse.format_output(false, err) end

action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME..".path") or "/"
  local status = false
  local get_response
  local output_info = {}
  local is_not_hsts = 0
  local is_hsts = 0

  get_response = http.get(host, port, path)

  if(get_response == nil) then
    return fail("Header request failed")
  end

  if(get_response.rawheader == nil) then
    return fail("GET header request didn't return a proper header")
  end

  table.insert(output_info, "HTTP Strict-Transport-Security (RFC 6797) forces the browser to send all communications over HTTPS.")
  table.insert(output_info, "References: https://www.owasp.org/index.php/HTTP_Strict_Transport_Security_Cheat_Sheet")

  for _,line in pairs(get_response.rawheader) do
    if line:match("strict.transport.security") or line:match("Strict.Transport.Security") then
      is_hsts = is_hsts + 1
      table.insert(output_info, "Banner: " .. line)
    end
  end

  if is_hsts >= 1 then
    table.insert(output_info, "State: HSTS is configured. (ENABLED)")
  else
    table.insert(output_info, "State: HSTS IS NOT CONFIGURED. (DISABLED)")
  end

  return stdnse.format_output(true, output_info)

end
