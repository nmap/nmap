local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Verify that HTTP Strict Transport Security is enabled.

HTTP Strict-Transport-Security (HSTS) (RFC 6797) forces a web browser to communicate with a web server over HTTPS.
This script examines HTTP Response Headers to determine whether HSTS is configured.

References: https://www.owasp.org/index.php/HTTP_Strict_Transport_Security_Cheat_Sheet
]]

---
-- @usage
-- nmap -p <port> --script http-hsts-verify <target>
--
-- @output
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- | http-hsts-verify:
-- |  HSTS is configured.
-- |_ Header: Strict-Transport-Security: max-age=31536000
--
-- @args http-hsts-verify.path The URL path to request. The default path is "/".

author = "Icaro Torres"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

local function fail (err) return stdnse.format_output(false, err) end

action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME..".path") or "/"
  local response
  local output_info = {}
  local hsts_header = {}

  response = http.head(host, port, path)

  if response == nil then
    return fail("Request failed")
  end

  if response.rawheader == nil then
    return fail("Response didn't include a proper header")
  end

  for _, line in pairs(response.rawheader) do
    if line:match("strict.transport.security") or line:match("Strict.Transport.Security") then
      table.insert(hsts_header, line)
    end
  end

  if #hsts_header > 0 then
    table.insert(output_info, "HSTS is configured.")
    table.insert(output_info, "Header: " .. table.concat(hsts_header, " "))
  else
    table.insert(output_info, "HSTS is not configured.")
  end

  return stdnse.format_output(true, output_info)

end
