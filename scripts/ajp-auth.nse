local ajp = require "ajp"
local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Retrieves the authentication scheme and realm of an AJP service (Apache JServ Protocol) that requires authentication.
]]

---
-- @usage
-- nmap -p 8009 <ip> --script ajp-auth [--script-args ajp-auth.path=/login]
--
-- @output
-- PORT     STATE SERVICE
-- 8009/tcp open  ajp13
-- | ajp-auth:
-- |_  Digest opaque=GPui3SvCGBoHrRMMzSsgaYBV qop=auth nonce=1336063830612:935b5b389696b0f67b9193e19f47e037 realm=example.org
--
-- @args ajp-auth.path  Define the request path
--

author = "Patrik Karlsson"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"default", "auth", "safe"}


portrule = shortport.port_or_service(8009, 'ajp13', 'tcp')

local arg_path = stdnse.get_script_args(SCRIPT_NAME .. ".path")

action = function(host, port)
  local helper = ajp.Helper:new(host, port)

  if ( not(helper:connect()) ) then
    return stdnse.format_output(false, "Failed to connect to AJP server")
  end

  local status, answer = helper:get(arg_path or "/")

  --- check for 401 response code
  if ( not(status) or answer.status ~= 401 ) then
    return
  end

  local result = { name = answer.status_line:match("^(.*)\r?\n$") }

  local www_authenticate = answer.headers["www-authenticate"]
  if not www_authenticate then
    table.insert( result, ("Server returned status %d but no WWW-Authenticate header."):format(answer.status) )
    return stdnse.format_output(true, result)
  end

  local challenges = http.parse_www_authenticate(www_authenticate)
  if ( not(challenges) ) then
    table.insert( result, ("Server returned status %d but the WWW-Authenticate header could not be parsed."):format(answer.status) )
    table.insert( result, ("WWW-Authenticate: %s"):format(www_authenticate) )
    return stdnse.format_output(true, result)
  end

  for _, challenge in ipairs(challenges) do
    local line = challenge.scheme
    if ( challenge.params ) then
      for name, value in pairs(challenge.params) do
        line = line .. (" %s=%s"):format(name, value)
      end
    end
    table.insert(result, line)
  end
  return stdnse.format_output(true, result)
end
