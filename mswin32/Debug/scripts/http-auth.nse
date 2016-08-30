local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Retrieves the authentication scheme and realm of a web service that requires
authentication.
]]

---
-- @usage
-- nmap --script http-auth [--script-args http-auth.path=/login] -p80 <host>
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-auth:
-- | HTTP/1.1 401 Unauthorized
-- |   Negotiate
-- |   NTLM
-- |   Digest charset=utf-8 nonce=+Upgraded+v1e4e256b4afb7f89be014e...968ccd60affb7c qop=auth algorithm=MD5-sess realm=example.com
-- |_  Basic realm=example.com
--
-- @xmloutput
-- <table>
--   <elem key="scheme">Basic</elem>
--   <table key="params">
--     <elem key="realm">Router</elem>
--   </table>
-- </table>
-- <elem key="scheme">Digest</elem>
--   <table key="params">
--     <elem key="nonce">np9qe4zJBAA=1f3ae82f536e70a806241b3358f571507a3a4d67</elem>
--     <elem key="realm">Router</elem>
--     <elem key="algorithm">MD5</elem>
--     <elem key="qop">auth</elem>
--     <elem key="domain">secret</elem>
--   </table>
-- </table>
--
-- @args http-auth.path  Define the request path

-- HTTP authentication information gathering script
-- rev 1.1 (2007-05-25)
-- 2008-11-06 Vlatko Kosturjak <kost@linux.hr>
--   * bug fixes against base64 encoded strings, more flexible auth/pass check,
--     corrected sample output
-- 2011-12-18 Duarte Silva <duarte.silva@serializing.me>
--   * Added hostname and path arguments
--   * Updated documentation
-----------------------------------------------------------------------

author = "Thomas Buchanan"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"default", "auth", "safe"}


portrule = shortport.http

local PATH = stdnse.get_script_args(SCRIPT_NAME .. ".path")

action = function(host, port)
  local www_authenticate
  local challenges

  local result = {}
  local answer = http.get(host, port, PATH or "/", { bypass_cache = true })

  --- check for 401 response code
  if answer.status ~= 401 then
    return
  end

  result.name = answer["status-line"]:match("^(.*)\r?\n$")

  www_authenticate = answer.header["www-authenticate"]
  if not www_authenticate then
    table.insert( result, ("Server returned status %d but no WWW-Authenticate header."):format(answer.status) )
    return stdnse.format_output(true, result)
  end
  challenges = http.parse_www_authenticate(www_authenticate)
  if not challenges then
    table.insert( result, ("Server returned status %d but the WWW-Authenticate header could not be parsed."):format(answer.status) )
    table.insert( result, ("WWW-Authenticate: %s"):format(www_authenticate) )
    return stdnse.format_output(true, result)
  end

  for _, challenge in ipairs(challenges) do
    local line = challenge.scheme
    if ( challenge.params ) then
      for name, value in pairs(challenge.params) do
        line = line .. string.format(" %s=%s", name, value)
      end
    end
    table.insert(result, line)
  end

  return challenges, stdnse.format_output(true, result)
end
