description = [[
Retrieves the authentication scheme and realm of a web service that requires
authentication.
]]

---
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-auth: HTTP/1.1 401 Unauthorized
-- |
-- |_Basic realm=WebAdmin

-- HTTP authentication information gathering script
-- rev 1.1 (2007-05-25)
-- 2008-11-06 Vlatko Kosturjak <kost@linux.hr>
-- * bug fixes against base64 encoded strings, more flexible auth/pass check,
--   corrected sample output

author = "Thomas Buchanan"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"default", "auth", "safe"}

require "shortport"
require "http"

portrule = shortport.http

action = function(host, port)
  local www_authenticate
  local challenges

  local result = {}
  local answer = http.get(host, port, "/")

  --- check for 401 response code
  if answer.status ~= 401 then
    return
  end

  result[#result + 1] = answer["status-line"]

  www_authenticate = answer.header["www-authenticate"]
  if not www_authenticate then
    result[#result + 1] = string.format("Server returned status %d but no WWW-Authenticate header.", answer.status)
    return table.concat(result, "\n")
  end
  challenges = http.parse_www_authenticate(www_authenticate)
  if not challenges then
    result[#result + 1] = string.format("Server returned status %d but the WWW-Authenticate header could not be parsed.", answer.status)
    result[#result + 1] = string.format("WWW-Authenticate: %s", www_authenticate)
    return table.concat(result, "\n")
  end

  for _, challenge in ipairs(challenges) do
    local line = challenge.scheme
    for name, value in pairs(challenge.params) do
      line = line .. string.format(" %s=%s", name, value)
    end
    result[#result + 1] = line
  end

  return table.concat(result, "\n")
end
